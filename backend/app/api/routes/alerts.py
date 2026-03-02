"""
Alert Routes

Alert listing, filtering, detail view, status updates, and AI analysis triggers.
"""

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models.alert import Alert
from app.schemas.alert import (
    AlertResponse,
    AlertListResponse,
    AlertUpdateRequest,
    AlertSeverityCount,
)

logger = structlog.get_logger()
router = APIRouter()


async def _run_alert_ai_analysis(alert: Alert, db: AsyncSession) -> dict:
    """Run LLM and correlation analysis for an alert and persist results."""
    from app.services.llm_engine import LLMEngine

    engine = LLMEngine()
    analysis = await engine.analyze_alert({
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "detection_source": alert.detection_source,
        "rule_id": alert.rule_id,
        "mitre_techniques": alert.mitre_techniques or [],
        "mitre_tactics": alert.mitre_tactics or [],
        "raw_events": alert.raw_events,
        "agent_id": str(alert.agent_id) if alert.agent_id else None,
    })

    # Persist LLM results back to alert
    alert.llm_analysis = analysis.get("analysis")
    alert.llm_recommendation = str(analysis.get("recommendations", []))
    alert.llm_confidence = analysis.get("confidence")
    await db.flush()
    await db.refresh(alert)

    # Run correlation engine on this alert
    try:
        from app.services.correlation_engine import CorrelationEngine

        corr = CorrelationEngine()

        # Fetch recent alerts for correlation
        recent_result = await db.execute(
            select(Alert)
            .where(Alert.status.in_(["new", "investigating", "escalated"]))
            .where(Alert.id != alert.id)
            .order_by(Alert.detected_at.desc())
            .limit(50)
        )
        recent_alerts = [
            {
                "id": str(a.id),
                "agent_id": str(a.agent_id) if a.agent_id else None,
                "mitre_techniques": a.mitre_techniques or [],
                "ioc_indicators": a.ioc_indicators or {},
            }
            for a in recent_result.scalars().all()
        ]

        correlation = await corr.correlate_alert(
            {
                "id": str(alert.id),
                "agent_id": str(alert.agent_id) if alert.agent_id else None,
                "mitre_techniques": alert.mitre_techniques or [],
                "ioc_indicators": alert.ioc_indicators or {},
            },
            recent_alerts,
        )
        analysis["correlation"] = correlation
    except Exception as corr_err:
        logger.warning("Correlation failed", error=str(corr_err), alert_id=str(alert.id))
        analysis["correlation"] = None

    return analysis


@router.get("/", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    agent_id: str | None = None,
    detection_source: str | None = None,
    search: str | None = None,
    _current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List alerts with pagination & filtering."""
    query = select(Alert).order_by(Alert.detected_at.desc())

    if severity:
        query = query.where(Alert.severity == severity)
    if status_filter:
        query = query.where(Alert.status == status_filter)
    if agent_id:
        query = query.where(Alert.agent_id == agent_id)
    if detection_source:
        query = query.where(Alert.detection_source == detection_source)
    if search:
        query = query.where(
            Alert.title.ilike(f"%{search}%") | Alert.description.ilike(f"%{search}%")
        )

    # Count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Paginate
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return {
        "alerts": alerts,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/severity-counts", response_model=AlertSeverityCount)
async def get_severity_counts(
    _current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get count of active alerts grouped by severity."""
    counts = {}
    for sev in ["critical", "high", "medium", "low", "informational"]:
        result = await db.execute(
            select(func.count())
            .select_from(Alert)
            .where(Alert.severity == sev)
            .where(Alert.status.in_(["new", "investigating"]))
        )
        counts[sev] = result.scalar() or 0
    return counts


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    _current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> Alert:
    """Get detailed information about a specific alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str,
    payload: AlertUpdateRequest,
    _current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Alert:
    """Update alert status, assignment, or add notes."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    previous_status = alert.status
    if payload.status:
        alert.status = payload.status
        if payload.status == "resolved":
            alert.resolved_at = datetime.now(timezone.utc)

    if payload.assigned_to:
        alert.assigned_to = payload.assigned_to

    # Auto-trigger AI analysis on escalation if not yet analyzed.
    if (
        payload.status == "escalated"
        and previous_status != "escalated"
        and not alert.llm_analysis
    ):
        try:
            await _run_alert_ai_analysis(alert, db)
            logger.info("Auto AI analysis completed for escalated alert", alert_id=alert_id)
        except Exception as analysis_err:
            logger.error(
                "Auto AI analysis failed for escalated alert",
                alert_id=alert_id,
                error=str(analysis_err),
            )

    logger.info("Alert updated", alert_id=alert_id, new_status=payload.status)
    await db.flush()
    await db.refresh(alert)
    return alert


@router.post("/{alert_id}/analyze")
async def trigger_llm_analysis(
    alert_id: str,
    _current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Trigger LLM-powered analysis on an alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    try:
        analysis = await _run_alert_ai_analysis(alert, db)

        return {
            "status": "analysis_complete",
            "alert_id": alert_id,
            "analysis": analysis,
        }
    except Exception as e:
        logger.error("LLM analysis failed", alert_id=alert_id, error=str(e))
        return {
            "status": "analysis_failed",
            "alert_id": alert_id,
            "message": f"LLM analysis failed: {str(e)}",
        }


# ═══════════════════════════════════════════════════════════════════
# Bulk Alert Operations
# ═══════════════════════════════════════════════════════════════════


@router.post("/bulk-update")
async def bulk_update_alerts(
    payload: dict,
    _current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Bulk update alert status or assignment.

    Body: {
        "alert_ids": ["uuid1", "uuid2", ...],
        "status": "resolved",           # optional
        "assigned_to": "user-uuid"       # optional
    }
    """
    alert_ids = payload.get("alert_ids", [])
    new_status = payload.get("status")
    assigned_to = payload.get("assigned_to")

    if not alert_ids:
        raise HTTPException(status_code=422, detail="alert_ids required")
    if not new_status and not assigned_to:
        raise HTTPException(status_code=422, detail="Provide status or assigned_to")

    updated = 0
    for aid in alert_ids:
        result = await db.execute(select(Alert).where(Alert.id == aid))
        alert = result.scalar_one_or_none()
        if alert:
            if new_status:
                alert.status = new_status
                if new_status == "resolved":
                    alert.resolved_at = datetime.now(timezone.utc)
            if assigned_to:
                alert.assigned_to = assigned_to
            updated += 1

    logger.info("Bulk alert update", updated=updated, total_requested=len(alert_ids), new_status=new_status)
    return {"updated": updated, "total_requested": len(alert_ids)}
