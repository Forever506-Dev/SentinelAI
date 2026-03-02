"""
Detection Pipeline

Standalone async detection pipeline that:
1. Runs the RuleEngine (fast, no LLM) on every telemetry batch
2. Optionally enriches via ThreatAnalyzer (LOLGlobs, MITRE, LLM)
3. Runs CorrelationEngine to group related alerts
4. Persists alerts to PostgreSQL
5. Publishes alerts to Redis for live WebSocket feed

Uses its OWN DB session — safe to run as asyncio.create_task().
"""

from __future__ import annotations

import asyncio
import json as _json
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import async_session_factory
from app.models.alert import Alert
from app.services.rule_engine import RuleEngine, RuleMatch
from app.services.correlation_engine import CorrelationEngine

logger = structlog.get_logger()

# Singleton rule engine (stateless, safe to share)
_rule_engine = RuleEngine()

# Singleton correlation engine
_correlation_engine = CorrelationEngine()

# Redis helper (same pattern as agents.py)
_redis_client = None


async def _get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            import redis.asyncio as aioredis
            _redis_client = aioredis.from_url(
                settings.REDIS_URL, decode_responses=True,
            )
            await _redis_client.ping()
        except Exception as e:
            logger.warning("Redis not available for detection pipeline", error=str(e))
            _redis_client = None
    return _redis_client


async def run_detection_pipeline(
    agent_id: str,
    agent_info: dict,
    events: list[dict],
) -> None:
    """
    Main detection entry point — called as a background task.

    Uses its own DB session so it's safe to run detached from the request.
    """
    try:
        async with async_session_factory() as db:
            async with db.begin():
                await _detect_and_alert(db, agent_id, agent_info, events)
    except Exception as e:
        logger.error(
            "Detection pipeline error",
            agent_id=agent_id,
            error=str(e),
            event_count=len(events),
        )


async def _detect_and_alert(
    db: AsyncSession,
    agent_id: str,
    agent_info: dict,
    events: list[dict],
) -> None:
    """Core detection logic."""

    # ── Stage 1: Rule Engine (fast, synchronous) ─────────────
    rule_matches: list[RuleMatch] = _rule_engine.evaluate_batch(events, agent_info)

    if not rule_matches:
        return  # Nothing suspicious

    logger.info(
        "Detection pipeline: rule matches found",
        agent_id=agent_id,
        hostname=agent_info.get("hostname"),
        match_count=len(rule_matches),
    )

    # ── Stage 2: Create alerts from rule matches ─────────────
    redis = await _get_redis()
    alerts_created = 0

    for match in rule_matches:
        # Dedup: check if we already have an open alert with same rule_id
        # for this agent in the last 10 minutes to avoid spam
        ten_min_ago = datetime.now(timezone.utc) - timedelta(minutes=10)
        dedup_result = await db.execute(
            select(Alert)
            .where(Alert.agent_id == agent_id)
            .where(Alert.rule_id == match.rule_id)
            .where(Alert.status.in_(["new", "investigating"]))
            .where(Alert.detected_at >= ten_min_ago)
            .limit(1)
        )
        existing = dedup_result.scalar_one_or_none()

        if existing:
            # Update the existing alert's event count instead of creating new
            existing.related_alert_count = (existing.related_alert_count or 0) + 1
            existing.last_event_at = datetime.now(timezone.utc)
            logger.debug(
                "Alert dedup — incremented existing",
                alert_id=str(existing.id),
                rule_id=match.rule_id,
            )
            continue

        alert = Alert(
            agent_id=agent_id,
            title=match.title,
            description=match.description,
            severity=match.severity,
            confidence=match.confidence,
            status="new",
            detection_source=match.detection_source,
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            mitre_tactics=match.mitre_tactics or [],
            mitre_techniques=match.mitre_techniques or [],
            raw_events=match.raw_event,
            first_event_at=datetime.now(timezone.utc),
            last_event_at=datetime.now(timezone.utc),
        )
        db.add(alert)
        await db.flush()
        await db.refresh(alert)
        alerts_created += 1

        logger.info(
            "Alert created",
            alert_id=str(alert.id),
            rule_id=match.rule_id,
            severity=match.severity,
            title=match.title,
        )

        # ── Stage 3: Publish to Redis for live WebSocket feed ─
        if redis:
            try:
                await redis.publish(
                    "sentinelai:alerts",
                    _json.dumps({
                        "type": "new_alert",
                        "alert": {
                            "id": str(alert.id),
                            "title": alert.title,
                            "severity": alert.severity,
                            "status": alert.status,
                            "confidence": alert.confidence,
                            "detection_source": alert.detection_source,
                            "rule_id": alert.rule_id,
                            "rule_name": alert.rule_name,
                            "agent_id": agent_id,
                            "hostname": agent_info.get("hostname", ""),
                            "detected_at": (
                                alert.detected_at.isoformat()
                                if alert.detected_at
                                else None
                            ),
                            "mitre_techniques": alert.mitre_techniques or [],
                            "mitre_tactics": alert.mitre_tactics or [],
                        },
                    }),
                )
            except Exception as pub_err:
                logger.warning("Redis publish failed", error=str(pub_err))

    if alerts_created:
        logger.info(
            "Detection pipeline complete",
            agent_id=agent_id,
            alerts_created=alerts_created,
            total_matches=len(rule_matches),
        )

    # ── Stage 4: Correlation Engine — cross-alert/cross-agent ─────
    if alerts_created:
        try:
            # Fetch recent alerts for correlation context
            recent_result = await db.execute(
                select(Alert)
                .where(Alert.status.in_(["new", "investigating"]))
                .order_by(Alert.detected_at.desc())
                .limit(50)
            )
            recent_alerts = [
                {
                    "id": str(a.id),
                    "agent_id": str(a.agent_id) if a.agent_id else None,
                    "mitre_techniques": a.mitre_techniques or [],
                    "mitre_tactics": a.mitre_tactics or [],
                    "ioc_indicators": a.ioc_indicators or {},
                }
                for a in recent_result.scalars().all()
            ]

            for match in rule_matches:
                correlation = await _correlation_engine.correlate_alert(
                    {
                        "agent_id": agent_id,
                        "mitre_techniques": match.mitre_techniques or [],
                        "ioc_indicators": {},
                    },
                    recent_alerts,
                )
                if correlation.get("is_correlated"):
                    logger.warning(
                        "Correlation detected",
                        agent_id=agent_id,
                        group_id=correlation.get("group_id"),
                        related_count=len(correlation.get("related_alerts", [])),
                        chain_phases=len(correlation.get("attack_chain", [])),
                    )
        except Exception as corr_err:
            logger.warning("Correlation engine failed", error=str(corr_err))

    # ── Stage 5 (optional): Async LLM enrichment on high-severity ─
    # Fire and forget — enrich critical/high alerts with LLM analysis
    high_sev_alerts = [m for m in rule_matches if m.severity in ("critical", "high")]
    if high_sev_alerts:
        asyncio.create_task(
            _enrich_with_llm(agent_id, agent_info, high_sev_alerts)
        )


async def _enrich_with_llm(
    agent_id: str,
    agent_info: dict,
    matches: list[RuleMatch],
) -> None:
    """
    Best-effort LLM enrichment for high-severity alerts.
    Runs in a separate task — failure does NOT prevent alert creation.
    """
    try:
        from app.services.llm_engine import LLMEngine
        llm = LLMEngine()

        async with async_session_factory() as db:
            async with db.begin():
                for match in matches[:5]:  # Limit to 5 to avoid overload
                    try:
                        result = await asyncio.wait_for(
                            llm.analyze_alert({
                                "title": match.title,
                                "description": match.description,
                                "detection_source": match.detection_source,
                                "os_type": agent_info.get("os_type", "unknown"),
                                "raw_events": match.raw_event,
                                "process_tree": {},
                                "network_context": {},
                            }),
                            timeout=30.0,
                        )

                        # Update the alert with LLM analysis
                        alert_result = await db.execute(
                            select(Alert)
                            .where(Alert.agent_id == agent_id)
                            .where(Alert.rule_id == match.rule_id)
                            .where(Alert.status == "new")
                            .order_by(Alert.detected_at.desc())
                            .limit(1)
                        )
                        alert = alert_result.scalar_one_or_none()
                        if alert:
                            alert.llm_analysis = result.get("analysis")
                            alert.llm_recommendation = str(
                                result.get("recommendations", [])
                            )
                            alert.llm_confidence = result.get("confidence")
                            # LLM may refine severity
                            llm_severity = result.get("severity")
                            if llm_severity in (
                                "critical", "high", "medium", "low", "informational"
                            ):
                                alert.severity = llm_severity

                    except asyncio.TimeoutError:
                        logger.warning(
                            "LLM enrichment timed out",
                            rule_id=match.rule_id,
                        )
                    except Exception as e:
                        logger.warning(
                            "LLM enrichment failed for alert",
                            rule_id=match.rule_id,
                            error=str(e),
                        )

    except Exception as e:
        logger.error("LLM enrichment task failed", error=str(e))
