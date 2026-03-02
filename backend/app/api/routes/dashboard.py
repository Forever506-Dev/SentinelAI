"""
Dashboard Routes

Aggregated statistics and real-time data for the main dashboard view.
Includes a WebSocket endpoint backed by Redis pub/sub for live alert streaming.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, Query
from sqlalchemy import select, func, case, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, async_session_factory
from app.core.security import get_current_user, decode_token, require_role
from app.core.config import settings
from app.models.agent import Agent
from app.models.alert import Alert

logger = structlog.get_logger()
router = APIRouter()


# ═══════════════════════════════════════════════════════════════════
# Background task — Heartbeat gap monitor
# ═══════════════════════════════════════════════════════════════════

_heartbeat_monitor_started = False


async def start_heartbeat_monitor() -> None:
    """Periodically check for agents that missed heartbeats and create alerts."""
    global _heartbeat_monitor_started
    if _heartbeat_monitor_started:
        return
    _heartbeat_monitor_started = True
    logger.info("Heartbeat gap monitor started")

    while True:
        try:
            await asyncio.sleep(60)  # Check every 60 seconds
            async with async_session_factory() as db:
                now = datetime.now(timezone.utc)
                threshold = now - timedelta(minutes=settings.AGENT_MAX_OFFLINE_MINUTES)

                # Find agents that were online but missed heartbeats
                stale_result = await db.execute(
                    select(Agent).where(
                        Agent.status == "online",
                        Agent.last_heartbeat < threshold,
                    )
                )
                stale_agents = stale_result.scalars().all()

                for agent in stale_agents:
                    agent.status = "offline"
                    minutes_silent = (now - agent.last_heartbeat).total_seconds() / 60

                    # Create a critical alert for the heartbeat gap
                    alert = Alert(
                        agent_id=agent.id,
                        title=f"Agent heartbeat lost: {agent.hostname}",
                        description=(
                            f"Agent '{agent.hostname}' ({agent.os_type} {agent.os_version}) "
                            f"has not sent a heartbeat in {minutes_silent:.0f} minutes. "
                            f"Last heartbeat: {agent.last_heartbeat.isoformat()}. "
                            f"The agent may be offline, compromised, or experiencing "
                            f"network issues. Investigate immediately."
                        ),
                        severity="critical" if minutes_silent > 15 else "high",
                        confidence=0.90,
                        status="new",
                        detection_source="heartbeat_monitor",
                        rule_id="HB001",
                        rule_name="heartbeat_gap",
                        mitre_tactics=["Defense Evasion", "Impact"],
                        mitre_techniques=["T1562.001", "T1489"],
                    )
                    db.add(alert)
                    logger.warning(
                        "Agent heartbeat gap detected",
                        agent_id=str(agent.id),
                        hostname=agent.hostname,
                        minutes_silent=f"{minutes_silent:.0f}",
                    )

                    # Publish to Redis for real-time WebSocket feed
                    try:
                        import redis.asyncio as aioredis
                        redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
                        await redis.publish(
                            "sentinelai:alerts",
                            json.dumps({
                                "type": "heartbeat_gap",
                                "agent_id": str(agent.id),
                                "hostname": agent.hostname,
                                "severity": "critical" if minutes_silent > 15 else "high",
                                "minutes_silent": minutes_silent,
                            }),
                        )
                        await redis.close()
                    except Exception:
                        pass

                await db.commit()

        except Exception as e:
            logger.error("Heartbeat monitor error", error=str(e))


@router.get("/stats")
async def get_dashboard_stats(
    _current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get aggregated dashboard statistics."""
    now = datetime.now(timezone.utc)
    offline_threshold = now - timedelta(minutes=settings.AGENT_MAX_OFFLINE_MINUTES)

    # Agent counts — exclude decommissioned
    total_agents = await db.execute(
        select(func.count())
        .select_from(Agent)
        .where(Agent.status != "decommissioned")
    )
    online_agents = await db.execute(
        select(func.count())
        .select_from(Agent)
        .where(Agent.last_heartbeat >= offline_threshold)
        .where(Agent.status.notin_(["decommissioned", "isolated"]))
    )
    isolated_agents = await db.execute(
        select(func.count()).select_from(Agent).where(Agent.is_isolated.is_(True))
    )

    # Alert counts
    active_alerts = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(Alert.status.in_(["new", "investigating", "escalated"]))
    )
    critical_alerts = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(Alert.severity == "critical")
        .where(Alert.status.in_(["new", "investigating", "escalated"]))
    )

    last_24h = now - timedelta(hours=24)
    alerts_24h = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(Alert.detected_at >= last_24h)
    )

    # Severity breakdown for charts
    severity_counts = {}
    for sev in ["critical", "high", "medium", "low", "informational"]:
        count_result = await db.execute(
            select(func.count())
            .select_from(Alert)
            .where(Alert.severity == sev)
            .where(Alert.status.in_(["new", "investigating", "escalated"]))
        )
        severity_counts[sev] = count_result.scalar() or 0

    # OS Distribution (exclude decommissioned)
    os_distribution = {}
    for os_type in ["windows", "linux", "macos", "android"]:
        count_result = await db.execute(
            select(func.count())
            .select_from(Agent)
            .where(Agent.os_type == os_type)
            .where(Agent.status != "decommissioned")
        )
        os_distribution[os_type] = count_result.scalar() or 0

    # Events in last hour
    last_hour = now - timedelta(hours=1)
    from app.models.event import TelemetryEvent
    events_1h = await db.execute(
        select(func.count())
        .select_from(TelemetryEvent)
        .where(TelemetryEvent.event_time >= last_hour)
    )

    return {
        "agents": {
            "total": total_agents.scalar() or 0,
            "online": online_agents.scalar() or 0,
            "isolated": isolated_agents.scalar() or 0,
            "os_distribution": os_distribution,
        },
        "alerts": {
            "active": active_alerts.scalar() or 0,
            "critical": critical_alerts.scalar() or 0,
            "last_24h": alerts_24h.scalar() or 0,
            "severity_breakdown": severity_counts,
        },
        "telemetry": {
            "events_last_hour": events_1h.scalar() or 0,
        },
        "timestamp": now.isoformat(),
    }


@router.get("/recent-alerts")
async def get_recent_alerts(
    _current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get the most recent alerts for the dashboard feed."""
    result = await db.execute(
        select(Alert)
        .order_by(Alert.detected_at.desc())
        .limit(20)
    )
    alerts = result.scalars().all()

    return {
        "alerts": [
            {
                "id": str(a.id),
                "title": a.title,
                "description": a.description,
                "severity": a.severity,
                "confidence": a.confidence,
                "status": a.status,
                "detection_source": a.detection_source,
                "agent_id": str(a.agent_id),
                "detected_at": a.detected_at.isoformat() if a.detected_at else None,
                "mitre_tactics": a.mitre_tactics,
                "mitre_techniques": a.mitre_techniques,
                "llm_analysis": a.llm_analysis,
            }
            for a in alerts
        ]
    }


# ═══════════════════════════════════════════════════════════════════
# MITRE ATT&CK Heatmap — technique frequency aggregation
# ═══════════════════════════════════════════════════════════════════


@router.get("/mitre-heatmap")
async def get_mitre_heatmap(
    days: int = Query(30, ge=1, le=365),
    _current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Return MITRE ATT&CK technique frequency for heatmap visualization.
    Aggregates from all alerts within the given time window.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(Alert.mitre_techniques, Alert.mitre_tactics, Alert.severity)
        .where(Alert.detected_at >= since)
        .where(Alert.mitre_techniques.isnot(None))
    )
    rows = result.all()

    technique_counts: dict[str, dict] = {}
    tactic_counts: dict[str, int] = {}

    for techniques, tactics, severity in rows:
        if techniques:
            for tech in techniques:
                if tech not in technique_counts:
                    technique_counts[tech] = {"count": 0, "severities": {}}
                technique_counts[tech]["count"] += 1
                technique_counts[tech]["severities"][severity] = (
                    technique_counts[tech]["severities"].get(severity, 0) + 1
                )
        if tactics:
            for tactic in tactics:
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    # Sort by frequency
    sorted_techniques = sorted(
        technique_counts.items(), key=lambda x: x[1]["count"], reverse=True
    )

    return {
        "techniques": [
            {"technique_id": tid, "count": data["count"], "severities": data["severities"]}
            for tid, data in sorted_techniques
        ],
        "tactics": [
            {"tactic": t, "count": c}
            for t, c in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
        ],
        "period_days": days,
        "total_alerts": len(rows),
    }


# ═══════════════════════════════════════════════════════════════════
# Alert Timeline — time-bucketed alert histogram
# ═══════════════════════════════════════════════════════════════════


@router.get("/alert-timeline")
async def get_alert_timeline(
    hours: int = Query(24, ge=1, le=720),
    bucket_minutes: int = Query(60, ge=5, le=1440),
    _current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Return time-bucketed alert counts for timeline visualization.
    Default: last 24 hours in 1-hour buckets.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    # Query alerts with severity breakdown per bucket
    result = await db.execute(
        select(Alert.detected_at, Alert.severity)
        .where(Alert.detected_at >= since)
        .order_by(Alert.detected_at)
    )
    alerts = result.all()

    # Build buckets
    bucket_delta = timedelta(minutes=bucket_minutes)
    buckets: list[dict] = []
    bucket_start = since

    while bucket_start < now:
        bucket_end = bucket_start + bucket_delta
        bucket_alerts = [a for a in alerts if bucket_start <= a.detected_at < bucket_end]

        severity_breakdown = {}
        for a in bucket_alerts:
            severity_breakdown[a.severity] = severity_breakdown.get(a.severity, 0) + 1

        buckets.append({
            "timestamp": bucket_start.isoformat(),
            "count": len(bucket_alerts),
            "severities": severity_breakdown,
        })
        bucket_start = bucket_end

    return {
        "buckets": buckets,
        "period_hours": hours,
        "bucket_minutes": bucket_minutes,
        "total_alerts": len(alerts),
    }


# ═══════════════════════════════════════════════════════════════════
# Top Alerting Agents — for investigation prioritization
# ═══════════════════════════════════════════════════════════════════


@router.get("/top-agents")
async def get_top_alerting_agents(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(10, ge=1, le=50),
    _current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return agents with the most alerts for investigation prioritization."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    result = await db.execute(
        select(
            Alert.agent_id,
            func.count(Alert.id).label("alert_count"),
            func.count(case((Alert.severity == "critical", 1))).label("critical_count"),
            func.count(case((Alert.severity == "high", 1))).label("high_count"),
        )
        .where(Alert.detected_at >= since)
        .where(Alert.status.in_(["new", "investigating", "escalated"]))
        .group_by(Alert.agent_id)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
    )
    rows = result.all()

    agents = []
    for agent_id, alert_count, critical_count, high_count in rows:
        agent_result = await db.execute(
            select(Agent.hostname, Agent.os_type, Agent.status)
            .where(Agent.id == agent_id)
        )
        agent_info = agent_result.first()
        agents.append({
            "agent_id": str(agent_id),
            "hostname": agent_info.hostname if agent_info else "unknown",
            "os_type": agent_info.os_type if agent_info else "unknown",
            "agent_status": agent_info.status if agent_info else "unknown",
            "alert_count": alert_count,
            "critical_count": critical_count,
            "high_count": high_count,
        })

    return {"agents": agents, "period_hours": hours}


# ═══════════════════════════════════════════════════════════════════
# WebSocket — Real-time dashboard feed backed by Redis pub/sub
# ═══════════════════════════════════════════════════════════════════


@router.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for real-time dashboard updates.
    Streams new alerts and agent status changes from Redis pub/sub.

    Authentication: pass JWT token as query param ?token=<jwt>
    Falls back to unauthenticated in DEBUG mode only.
    """
    # ── Authenticate WebSocket connection ──
    token = websocket.query_params.get("token")
    if token:
        try:
            payload = decode_token(token)
            if payload.get("type") not in ("access",):
                await websocket.close(code=4001, reason="Invalid token type")
                return
            logger.info("WebSocket authenticated", username=payload.get("username", "?"))
        except Exception:
            await websocket.close(code=4001, reason="Invalid or expired token")
            return
    elif not settings.DEBUG:
        await websocket.close(code=4001, reason="Authentication required")
        return
    else:
        logger.warning("WebSocket connected without authentication (DEBUG mode)")

    await websocket.accept()
    logger.info("WebSocket client connected")

    # Start heartbeat monitor on first WebSocket connection (lazy init)
    asyncio.ensure_future(start_heartbeat_monitor())

    pubsub = None
    redis = None

    try:
        # Try Redis pub/sub
        try:
            import redis.asyncio as aioredis
            redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            await redis.ping()
            pubsub = redis.pubsub()
            await pubsub.subscribe("sentinelai:alerts", "sentinelai:agents")
            logger.info("WebSocket subscribed to Redis channels")
        except Exception as e:
            logger.warning("Redis not available for WebSocket", error=str(e))

        if pubsub:
            # ── Redis-backed real-time stream ────────────────────
            async def listen_redis():
                try:
                    async for message in pubsub.listen():
                        if message["type"] == "message":
                            await websocket.send_text(message["data"])
                except Exception:
                    pass

            async def listen_client():
                try:
                    while True:
                        data = await websocket.receive_text()
                        try:
                            cmd = json.loads(data)
                            if cmd.get("type") == "ping":
                                await websocket.send_json({"type": "pong"})
                        except json.JSONDecodeError:
                            pass
                except WebSocketDisconnect:
                    pass

            await asyncio.gather(
                listen_redis(),
                listen_client(),
                return_exceptions=True,
            )
        else:
            # ── Polling fallback ─────────────────────────────────
            while True:
                try:
                    data = await asyncio.wait_for(
                        websocket.receive_text(), timeout=5.0
                    )
                    try:
                        cmd = json.loads(data)
                        if cmd.get("type") == "ping":
                            await websocket.send_json({"type": "pong"})
                    except json.JSONDecodeError:
                        pass
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "heartbeat"})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WebSocket error", error=str(e))
    finally:
        if pubsub:
            await pubsub.unsubscribe()
            await pubsub.close()
        if redis:
            await redis.close()
        logger.info("WebSocket client disconnected")
