"""
AI Analysis Routes

Natural language threat investigation with automatic agent/telemetry
enrichment and OSINT tool-calling via LLM.
"""

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user, require_role
from app.core.database import get_db
from app.models.agent import Agent
from app.models.alert import Alert
from app.models.event import TelemetryEvent

logger = structlog.get_logger()
router = APIRouter()


class InvestigationQuery(BaseModel):
    query: str = Field(..., min_length=3, max_length=4000)
    context: dict = Field(default_factory=dict)


class ThreatLookupRequest(BaseModel):
    indicator_type: str = Field(..., pattern=r"^(ip|domain|hash_sha256|hash_md5|cve|url|email)$")
    indicator_value: str = Field(..., min_length=1, max_length=500)


# ─────────────────────────────────────────────────────────────────
# Helper: auto-enrich context from the database
# ─────────────────────────────────────────────────────────────────

async def _enrich_context(query: str, context: dict, db: AsyncSession) -> dict:
    """
    Detect agent hostnames / IPs in the query and auto-load their
    profile, recent alerts, and recent telemetry so the LLM has
    real data to work with.
    """
    enriched = dict(context)

    # ── 1.  Find agent references in the query ──────────────────
    agents_result = await db.execute(select(Agent).where(Agent.status != "decommissioned"))
    all_agents = agents_result.scalars().all()

    matched_agents: list[Agent] = []
    query_lower = query.lower()
    for agent in all_agents:
        if (
            agent.hostname.lower() in query_lower
            or (agent.internal_ip and agent.internal_ip in query)
            or (agent.external_ip and agent.external_ip in query)
            or str(agent.id) in query
        ):
            matched_agents.append(agent)

    # If no specific agent matched but user says "my endpoint" / "my system"
    # and there is exactly one online agent, use that
    if not matched_agents:
        vague_terms = ["my endpoint", "my system", "my machine", "my computer", "my desktop", "my server", "this system", "this machine"]
        if any(term in query_lower for term in vague_terms):
            online = [a for a in all_agents if a.status == "online"]
            if len(online) == 1:
                matched_agents = online

    if not matched_agents:
        # Still provide a summary of all agents
        enriched["available_agents"] = [
            {"hostname": a.hostname, "os": f"{a.os_type} {a.os_version}", "status": a.status, "ip": a.internal_ip}
            for a in all_agents[:10]
        ]
        return enriched

    # ── 2.  Enrich each matched agent ───────────────────────────
    agent_profiles = []
    for agent in matched_agents[:3]:  # cap at 3
        profile: dict = {
            "agent_id": str(agent.id),
            "hostname": agent.hostname,
            "os_type": agent.os_type,
            "os_version": agent.os_version,
            "architecture": agent.architecture,
            "internal_ip": agent.internal_ip,
            "external_ip": agent.external_ip,
            "status": agent.status,
            "is_isolated": agent.is_isolated,
            "cpu_usage": agent.cpu_usage,
            "memory_usage": agent.memory_usage,
            "disk_usage": agent.disk_usage,
            "uptime_seconds": agent.uptime_seconds,
            "agent_version": agent.agent_version,
            "last_heartbeat": str(agent.last_heartbeat) if agent.last_heartbeat else None,
            "registered_at": str(agent.registered_at),
            "tags": agent.tags,
            "installed_software": agent.installed_software,
        }

        # ── Recent alerts for this agent ────────────────────────
        alerts_q = await db.execute(
            select(Alert)
            .where(Alert.agent_id == str(agent.id))
            .order_by(desc(Alert.detected_at))
            .limit(15)
        )
        recent_alerts = alerts_q.scalars().all()
        profile["recent_alerts"] = [
            {
                "title": a.title,
                "severity": a.severity,
                "confidence": a.confidence,
                "status": a.status,
                "detection_source": a.detection_source,
                "mitre_tactics": a.mitre_tactics,
                "mitre_techniques": a.mitre_techniques,
                "description": (a.description or "")[:300],
                "detected_at": str(a.detected_at),
            }
            for a in recent_alerts
        ]

        # ── Recent telemetry  ──────────────────────────────────
        telem_q = await db.execute(
            select(TelemetryEvent)
            .where(TelemetryEvent.agent_id == str(agent.id))
            .order_by(desc(TelemetryEvent.received_at))
            .limit(30)
        )
        recent_telemetry = telem_q.scalars().all()
        profile["recent_telemetry_summary"] = {
            "total_events": len(recent_telemetry),
            "event_types": {},
            "processes_seen": [],
            "network_connections": [],
            "suspicious_flags": [],
        }
        seen_procs = set()
        for ev in recent_telemetry:
            etype = ev.event_type or "unknown"
            profile["recent_telemetry_summary"]["event_types"][etype] = (
                profile["recent_telemetry_summary"]["event_types"].get(etype, 0) + 1
            )
            if ev.process_name and ev.process_name not in seen_procs:
                seen_procs.add(ev.process_name)
                profile["recent_telemetry_summary"]["processes_seen"].append({
                    "name": ev.process_name,
                    "pid": ev.process_id,
                    "cmd": (ev.command_line or "")[:200],
                })
            if ev.dest_ip:
                profile["recent_telemetry_summary"]["network_connections"].append({
                    "dest_ip": ev.dest_ip,
                    "dest_port": ev.dest_port,
                    "protocol": ev.protocol,
                    "dns_query": ev.dns_query,
                })

        # ── Alert count summary ─────────────────────────────────
        count_q = await db.execute(
            select(
                Alert.severity,
                func.count(Alert.id).label("cnt"),
            )
            .where(Alert.agent_id == str(agent.id))
            .group_by(Alert.severity)
        )
        profile["alert_counts_by_severity"] = {
            row.severity: row.cnt for row in count_q
        }

        agent_profiles.append(profile)

    enriched["matched_agents"] = agent_profiles
    return enriched


def _build_fallback_assessment(query: str, enriched_context: dict) -> dict:
    """Build deterministic assessment when LLM/provider is unavailable."""
    matched_agents = enriched_context.get("matched_agents", []) or []
    available_agents = enriched_context.get("available_agents", []) or []

    if matched_agents:
        agent = matched_agents[0]
        alerts = agent.get("recent_alerts", []) or []
        telemetry_summary = agent.get("recent_telemetry_summary", {}) or {}

        high_sev_count = sum(
            1 for a in alerts if (a.get("severity") in {"critical", "high"})
        )
        total_alerts = len(alerts)
        total_events = telemetry_summary.get("total_events", 0)
        seen_procs = telemetry_summary.get("processes_seen", []) or []
        seen_conns = telemetry_summary.get("network_connections", []) or []

        if high_sev_count >= 3:
            confidence = 0.82
            risk = "high"
        elif high_sev_count > 0:
            confidence = 0.7
            risk = "medium"
        else:
            confidence = 0.6
            risk = "low"

        analysis = (
            f"Fallback threat assessment for {agent.get('hostname', 'endpoint')} based on live telemetry and alerts. "
            f"Recent alerts reviewed: {total_alerts} ({high_sev_count} high/critical). "
            f"Recent telemetry events: {total_events}. "
            f"Observed processes: {len(seen_procs)}. "
            f"Observed network connections: {len(seen_conns)}. "
            f"Current estimated risk level: {risk}."
        )

        recommendations = [
            "Escalate and investigate all high/critical alerts first.",
            "Validate suspicious outbound network destinations and block known-malicious indicators.",
            "Review startup/persistence-related process and registry activity.",
            "Run endpoint malware scan and isolate host if active compromise indicators are confirmed.",
        ]

        return {
            "status": "completed_with_fallback",
            "query": query,
            "analysis": analysis,
            "confidence": confidence,
            "recommendations": recommendations,
            "related_techniques": [],
            "sources": ["agent_profile", "recent_alerts", "recent_telemetry"],
            "tools_used": [],
        }

    analysis = (
        "Fallback threat assessment completed with limited endpoint context. "
        f"Available agents discovered: {len(available_agents)}. "
        "No specific endpoint was matched from the query."
    )
    return {
        "status": "completed_with_fallback",
        "query": query,
        "analysis": analysis,
        "confidence": 0.45,
        "recommendations": [
            "Specify an endpoint hostname or IP for a deeper assessment.",
            "Ensure agent telemetry is flowing and endpoint is online.",
            "Run targeted indicator lookups for suspicious IPs/domains/hashes.",
        ],
        "related_techniques": [],
        "sources": ["available_agents"],
        "tools_used": [],
    }


# ─────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────

@router.post("/investigate")
async def investigate(
    payload: InvestigationQuery,
    _current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """AI-powered threat investigation with automatic context enrichment."""
    # ── Auto-enrich context ────────────────────────────────────
    enriched_context = await _enrich_context(payload.query, payload.context, db)

    try:
        from app.services.llm_engine import LLMEngine

        engine = LLMEngine()
        result = await engine.investigate(
            query=payload.query,
            context=enriched_context,
        )
        return {
            "status": "completed",
            "query": payload.query,
            "analysis": result.get("analysis", ""),
            "confidence": result.get("confidence", 0),
            "recommendations": result.get("recommendations", []),
            "related_techniques": result.get("mitre_techniques", []),
            "sources": result.get("sources", []),
            "tools_used": result.get("tools_used", []),
        }
    except Exception as e:
        logger.error("Investigation failed", query=payload.query[:100], error=str(e))
        fallback = _build_fallback_assessment(payload.query, enriched_context)
        fallback["analysis"] = f"{fallback['analysis']}\n\nLLM unavailable: {e}"
        return fallback


class ShellAnalysisRequest(BaseModel):
    agent_id: str = Field(..., min_length=1)
    command: str = Field(..., min_length=1, max_length=500)
    output: str = Field(..., min_length=1, max_length=2_000_000)


@router.post("/shell-output")
async def analyze_shell_output(
    payload: ShellAnalysisRequest,
    _current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    AI-powered analysis of remote shell command output.
    Detects security issues, vulnerabilities, anomalies, and maps to MITRE ATT&CK.
    """
    # Load agent context for the LLM
    agent_context: dict | None = None
    try:
        result = await db.execute(select(Agent).where(Agent.id == payload.agent_id))
        agent = result.scalar_one_or_none()
        if agent:
            agent_context = {
                "hostname": agent.hostname,
                "os_type": agent.os_type,
                "os_version": agent.os_version,
                "architecture": agent.architecture,
                "internal_ip": agent.internal_ip,
                "external_ip": agent.external_ip,
                "status": agent.status,
                "agent_version": agent.agent_version,
            }
    except Exception:
        pass  # proceed without agent context

    try:
        from app.services.llm_engine import LLMEngine

        engine = LLMEngine()
        result = await engine.analyze_shell_output(
            command=payload.command,
            output=payload.output,
            agent_context=agent_context,
        )
        return {
            "status": "completed",
            "agent_id": payload.agent_id,
            "command": payload.command,
            "summary": result.get("summary", ""),
            "risk_level": result.get("risk_level", "unknown"),
            "findings": result.get("findings", []),
            "recommendations": result.get("recommendations", []),
            "mitre_techniques": result.get("mitre_techniques", []),
            "confidence": result.get("confidence", 0),
        }
    except Exception as e:
        logger.error("Shell output analysis failed", error=str(e))
        # Provide a deterministic fallback analysis
        return _build_shell_fallback(payload.command, payload.output, payload.agent_id)


def _build_shell_fallback(command: str, output: str, agent_id: str) -> dict:
    """Deterministic fallback when LLM is unavailable."""
    output_lower = output.lower()
    findings = []

    # Simple heuristic detections
    suspicious_patterns = [
        ("mimikatz", "Credential dumping tool detected", "critical", "T1003"),
        ("cobalt", "Possible CobaltStrike indicator", "critical", "T1071.001"),
        ("nc.exe", "Netcat detected — potential reverse shell", "high", "T1059"),
        ("ncat", "Netcat variant detected", "high", "T1059"),
        ("powershell -enc", "Encoded PowerShell execution", "high", "T1059.001"),
        ("bypass executionpolicy", "Execution policy bypass", "medium", "T1059.001"),
        ("scheduled task", "Scheduled task — check for persistence", "medium", "T1053.005"),
        ("run key", "Registry Run key — persistence mechanism", "medium", "T1547.001"),
        ("0.0.0.0:0", "Listening on all interfaces", "low", "T1071"),
    ]
    for pattern, title, severity, technique in suspicious_patterns:
        if pattern in output_lower:
            findings.append({
                "title": title,
                "severity": severity,
                "description": f"Pattern '{pattern}' found in command output.",
                "mitre_technique": technique,
                "evidence": pattern,
            })

    risk = "clean"
    if any(f["severity"] == "critical" for f in findings):
        risk = "critical"
    elif any(f["severity"] == "high" for f in findings):
        risk = "high"
    elif any(f["severity"] == "medium" for f in findings):
        risk = "medium"
    elif findings:
        risk = "low"

    return {
        "status": "completed_with_fallback",
        "agent_id": agent_id,
        "command": command,
        "summary": f"Fallback pattern-matching analysis (LLM unavailable). Found {len(findings)} potential issue(s) in the output of '{command}'.",
        "risk_level": risk,
        "findings": findings,
        "recommendations": [
            "Configure an LLM provider (Ollama/OpenAI/Anthropic) for deeper AI analysis.",
            "Review each finding manually and correlate with other telemetry.",
        ] if findings else ["Output appears clean based on pattern matching. Configure LLM for deeper analysis."],
        "mitre_techniques": list({f["mitre_technique"] for f in findings}),
        "confidence": 0.4 if findings else 0.5,
    }


@router.post("/threat-lookup")
async def threat_lookup(
    payload: ThreatLookupRequest,
    _current_user: dict = Depends(require_role("viewer")),
) -> dict:
    """Look up a threat indicator across multiple intelligence sources."""
    try:
        from app.services.threat_analyzer import ThreatAnalyzer

        analyzer = ThreatAnalyzer()
        result = await analyzer.lookup_indicator(
            indicator_type=payload.indicator_type,
            indicator_value=payload.indicator_value,
        )
        return {
            "indicator_type": payload.indicator_type,
            "indicator_value": payload.indicator_value,
            "threat_level": result["threat_level"],
            "sources": result["sources"],
            "details": result["details"],
            "recommendations": result["recommendations"],
        }
    except Exception as e:
        logger.error(
            "Threat lookup failed",
            indicator_type=payload.indicator_type,
            error=str(e),
        )
        return {
            "indicator_type": payload.indicator_type,
            "indicator_value": payload.indicator_value,
            "threat_level": "unknown",
            "sources": [],
            "details": {"error": str(e)},
            "recommendations": [
                "Verify AI provider configuration and retry.",
                "Use direct OSINT tools as temporary fallback.",
            ],
        }
