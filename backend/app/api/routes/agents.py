"""
Agent Routes

Agent registration, heartbeat, telemetry ingestion, management,
and real-time command relay via Redis.
"""

import asyncio
import json as _json
from datetime import datetime, timezone
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    create_agent_token,
    get_current_user,
    get_current_agent,
    require_role,
    generate_hmac_key,
)
from app.core.config import settings
from app.models.agent import Agent
from app.models.alert import Alert
from app.models.event import TelemetryEvent
from app.schemas.agent import (
    AgentRegistration,
    AgentRegistrationResponse,
    HeartbeatPayload,
    HeartbeatResponse,
    TelemetryBatch,
    AgentResponse,
    AgentListResponse,
    AgentCommand,
    CommandResultPayload,
    CommandResponse,
)

logger = structlog.get_logger()
router = APIRouter()

# == Redis helper (lazy import) ==========================================
_redis_client = None


async def _get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            import redis.asyncio as aioredis
            _redis_client = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
            )
            await _redis_client.ping()
            logger.info("Redis connected for command relay")
        except Exception as e:
            logger.warning("Redis not available, command relay disabled", error=str(e))
            _redis_client = None
    return _redis_client


# =====================================================
# Agent-facing endpoints (agent auth)
# =====================================================


@router.post("/register", response_model=AgentRegistrationResponse)
async def register_agent(
    payload: AgentRegistration,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Register a new endpoint agent or re-register an existing one."""
    existing_result = await db.execute(
        select(Agent)
        .where(Agent.hostname == payload.hostname)
        .where(Agent.os_type == payload.os_type)
        .where(Agent.status != "decommissioned")
        .order_by(Agent.last_heartbeat.desc().nullslast())
        .limit(1)
    )
    existing = existing_result.scalar_one_or_none()

    if existing:
        existing.os_version = payload.os_version
        existing.architecture = payload.architecture
        existing.agent_version = payload.agent_version
        existing.internal_ip = payload.internal_ip or existing.internal_ip
        existing.mac_address = payload.mac_address or existing.mac_address
        existing.status = "online"
        existing.last_heartbeat = datetime.now(timezone.utc)
        # Provision HMAC key if not yet assigned
        if not existing.hmac_key:
            existing.hmac_key = generate_hmac_key()
        auth_token = create_agent_token(str(existing.id), existing.hostname)
        logger.info("Agent re-registered (dedup)", agent_id=str(existing.id), hostname=existing.hostname)
        return {
            "agent_id": str(existing.id),
            "auth_token": auth_token,
            "heartbeat_interval": settings.AGENT_HEARTBEAT_INTERVAL_SECONDS,
            "hmac_key": existing.hmac_key,
            "policy": None,
        }

    agent = Agent(
        hostname=payload.hostname,
        os_type=payload.os_type,
        os_version=payload.os_version,
        architecture=payload.architecture,
        agent_version=payload.agent_version,
        internal_ip=payload.internal_ip,
        mac_address=payload.mac_address,
        hmac_key=generate_hmac_key(),
        status="online",
        last_heartbeat=datetime.now(timezone.utc),
    )
    db.add(agent)
    await db.flush()
    await db.refresh(agent)
    auth_token = create_agent_token(str(agent.id), agent.hostname)
    logger.info("Agent registered (new)", agent_id=str(agent.id), hostname=agent.hostname, os_type=agent.os_type)
    return {
        "agent_id": str(agent.id),
        "auth_token": auth_token,
        "heartbeat_interval": settings.AGENT_HEARTBEAT_INTERVAL_SECONDS,
        "hmac_key": agent.hmac_key,
        "policy": None,
    }


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def agent_heartbeat(
    payload: HeartbeatPayload,
    agent_data: dict = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Receive heartbeat from an agent and return any pending commands."""
    agent_id = agent_data["sub"]
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    agent.cpu_usage = payload.cpu_usage
    agent.memory_usage = payload.memory_usage
    agent.disk_usage = payload.disk_usage
    agent.uptime_seconds = payload.uptime_seconds
    agent.internal_ip = payload.internal_ip or agent.internal_ip
    agent.external_ip = payload.external_ip or agent.external_ip
    agent.agent_version = payload.agent_version
    agent.status = "online"
    agent.last_heartbeat = datetime.now(timezone.utc)

    # Drain pending commands from Redis
    commands: list[dict] = []
    redis = await _get_redis()
    if redis:
        try:
            pending_key = f"sentinel:agent:{agent_id}:pending"
            while True:
                cmd_id = await redis.lpop(pending_key)
                if not cmd_id:
                    break
                cmd_data = await redis.get(f"sentinel:cmd:{cmd_id}")
                if cmd_data:
                    cmd = _json.loads(cmd_data)
                    commands.append({
                        "command_id": cmd_id,
                        "command": cmd["command"],
                        "parameters": cmd.get("parameters", {}),
                    })
        except Exception as e:
            logger.warning("Failed to fetch pending commands", error=str(e))

    return {"status": "ok", "commands": commands, "policy_update": None, "yara_rules_version": None}


@router.get("/commands/pending")
async def get_pending_commands(
    agent_data: dict = Depends(get_current_agent),
) -> dict:
    """Agent polls this endpoint for pending commands (faster than heartbeat)."""
    agent_id = agent_data["sub"]
    redis = await _get_redis()
    commands: list[dict] = []
    if redis:
        try:
            pending_key = f"sentinel:agent:{agent_id}:pending"
            while True:
                cmd_id = await redis.lpop(pending_key)
                if not cmd_id:
                    break
                cmd_data = await redis.get(f"sentinel:cmd:{cmd_id}")
                if cmd_data:
                    cmd = _json.loads(cmd_data)
                    commands.append({
                        "command_id": cmd_id,
                        "command": cmd["command"],
                        "parameters": cmd.get("parameters", {}),
                    })
        except Exception as e:
            logger.warning("Failed to fetch pending commands", error=str(e))
    return {"commands": commands}


@router.post("/command-result")
async def submit_command_result(
    payload: CommandResultPayload,
    agent_data: dict = Depends(get_current_agent),
) -> dict:
    """Agent submits the result of an executed command."""
    redis = await _get_redis()
    if not redis:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis unavailable")

    result_key = f"sentinel:cmd:{payload.command_id}:result"
    result_data = _json.dumps({
        "command_id": payload.command_id,
        "status": payload.status,
        "output": payload.output,
        "data": payload.data,
        "exit_code": payload.exit_code,
    })
    await redis.set(result_key, result_data, ex=300)
    logger.info("Command result received", command_id=payload.command_id, status=payload.status, output_len=len(payload.output))
    return {"status": "accepted"}


@router.post("/telemetry")
async def ingest_telemetry(
    payload: TelemetryBatch,
    agent_data: dict = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Ingest a batch of telemetry events from an agent."""
    agent_id = agent_data["sub"]
    events_created = 0
    raw_events_for_analysis: list[dict] = []

    # Validate agent exists before inserting events (prevents FK violation → 500)
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found — please re-register",
        )

    for event_data in payload.events:
        event = TelemetryEvent(
            agent_id=agent_id,
            event_type=event_data.get("event_type", "unknown"),
            event_action=event_data.get("event_action", "unknown"),
            process_name=event_data.get("process_name"),
            process_id=event_data.get("process_id"),
            parent_process_id=event_data.get("parent_process_id"),
            command_line=event_data.get("command_line"),
            file_path=event_data.get("file_path"),
            file_hash_sha256=event_data.get("file_hash_sha256"),
            source_ip=event_data.get("source_ip"),
            source_port=event_data.get("source_port"),
            dest_ip=event_data.get("dest_ip"),
            dest_port=event_data.get("dest_port"),
            protocol=event_data.get("protocol"),
            dns_query=event_data.get("dns_query"),
            username=event_data.get("username"),
            auth_result=event_data.get("auth_result"),
            raw_payload=event_data,
            event_time=payload.timestamp,
        )
        db.add(event)
        events_created += 1
        raw_events_for_analysis.append(event_data)

    agent.last_telemetry = datetime.now(timezone.utc)
    await db.flush()

    logger.info("Telemetry ingested", agent_id=agent_id, batch_id=payload.batch_id, event_count=events_created)

    agent_info = {
        "agent_id": agent_id,
        "hostname": agent.hostname,
        "os_type": agent.os_type,
    }
    # Run detection pipeline in background with its OWN DB session (safe for background task)
    from app.services.detection_pipeline import run_detection_pipeline
    asyncio.create_task(run_detection_pipeline(agent_id, agent_info, raw_events_for_analysis))

    return {"status": "accepted", "events_processed": events_created, "batch_id": payload.batch_id}



# =====================================================
# Panel-facing endpoints (user auth)
# =====================================================


@router.get("/", response_model=AgentListResponse)
async def list_agents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status"),
    os_filter: str | None = Query(None, alias="os"),
    search: str | None = None,
    _current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List all registered agents with optional filtering and pagination."""
    query = select(Agent)
    if status_filter != "decommissioned":
        query = query.where(Agent.status != "decommissioned")
    if status_filter and status_filter != "decommissioned":
        query = query.where(Agent.status == status_filter)
    if os_filter:
        query = query.where(Agent.os_type == os_filter)
    if search:
        query = query.where(
            Agent.hostname.ilike(f"%{search}%")
            | Agent.display_name.ilike(f"%{search}%")
            | Agent.internal_ip.ilike(f"%{search}%")
        )
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    agents = result.scalars().all()
    return {"agents": agents, "total": total, "page": page, "page_size": page_size}


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    _current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> Agent:
    """Get detailed information about a specific agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return agent


@router.post("/{agent_id}/command")
async def send_command(
    agent_id: str,
    command: AgentCommand,
    _current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Send a command to an agent and wait for the result.

    1. Validate agent exists and is online
    2. Push command to Redis queue
    3. Poll for result (agent picks up via /commands/pending)
    4. Return result or timeout after 30s
    """
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    # Handle isolation at DB level
    if command.command == "isolate":
        agent.is_isolated = True
        agent.status = "isolated"
        return {"command_id": "", "agent_id": agent_id, "command": "isolate", "status": "completed", "output": "Agent isolated"}
    elif command.command == "unisolate":
        agent.is_isolated = False
        agent.status = "online"
        return {"command_id": "", "agent_id": agent_id, "command": "unisolate", "status": "completed", "output": "Agent un-isolated"}

    # Relay via Redis
    redis = await _get_redis()
    if not redis:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis unavailable - cannot relay commands to agent")

    command_id = str(uuid4())
    cmd_payload = _json.dumps({"command": command.command, "parameters": command.parameters})
    await redis.set(f"sentinel:cmd:{command_id}", cmd_payload, ex=300)
    await redis.rpush(f"sentinel:agent:{agent_id}:pending", command_id)

    logger.info("Command queued", command_id=command_id, agent_id=agent_id, command=command.command)

    # Poll for result
    result_key = f"sentinel:cmd:{command_id}:result"
    for _ in range(60):
        result_data = await redis.get(result_key)
        if result_data:
            parsed = _json.loads(result_data)
            await redis.delete(result_key)
            await redis.delete(f"sentinel:cmd:{command_id}")
            return {
                "command_id": command_id,
                "agent_id": agent_id,
                "command": command.command,
                "status": parsed.get("status", "completed"),
                "output": parsed.get("output", ""),
                "data": parsed.get("data"),
                "exit_code": parsed.get("exit_code"),
            }
        await asyncio.sleep(0.5)

    await redis.delete(f"sentinel:cmd:{command_id}")
    return {
        "command_id": command_id,
        "agent_id": agent_id,
        "command": command.command,
        "status": "timeout",
        "output": "Command timed out after 30 seconds. Agent may be offline or unresponsive.",
        "data": None,
        "exit_code": None,
    }


@router.delete("/{agent_id}")
async def decommission_agent(
    agent_id: str,
    _current_user: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Permanently decommission an agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    agent.status = "decommissioned"
    agent.is_isolated = False
    logger.info("Agent decommissioned", agent_id=agent_id, hostname=agent.hostname)
    return {"status": "decommissioned", "agent_id": agent_id}


# =====================================================
# Agent Tagging & Management
# =====================================================


@router.patch("/{agent_id}/tags")
async def update_agent_tags(
    agent_id: str,
    tag_update: dict,
    _current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Update tags on an agent.

    Body: {"tags": {"environment": "production", "department": "finance"}}
    """
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    new_tags = tag_update.get("tags", {})
    if not isinstance(new_tags, dict):
        raise HTTPException(status_code=422, detail="tags must be a dictionary")

    # Merge with existing tags
    existing = agent.tags or {}
    existing.update(new_tags)
    # Remove keys set to None
    agent.tags = {k: v for k, v in existing.items() if v is not None}

    logger.info("Agent tags updated", agent_id=agent_id, tags=agent.tags)
    return {"agent_id": agent_id, "tags": agent.tags}


@router.patch("/{agent_id}/display-name")
async def update_agent_display_name(
    agent_id: str,
    payload: dict,
    _current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update the display name for an agent. Body: {"display_name": "DC-Primary"}"""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    agent.display_name = payload.get("display_name")
    return {"agent_id": agent_id, "display_name": agent.display_name}
