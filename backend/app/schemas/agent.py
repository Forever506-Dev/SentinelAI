"""Agent schemas for registration, heartbeat, and telemetry submission."""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class AgentRegistration(BaseModel):
    """Agent registration payload sent during first contact."""

    hostname: str = Field(..., max_length=255)
    os_type: str = Field(..., pattern=r"^(windows|linux|macos|android)$")
    os_version: str = Field(..., max_length=100)
    architecture: str = Field(..., pattern=r"^(x86_64|aarch64|armv7)$")
    agent_version: str = Field(..., max_length=50)
    internal_ip: str | None = None
    mac_address: str | None = None


class AgentRegistrationResponse(BaseModel):
    """Response to successful agent registration."""

    agent_id: str
    auth_token: str
    heartbeat_interval: int  # seconds
    hmac_key: str | None = None
    policy: dict | None = None


class HeartbeatPayload(BaseModel):
    """Periodic heartbeat from agent with system metrics."""

    cpu_usage: float = Field(..., ge=0.0, le=100.0)
    memory_usage: float = Field(..., ge=0.0, le=100.0)
    disk_usage: float = Field(..., ge=0.0, le=100.0)
    uptime_seconds: int = Field(..., ge=0)
    internal_ip: str | None = None
    external_ip: str | None = None
    agent_version: str


class HeartbeatResponse(BaseModel):
    """Backend response to heartbeat - can push policy updates or commands."""

    status: str = "ok"
    commands: list[dict] = []
    policy_update: dict | None = None
    yara_rules_version: str | None = None


class TelemetryBatch(BaseModel):
    """Batch of telemetry events from an agent."""

    events: list[dict] = Field(..., min_length=1, max_length=500)
    batch_id: str
    timestamp: datetime


class AgentResponse(BaseModel):
    """Full agent details for the panel."""

    id: uuid.UUID
    hostname: str
    display_name: str | None
    os_type: str
    os_version: str
    architecture: str
    agent_version: str
    status: str
    is_isolated: bool
    internal_ip: str | None
    external_ip: str | None
    cpu_usage: float | None
    memory_usage: float | None
    disk_usage: float | None
    uptime_seconds: int | None
    tags: dict | None
    registered_at: datetime
    last_heartbeat: datetime | None

    model_config = {"from_attributes": True}


class AgentListResponse(BaseModel):
    """Paginated list of agents."""

    agents: list[AgentResponse]
    total: int
    page: int
    page_size: int


class AgentCommand(BaseModel):
    """Command to send to an agent — includes shell, scan, and management."""

    command: str = Field(
        ...,
        pattern=r"^(shell|sysinfo|ps|netstat|scan|scan_ports|installed_software|users|startup_items|scheduled_tasks|isolate|unisolate|restart|update|collect_forensics|kill_process|uninstall)$",
    )
    parameters: dict = {}


class PendingCommand(BaseModel):
    """A command waiting for the agent to pick up."""

    command_id: str
    command: str
    parameters: dict = {}


class CommandResultPayload(BaseModel):
    """Result of a command execution submitted by the agent."""

    command_id: str
    status: str = Field(..., pattern=r"^(completed|error|timeout)$")
    output: str = ""
    data: dict | None = None
    exit_code: int | None = None


class CommandResponse(BaseModel):
    """Response returned to the panel after a command completes."""

    command_id: str
    agent_id: str
    command: str
    status: str
    output: str = ""
    data: dict | None = None
    exit_code: int | None = None
