"""Telemetry event schemas."""

from datetime import datetime

from pydantic import BaseModel, Field


class ProcessEvent(BaseModel):
    """Process creation or termination event."""

    event_action: str = Field(..., pattern=r"^(create|terminate|modify)$")
    process_name: str
    process_id: int
    parent_process_id: int | None = None
    command_line: str | None = None
    file_path: str | None = None
    file_hash_sha256: str | None = None
    username: str | None = None
    event_time: datetime


class FileEvent(BaseModel):
    """File system event."""

    event_action: str = Field(..., pattern=r"^(create|modify|delete|rename)$")
    file_path: str
    file_hash_sha256: str | None = None
    file_size: int | None = None
    process_name: str | None = None
    process_id: int | None = None
    event_time: datetime


class NetworkEvent(BaseModel):
    """Network connection event."""

    event_action: str = Field(..., pattern=r"^(connect|listen|dns_query|close)$")
    source_ip: str | None = None
    source_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: str | None = None
    dns_query: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    event_time: datetime


class AuthEvent(BaseModel):
    """Authentication event."""

    event_action: str = Field(..., pattern=r"^(login|logout|failed_login|privilege_escalation)$")
    username: str
    auth_result: str  # success | failure
    source_ip: str | None = None
    method: str | None = None  # password | key | certificate
    event_time: datetime


class TelemetryEventRequest(BaseModel):
    """Union of all telemetry event types."""

    event_type: str = Field(
        ..., pattern=r"^(process|file|network|auth|registry|system)$"
    )
    data: dict  # Type-specific data matching one of the above schemas
    event_time: datetime
