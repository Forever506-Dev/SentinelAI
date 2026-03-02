"""
Agent Model

Represents an endpoint agent installed on a managed device.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Boolean, DateTime, Integer, Text, Float
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Agent(Base):
    """Endpoint agent registered with the platform."""

    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # --- Identity ---
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(50), nullable=False)

    # --- Platform ---
    os_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # windows | linux | macos | android
    os_version: Mapped[str] = mapped_column(String(100), nullable=False)
    architecture: Mapped[str] = mapped_column(String(20), nullable=False)  # x86_64 | aarch64

    # --- Network ---
    internal_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    external_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)

    # --- Status ---
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="online", index=True
    )  # online | offline | isolated | decommissioned
    is_isolated: Mapped[bool] = mapped_column(Boolean, default=False)

    # --- System Metrics (latest snapshot) ---
    cpu_usage: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_usage: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_usage: Mapped[float | None] = mapped_column(Float, nullable=True)
    uptime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- Policy & Tags ---
    policy_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tags: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=dict)

    # --- Installed Software (cached) ---
    installed_software: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # --- Authentication ---
    auth_token_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    hmac_key: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # --- Timestamps ---
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_heartbeat: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_telemetry: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<Agent(id={self.id}, hostname={self.hostname}, "
            f"os={self.os_type}, status={self.status})>"
        )
