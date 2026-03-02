"""
Telemetry Event Model

Raw telemetry events received from endpoint agents.
Stored briefly in PostgreSQL then indexed into Elasticsearch for long-term search.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Integer, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class TelemetryEvent(Base):
    """Raw telemetry event from an endpoint agent."""

    __tablename__ = "telemetry_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # --- Source ---
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False, index=True
    )

    # --- Event Classification ---
    event_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # process | file | network | registry | auth | system
    event_action: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # create | modify | delete | connect | login | execute

    # --- Event Data ---
    # Process events
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parent_process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_hash_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Network events
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dest_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dest_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    dns_query: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Auth events
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    auth_result: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # --- Full raw payload (for anything not covered by typed columns) ---
    raw_payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # --- Timestamps ---
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self) -> str:
        return (
            f"<TelemetryEvent(id={self.id}, type={self.event_type}, "
            f"action={self.event_action}, agent={self.agent_id})>"
        )
