"""
Remediation Action Model

Tracks firewall rule changes and other remediation actions
applied to agents, with full audit trail.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RemediationAction(Base):
    """A firewall or remediation action applied to an endpoint."""

    __tablename__ = "remediation_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # --- Target ---
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False, index=True
    )

    # --- Action ---
    action_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # firewall_add | firewall_delete | firewall_edit | firewall_toggle | firewall_block_ip | firewall_block_port

    # --- Linked Firewall Rule ---
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("firewall_rules.id"), nullable=True
    )

    # --- Approval Link ---
    approval_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("remediation_approvals.id"), nullable=True
    )

    # --- Rollback Chain ---
    rollback_of: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("remediation_actions.id"), nullable=True
    )

    # --- Command Signing ---
    command_signature: Mapped[str | None] = mapped_column(
        String(256), nullable=True
    )

    # --- Parameters ---
    rule_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    direction: Mapped[str | None] = mapped_column(String(20), nullable=True)   # inbound | outbound
    action: Mapped[str | None] = mapped_column(String(20), nullable=True)      # allow | block
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)    # tcp | udp | any | icmp
    port: Mapped[str | None] = mapped_column(String(100), nullable=True)
    remote_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    parameters: Mapped[dict | None] = mapped_column(JSONB, nullable=True)      # full params blob

    # --- Result ---
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending", index=True
    )  # pending | applied | failed | rolled_back
    result_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Audit ---
    initiated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<RemediationAction(id={self.id}, agent_id={self.agent_id}, "
            f"action_type={self.action_type}, status={self.status})>"
        )
