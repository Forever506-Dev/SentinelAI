"""
Remediation Approval Model

Tracks approval requests for destructive firewall/remediation actions.
Analysts create requests; admins/superadmins approve or reject them.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RemediationApproval(Base):
    """An approval request for a remediation action."""

    __tablename__ = "remediation_approvals"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # --- Linked Remediation ---
    remediation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("remediation_actions.id"),
        nullable=False, index=True
    )

    # --- Requester ---
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    request_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Approver ---
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )

    # --- Status ---
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending", index=True
    )  # pending | approved | rejected | expired | auto_approved

    approval_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Expiry ---
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # --- Timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<RemediationApproval(id={self.id}, remediation_id={self.remediation_id}, "
            f"status={self.status})>"
        )
