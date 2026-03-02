"""Approval schemas for request/response validation."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ApprovalResponse(BaseModel):
    """Full approval details."""
    id: uuid.UUID
    remediation_id: uuid.UUID
    requested_by: uuid.UUID
    approved_by: uuid.UUID | None = None
    status: str
    request_reason: str | None = None
    approval_note: str | None = None
    expires_at: datetime
    created_at: datetime
    resolved_at: datetime | None = None

    model_config = {"from_attributes": True}


class ApprovalDecisionRequest(BaseModel):
    """Approve or reject a remediation request."""
    decision: str = Field(..., pattern=r"^(approved|rejected)$")
    note: str = Field("", max_length=2000)


class PendingApprovalResponse(BaseModel):
    """Enriched pending approval with remediation + agent details."""
    id: uuid.UUID
    remediation_id: uuid.UUID
    requested_by: uuid.UUID
    requester_username: str | None = None
    status: str
    request_reason: str | None = None
    expires_at: datetime
    created_at: datetime

    # Remediation details
    action_type: str | None = None
    rule_name: str | None = None
    direction: str | None = None
    protocol: str | None = None
    port: str | None = None
    remote_address: str | None = None

    # Agent details
    agent_id: uuid.UUID | None = None
    agent_hostname: str | None = None


class ApprovalListResponse(BaseModel):
    """Paginated list of approvals."""
    approvals: list[PendingApprovalResponse]
    total: int
    page: int
    page_size: int


class ApprovalCountResponse(BaseModel):
    """Count of pending approvals (for sidebar badge)."""
    pending_count: int
