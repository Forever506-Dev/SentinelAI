"""
Approval Routes

Approval queue management for remediation actions.
Admins+ can approve/reject; viewers can see status.
"""

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_role
from app.models.approval import RemediationApproval
from app.models.remediation import RemediationAction
from app.models.agent import Agent
from app.models.user import User
from app.schemas.approval import (
    ApprovalDecisionRequest,
    ApprovalListResponse,
    ApprovalCountResponse,
    PendingApprovalResponse,
)
from app.services.firewall_service import relay_signed_command, record_remediation

logger = structlog.get_logger()
router = APIRouter()


@router.get("/pending/count", response_model=ApprovalCountResponse)
async def get_pending_count(
    current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get count of pending approvals (for sidebar badge)."""
    now = datetime.now(timezone.utc)

    # Expire old approvals
    expired_q = await db.execute(
        select(RemediationApproval)
        .where(RemediationApproval.status == "pending")
        .where(RemediationApproval.expires_at < now)
    )
    for approval in expired_q.scalars().all():
        approval.status = "expired"
        approval.resolved_at = now

    count_result = await db.execute(
        select(func.count())
        .select_from(RemediationApproval)
        .where(RemediationApproval.status == "pending")
    )
    return {"pending_count": count_result.scalar() or 0}


@router.get("/pending", response_model=ApprovalListResponse)
async def list_pending_approvals(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List pending approval requests with remediation + agent details."""
    now = datetime.now(timezone.utc)

    # Expire old approvals first
    expired_q = await db.execute(
        select(RemediationApproval)
        .where(RemediationApproval.status == "pending")
        .where(RemediationApproval.expires_at < now)
    )
    for approval in expired_q.scalars().all():
        approval.status = "expired"
        approval.resolved_at = now

    # Query pending
    query = (
        select(RemediationApproval)
        .where(RemediationApproval.status == "pending")
        .order_by(desc(RemediationApproval.created_at))
    )
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    approvals = result.scalars().all()

    # Enrich with remediation + agent + user details
    enriched = []
    for a in approvals:
        # Get remediation
        rem_result = await db.execute(
            select(RemediationAction).where(RemediationAction.id == a.remediation_id)
        )
        rem = rem_result.scalar_one_or_none()

        # Get requester username
        user_result = await db.execute(
            select(User).where(User.id == a.requested_by)
        )
        requester = user_result.scalar_one_or_none()

        # Get agent hostname
        agent_hostname = None
        agent_id = None
        if rem:
            agent_result = await db.execute(
                select(Agent).where(Agent.id == rem.agent_id)
            )
            agent_obj = agent_result.scalar_one_or_none()
            if agent_obj:
                agent_hostname = agent_obj.hostname
                agent_id = agent_obj.id

        enriched.append({
            "id": a.id,
            "remediation_id": a.remediation_id,
            "requested_by": a.requested_by,
            "requester_username": requester.username if requester else None,
            "status": a.status,
            "request_reason": a.request_reason,
            "expires_at": a.expires_at,
            "created_at": a.created_at,
            "action_type": rem.action_type if rem else None,
            "rule_name": rem.rule_name if rem else None,
            "direction": rem.direction if rem else None,
            "protocol": rem.protocol if rem else None,
            "port": rem.port if rem else None,
            "remote_address": rem.remote_address if rem else None,
            "agent_id": agent_id,
            "agent_hostname": agent_hostname,
        })

    return {"approvals": enriched, "total": total, "page": page, "page_size": page_size}


@router.post("/{approval_id}/decide")
async def decide_approval(
    approval_id: str,
    req: ApprovalDecisionRequest,
    current_user: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Approve or reject a pending remediation request. Admin+ only."""
    result = await db.execute(
        select(RemediationApproval).where(RemediationApproval.id == approval_id)
    )
    approval = result.scalar_one_or_none()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")

    if approval.status != "pending":
        raise HTTPException(status_code=400, detail=f"Approval is already '{approval.status}'")

    # Check expiry
    if approval.expires_at < datetime.now(timezone.utc):
        approval.status = "expired"
        approval.resolved_at = datetime.now(timezone.utc)
        return {"status": "expired", "output": "Approval request has expired"}

    approval.status = req.decision
    approval.approved_by = current_user.get("sub")
    approval.approval_note = req.note
    approval.resolved_at = datetime.now(timezone.utc)

    # If approved, execute the pending remediation
    if req.decision == "approved":
        rem_result = await db.execute(
            select(RemediationAction).where(RemediationAction.id == approval.remediation_id)
        )
        rem_action = rem_result.scalar_one_or_none()
        if rem_action and rem_action.status == "pending_approval":
            # Execute the actual command
            params = rem_action.parameters or {}
            cmd_result = await relay_signed_command(
                str(rem_action.agent_id), rem_action.action_type, params,
            )
            rem_action.status = "applied" if cmd_result.get("status") == "completed" else "failed"
            rem_action.result_output = cmd_result.get("output", "")
            rem_action.applied_at = datetime.now(timezone.utc)
            rem_action.approval_id = approval.id

            logger.info(
                "Approved remediation executed",
                remediation_id=str(rem_action.id),
                approval_id=approval_id,
                status=rem_action.status,
            )

            return {
                "status": "approved_and_executed",
                "remediation_status": rem_action.status,
                "output": cmd_result.get("output", ""),
            }

    return {
        "status": req.decision,
        "output": f"Approval {req.decision}",
    }


@router.get("/history")
async def approval_history(
    status_filter: str | None = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get approval history with optional status filter."""
    query = select(RemediationApproval).order_by(desc(RemediationApproval.created_at))
    if status_filter:
        query = query.where(RemediationApproval.status == status_filter)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    approvals = result.scalars().all()

    return {
        "approvals": [
            {
                "id": str(a.id),
                "remediation_id": str(a.remediation_id),
                "requested_by": str(a.requested_by),
                "approved_by": str(a.approved_by) if a.approved_by else None,
                "status": a.status,
                "request_reason": a.request_reason,
                "approval_note": a.approval_note,
                "expires_at": a.expires_at.isoformat(),
                "created_at": a.created_at.isoformat(),
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
            }
            for a in approvals
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }
