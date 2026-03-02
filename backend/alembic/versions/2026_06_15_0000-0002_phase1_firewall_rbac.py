"""Phase 1 — Firewall management, approvals, RBAC, HMAC signing

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-15 00:00:00.000000+00:00

Adds:
  - firewall_rules: Tracked/managed firewall rules per agent
  - firewall_rule_revisions: Version history for rule changes
  - firewall_policies: Named policy templates with JSONB rule sets
  - remediation_approvals: Approval workflow for destructive actions
  - remediation_actions: Full audit trail (replaces if exists, adds new columns)
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── firewall_policies (must come before firewall_rules due to FK) ──
    op.create_table(
        "firewall_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), unique=True, nullable=False, index=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("rules", postgresql.JSONB, nullable=True),
        sa.Column("default_inbound_action", sa.String(20), server_default="block"),
        sa.Column("default_outbound_action", sa.String(20), server_default="allow"),
        sa.Column("assigned_agent_count", sa.Integer, server_default=sa.text("0")),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── firewall_rules ───────────────────────────────────────────
    op.create_table(
        "firewall_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("direction", sa.String(20), nullable=False),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("protocol", sa.String(10), nullable=True),
        sa.Column("port", sa.String(100), nullable=True),
        sa.Column("remote_address", sa.String(255), nullable=True),
        sa.Column("local_address", sa.String(255), nullable=True),
        sa.Column("enabled", sa.Boolean, server_default=sa.text("true")),
        sa.Column("profile", sa.String(50), nullable=True),
        sa.Column(
            "policy_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("firewall_policies.id"),
            nullable=True,
        ),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("drift_detected", sa.Boolean, server_default=sa.text("false")),
        sa.Column("current_version", sa.Integer, server_default=sa.text("1")),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_firewall_rules_agent_name",
        "firewall_rules",
        ["agent_id", "name"],
    )

    # ── firewall_rule_revisions ──────────────────────────────────
    op.create_table(
        "firewall_rule_revisions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("firewall_rules.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("diff", postgresql.JSONB, nullable=True),
        sa.Column("snapshot", postgresql.JSONB, nullable=True),
        sa.Column(
            "changed_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("change_reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── remediation_approvals ────────────────────────────────────
    op.create_table(
        "remediation_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "remediation_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "requested_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column(
            "approved_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="pending",
            index=True,
        ),
        sa.Column("request_reason", sa.Text, nullable=True),
        sa.Column("approval_note", sa.Text, nullable=True),
        sa.Column("action_type", sa.String(50), nullable=True),
        sa.Column("action_params", postgresql.JSONB, nullable=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── remediation_actions ──────────────────────────────────────
    # Create the full table (only if it doesn't exist yet in the DB)
    op.create_table(
        "remediation_actions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("action_type", sa.String(50), nullable=False, index=True),
        sa.Column(
            "rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("firewall_rules.id"),
            nullable=True,
        ),
        sa.Column(
            "approval_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_approvals.id"),
            nullable=True,
        ),
        sa.Column(
            "rollback_of",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_actions.id"),
            nullable=True,
        ),
        sa.Column("command_signature", sa.String(256), nullable=True),
        sa.Column("rule_name", sa.String(255), nullable=True),
        sa.Column("direction", sa.String(20), nullable=True),
        sa.Column("action", sa.String(20), nullable=True),
        sa.Column("protocol", sa.String(10), nullable=True),
        sa.Column("port", sa.String(100), nullable=True),
        sa.Column("remote_address", sa.String(255), nullable=True),
        sa.Column("parameters", postgresql.JSONB, nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending", index=True),
        sa.Column("result_output", sa.Text, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column(
            "initiated_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ── agents table additions ───────────────────────────────────
    # Add hmac_key column to agents for HMAC command signing
    op.add_column(
        "agents",
        sa.Column("hmac_key", sa.String(128), nullable=True),
    )


def downgrade() -> None:
    # Remove agents additions
    op.drop_column("agents", "hmac_key")

    # Drop tables in reverse dependency order
    op.drop_table("remediation_actions")
    op.drop_table("remediation_approvals")
    op.drop_table("firewall_rule_revisions")
    op.drop_index("ix_firewall_rules_agent_name", table_name="firewall_rules")
    op.drop_table("firewall_rules")
    op.drop_table("firewall_policies")
