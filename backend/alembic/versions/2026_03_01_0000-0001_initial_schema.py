"""Initial schema — users, agents, alerts, telemetry_events

Revision ID: 0001
Revises: None
Create Date: 2026-03-01 00:00:00.000000+00:00

Baseline migration capturing all four ORM models as they exist today.
This was generated manually to bootstrap Alembic on an existing database.
If you already have tables, run:
    alembic stamp 0001
to mark this revision as applied without executing the DDL.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── users ────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), unique=True, nullable=False, index=True),
        sa.Column("username", sa.String(100), unique=True, nullable=False, index=True),
        sa.Column("hashed_password", sa.Text, nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("role", sa.String(50), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean, server_default=sa.text("true")),
        sa.Column("is_superuser", sa.Boolean, server_default=sa.text("false")),
        sa.Column("totp_secret", sa.Text, nullable=True),
        sa.Column("totp_enabled", sa.Boolean, server_default=sa.text("false")),
        sa.Column("reset_code", sa.String(8), nullable=True),
        sa.Column("reset_code_expires", sa.DateTime(timezone=True), nullable=True),
        sa.Column("must_change_password", sa.Boolean, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )

    # ── agents ───────────────────────────────────────────────────
    op.create_table(
        "agents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False, index=True),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("agent_version", sa.String(50), nullable=False),
        sa.Column("os_type", sa.String(50), nullable=False),
        sa.Column("os_version", sa.String(100), nullable=False),
        sa.Column("architecture", sa.String(20), nullable=False),
        sa.Column("internal_ip", sa.String(45), nullable=True),
        sa.Column("external_ip", sa.String(45), nullable=True),
        sa.Column("mac_address", sa.String(17), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="online", index=True),
        sa.Column("is_isolated", sa.Boolean, server_default=sa.text("false")),
        sa.Column("cpu_usage", sa.Float, nullable=True),
        sa.Column("memory_usage", sa.Float, nullable=True),
        sa.Column("disk_usage", sa.Float, nullable=True),
        sa.Column("uptime_seconds", sa.Integer, nullable=True),
        sa.Column("policy_id", sa.String(100), nullable=True),
        sa.Column("tags", postgresql.JSONB, nullable=True),
        sa.Column("installed_software", postgresql.JSONB, nullable=True),
        sa.Column("auth_token_hash", sa.Text, nullable=True),
        sa.Column("registered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_telemetry", sa.DateTime(timezone=True), nullable=True),
    )

    # ── alerts ───────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, index=True),
        sa.Column("confidence", sa.Float, nullable=False, server_default=sa.text("0.0")),
        sa.Column("status", sa.String(20), nullable=False, server_default="new", index=True),
        sa.Column("detection_source", sa.String(50), nullable=False),
        sa.Column("rule_id", sa.String(255), nullable=True),
        sa.Column("rule_name", sa.String(255), nullable=True),
        sa.Column("mitre_tactics", postgresql.ARRAY(sa.String), nullable=True),
        sa.Column("mitre_techniques", postgresql.ARRAY(sa.String), nullable=True),
        sa.Column("related_cves", postgresql.ARRAY(sa.String), nullable=True),
        sa.Column("ioc_indicators", postgresql.JSONB, nullable=True),
        sa.Column("llm_analysis", sa.Text, nullable=True),
        sa.Column("llm_recommendation", sa.Text, nullable=True),
        sa.Column("llm_confidence", sa.Float, nullable=True),
        sa.Column("raw_events", postgresql.JSONB, nullable=True),
        sa.Column("process_tree", postgresql.JSONB, nullable=True),
        sa.Column("network_context", postgresql.JSONB, nullable=True),
        sa.Column("response_actions", postgresql.JSONB, nullable=True),
        sa.Column(
            "assigned_to",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("correlation_group", sa.String(100), nullable=True, index=True),
        sa.Column("related_alert_count", sa.Integer, server_default=sa.text("0")),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ── telemetry_events ─────────────────────────────────────────
    op.create_table(
        "telemetry_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("event_type", sa.String(50), nullable=False, index=True),
        sa.Column("event_action", sa.String(50), nullable=False),
        sa.Column("process_name", sa.String(255), nullable=True),
        sa.Column("process_id", sa.Integer, nullable=True),
        sa.Column("parent_process_id", sa.Integer, nullable=True),
        sa.Column("command_line", sa.Text, nullable=True),
        sa.Column("file_path", sa.Text, nullable=True),
        sa.Column("file_hash_sha256", sa.String(64), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("source_port", sa.Integer, nullable=True),
        sa.Column("dest_ip", sa.String(45), nullable=True),
        sa.Column("dest_port", sa.Integer, nullable=True),
        sa.Column("protocol", sa.String(10), nullable=True),
        sa.Column("dns_query", sa.String(255), nullable=True),
        sa.Column("username", sa.String(100), nullable=True),
        sa.Column("auth_result", sa.String(20), nullable=True),
        sa.Column("raw_payload", postgresql.JSONB, nullable=True),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("telemetry_events")
    op.drop_table("alerts")
    op.drop_table("agents")
    op.drop_table("users")
