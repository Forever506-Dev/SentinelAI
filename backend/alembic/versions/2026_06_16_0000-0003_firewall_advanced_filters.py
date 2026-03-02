"""Phase 2 — Firewall advanced filtering, profiles array, indexing

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-16 00:00:00.000000+00:00

Changes:
  - firewall_rules.profiles: new ARRAY(String) column replacing scalar 'profile'
  - firewall_rules.local_port / remote_port: add missing columns to DB (model had them, migration didn't)
  - Indexes: trigram on name for ILIKE search, composite for common filter combos
  - Backfill: migrate existing 'profile' values into 'profiles' array
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Enable pg_trgm for fast ILIKE searches ──
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # ── Add profiles ARRAY column ──
    op.add_column(
        "firewall_rules",
        sa.Column(
            "profiles",
            postgresql.ARRAY(sa.String(20)),
            server_default="{}",
            nullable=False,
        ),
    )

    # ── Add local_port / remote_port if not present (model had them but 0002 used 'port') ──
    # Check if 'local_port' already exists; if not, add it and copy from 'port'
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_cols = {c["name"] for c in inspector.get_columns("firewall_rules")}

    if "local_port" not in existing_cols:
        op.add_column(
            "firewall_rules",
            sa.Column("local_port", sa.String(100), nullable=True, server_default="any"),
        )
        # Copy data from 'port' → 'local_port'
        op.execute("UPDATE firewall_rules SET local_port = COALESCE(port, 'any')")

    if "remote_port" not in existing_cols:
        op.add_column(
            "firewall_rules",
            sa.Column("remote_port", sa.String(100), nullable=True, server_default="any"),
        )

    # ── Backfill: migrate scalar 'profile' → 'profiles' array ──
    op.execute("""
        UPDATE firewall_rules
        SET profiles = CASE
            WHEN profile IS NULL OR profile = '' OR LOWER(profile) = 'any' THEN '{}'::text[]
            ELSE string_to_array(REPLACE(profile, ' ', ''), ',')
        END
    """)

    # ── Indexes for advanced filtering ──
    # Trigram GIN index on name for fast ILIKE search
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_firewall_rules_name_trgm
        ON firewall_rules USING gin (name gin_trgm_ops)
    """)

    # Composite index for common filter combinations
    op.create_index(
        "ix_firewall_rules_agent_direction_action",
        "firewall_rules",
        ["agent_id", "direction", "action"],
    )

    # Index on enabled for filtering active/disabled rules
    op.create_index(
        "ix_firewall_rules_agent_enabled",
        "firewall_rules",
        ["agent_id", "enabled"],
    )

    # GIN index on profiles array for @> (contains) queries
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_firewall_rules_profiles_gin
        ON firewall_rules USING gin (profiles)
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_firewall_rules_profiles_gin")
    op.drop_index("ix_firewall_rules_agent_enabled", table_name="firewall_rules")
    op.drop_index("ix_firewall_rules_agent_direction_action", table_name="firewall_rules")
    op.execute("DROP INDEX IF EXISTS ix_firewall_rules_name_trgm")

    # Backfill profiles → profile
    op.execute("""
        UPDATE firewall_rules
        SET profile = COALESCE(array_to_string(profiles, ','), 'any')
    """)

    op.drop_column("firewall_rules", "profiles")
    # Don't drop local_port/remote_port as they may have existed before
