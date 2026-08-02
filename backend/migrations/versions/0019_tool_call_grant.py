"""tool_call_grant + tool_call_attempt tables (ISSUE-134 / #640)

Revision ID: 0019_tool_call_grant
Revises: 0018_knowledge_release
Create Date: 2026-08-02 14:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019_tool_call_grant"
down_revision: str | None = "0018_knowledge_release"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tool_call_grant",
        sa.Column("grant_id", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("namespace_key", sa.String(), nullable=False),
        sa.Column("shadow_run_id", sa.String(), nullable=True),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("plan_step_id", sa.String(), nullable=True),
        sa.Column("task_id", sa.String(), nullable=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("execution_principal", sa.JSON(), nullable=False),
        sa.Column("max_calls", sa.Integer(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_version", sa.String(), nullable=False),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("grant_token_hash", sa.String(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("grant_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_tool_call_grant_idempotency_key"),
    )
    op.create_index("ix_tool_call_grant_event_id", "tool_call_grant", ["event_id"])
    op.create_index("ix_tool_call_grant_namespace_key", "tool_call_grant", ["namespace_key"])
    op.create_index(
        "ix_tool_call_grant_mode_namespace",
        "tool_call_grant",
        ["mode", "namespace_key"],
    )

    op.create_table(
        "tool_call_attempt",
        sa.Column("attempt_id", sa.String(), nullable=False),
        sa.Column("grant_id", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("namespace_key", sa.String(), nullable=False),
        sa.Column("shadow_run_id", sa.String(), nullable=True),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("tool_name", sa.String(), nullable=False),
        sa.Column("attempt_seq", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("denial_reason", sa.Text(), nullable=True),
        sa.Column("params_hash", sa.String(), nullable=False),
        sa.Column("result_status", sa.String(), nullable=True),
        sa.Column("projection_hash", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["grant_id"],
            ["tool_call_grant.grant_id"],
            name="fk_tool_call_attempt_grant_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("attempt_id"),
        sa.UniqueConstraint(
            "grant_id",
            "attempt_seq",
            name="uq_tool_call_attempt_grant_seq",
        ),
    )
    op.create_index("ix_tool_call_attempt_grant_id", "tool_call_attempt", ["grant_id"])
    op.create_index("ix_tool_call_attempt_namespace_key", "tool_call_attempt", ["namespace_key"])
    op.create_index("ix_tool_call_attempt_event_id", "tool_call_attempt", ["event_id"])


def downgrade() -> None:
    op.drop_index("ix_tool_call_attempt_event_id", table_name="tool_call_attempt")
    op.drop_index("ix_tool_call_attempt_namespace_key", table_name="tool_call_attempt")
    op.drop_index("ix_tool_call_attempt_grant_id", table_name="tool_call_attempt")
    op.drop_table("tool_call_attempt")
    op.drop_index("ix_tool_call_grant_mode_namespace", table_name="tool_call_grant")
    op.drop_index("ix_tool_call_grant_namespace_key", table_name="tool_call_grant")
    op.drop_index("ix_tool_call_grant_event_id", table_name="tool_call_grant")
    op.drop_table("tool_call_grant")
