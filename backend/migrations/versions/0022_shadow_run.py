"""shadow_run + shadow decision/artifact tables (ISSUE-135 / #641 Phase A)

Revision ID: 0022_shadow_run
Revises: 0021_detection_governance
Create Date: 2026-08-03 12:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0022_shadow_run"
down_revision: str | None = "0021_detection_governance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "shadow_run",
        sa.Column("shadow_run_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("namespace_key", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("max_steps", sa.Integer(), nullable=False),
        sa.Column("step_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_tool_calls", sa.Integer(), nullable=False),
        sa.Column("tool_call_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "result_summary",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "rejected_reasons",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'failed', 'rejected')",
            name="ck_shadow_run_status",
        ),
        sa.PrimaryKeyConstraint("shadow_run_id"),
    )
    op.create_index("ix_shadow_run_event_id", "shadow_run", ["event_id"])
    op.create_index("ix_shadow_run_tenant_id", "shadow_run", ["tenant_id"])
    op.create_index("ix_shadow_run_namespace_key", "shadow_run", ["namespace_key"])

    op.create_table(
        "shadow_decision_record",
        sa.Column("record_id", sa.String(), nullable=False),
        sa.Column("shadow_run_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("namespace_key", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("record_hash", sa.String(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("record_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_shadow_decision_record_idempotency_key"),
    )
    op.create_index(
        "ix_shadow_decision_record_shadow_run_id",
        "shadow_decision_record",
        ["shadow_run_id"],
    )
    op.create_index("ix_shadow_decision_record_event_id", "shadow_decision_record", ["event_id"])

    op.create_table(
        "shadow_query_artifact",
        sa.Column("artifact_id", sa.String(), nullable=False),
        sa.Column("shadow_run_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "provenance",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("artifact_id"),
    )
    op.create_index(
        "ix_shadow_query_artifact_shadow_run_id",
        "shadow_query_artifact",
        ["shadow_run_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_shadow_query_artifact_shadow_run_id", table_name="shadow_query_artifact")
    op.drop_table("shadow_query_artifact")
    op.drop_index("ix_shadow_decision_record_event_id", table_name="shadow_decision_record")
    op.drop_index("ix_shadow_decision_record_shadow_run_id", table_name="shadow_decision_record")
    op.drop_table("shadow_decision_record")
    op.drop_index("ix_shadow_run_namespace_key", table_name="shadow_run")
    op.drop_index("ix_shadow_run_tenant_id", table_name="shadow_run")
    op.drop_index("ix_shadow_run_event_id", table_name="shadow_run")
    op.drop_table("shadow_run")
