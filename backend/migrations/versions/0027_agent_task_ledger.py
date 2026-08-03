"""agent_task / agent_task_attempt / agent_artifact tables (ISSUE-133 / #639 Phase A)

Revision ID: 0027_agent_task_ledger
Revises: 0026_dctx_event_revision_uq
Create Date: 2026-08-03 11:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0027_agent_task_ledger"
down_revision: str | None = "0026_dctx_event_revision_uq"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_task",
        sa.Column("task_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("task_type", sa.String(), nullable=False),
        sa.Column("goal", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("attempt", sa.Integer(), server_default="0", nullable=False),
        sa.Column("claim_owner", sa.String(), nullable=True),
        sa.Column("fencing_token_hash", sa.String(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("side_effect_status", sa.String(), server_default="none", nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('queued','claimed','running','completed','failed',"
            "'cancelled','expired','dead','manual')",
            name="ck_agent_task_status",
        ),
        sa.CheckConstraint("revision >= 1", name="ck_agent_task_revision"),
        sa.CheckConstraint("attempt >= 0", name="ck_agent_task_attempt"),
        sa.PrimaryKeyConstraint("task_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_agent_task_tenant_idempotency_key",
        ),
    )
    op.create_index("ix_agent_task_event_id", "agent_task", ["event_id"])
    op.create_index("ix_agent_task_tenant_id", "agent_task", ["tenant_id"])
    op.create_index("ix_agent_task_status_updated", "agent_task", ["status", "updated_at"])
    op.create_index("ix_agent_task_lease_expires", "agent_task", ["lease_expires_at"])

    op.create_table(
        "agent_task_attempt",
        sa.Column("attempt_id", sa.String(), nullable=False),
        sa.Column("task_id", sa.String(), nullable=False),
        sa.Column("attempt_seq", sa.Integer(), nullable=False),
        sa.Column("worker_principal", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("fencing_token_hash", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["agent_task.task_id"],
            name="fk_agent_task_attempt_task_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("attempt_id"),
        sa.UniqueConstraint("task_id", "attempt_seq", name="uq_agent_task_attempt_seq"),
    )
    op.create_index("ix_agent_task_attempt_task_id", "agent_task_attempt", ["task_id"])

    op.create_table(
        "agent_artifact",
        sa.Column("artifact_id", sa.String(), nullable=False),
        sa.Column("task_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("logical_artifact_key", sa.String(), nullable=False),
        sa.Column("producer_revision", sa.Integer(), nullable=False),
        sa.Column("producer_attempt", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source_refs", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
        sa.Column(
            "decision_record_refs",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["agent_task.task_id"],
            name="fk_agent_artifact_task_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("artifact_id"),
        sa.UniqueConstraint(
            "task_id",
            "logical_artifact_key",
            "producer_revision",
            name="uq_agent_artifact_logical_revision",
        ),
    )
    op.create_index("ix_agent_artifact_task_id", "agent_artifact", ["task_id"])
    op.create_index("ix_agent_artifact_event_id", "agent_artifact", ["event_id"])
    op.create_index("ix_agent_artifact_tenant_id", "agent_artifact", ["tenant_id"])


def downgrade() -> None:
    op.drop_table("agent_artifact")
    op.drop_table("agent_task_attempt")
    op.drop_table("agent_task")
