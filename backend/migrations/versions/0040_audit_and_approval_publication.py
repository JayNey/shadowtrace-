"""Add durable WorkingMemory audit and approval publication markers."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0040_audit_and_approval_publication"
down_revision = "0039_graph_resume_intent"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "memory_access_audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column(
            "timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("agent_name", sa.String(), nullable=False),
        sa.Column("op", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_memory_access_audit_log_event_id", "memory_access_audit_log", ["event_id"])
    op.create_index(
        "ix_memory_access_audit_event_created",
        "memory_access_audit_log",
        ["event_id", "timestamp"],
    )
    op.create_table(
        "approval_publication",
        sa.Column("publication_id", sa.String(), primary_key=True),
        sa.Column(
            "event_id",
            sa.String(),
            sa.ForeignKey("security_event.event_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "action_id",
            sa.String(),
            sa.ForeignKey("action.action_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("approval_cycle", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("claim_token", sa.String(), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "event_id", "action_id", "approval_cycle",
            name="uq_approval_publication_event_action_cycle",
        ),
    )
    op.create_index(
        "ix_approval_publication_claim_expires", "approval_publication", ["claim_expires_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_approval_publication_claim_expires", table_name="approval_publication")
    op.drop_table("approval_publication")
    op.drop_index("ix_memory_access_audit_event_created", table_name="memory_access_audit_log")
    op.drop_index("ix_memory_access_audit_log_event_id", table_name="memory_access_audit_log")
    op.drop_table("memory_access_audit_log")
