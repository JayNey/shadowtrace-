"""Add durable graph_resume_intent ledger (ISSUE-277 / #873).

Revision ID: 0039_graph_resume_intent
Revises: 0038_investigation_intent_http_intake
Create Date: 2026-08-09 00:00:00.000000+00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0039_graph_resume_intent"
down_revision = "0038_investigation_intent_http_intake"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "graph_resume_intent",
        sa.Column("intent_id", sa.String(), primary_key=True),
        sa.Column("event_id", sa.String(), sa.ForeignKey("security_event.event_id", ondelete="CASCADE"), nullable=False),
        sa.Column("intent_kind", sa.String(), nullable=False),
        sa.Column("intent_version", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hold_generation", sa.Integer(), nullable=False),
        sa.Column("checkpoint_id", sa.String(), nullable=True),
        sa.Column("operation_id", sa.String(length=128), nullable=True),
        sa.Column("resolution_source", sa.String(), nullable=False),
        sa.Column("subject_kind", sa.String(), nullable=False),
        sa.Column("subject_id", sa.String(), nullable=False),
        sa.Column("resolution", sa.String(), nullable=True),
        sa.Column("principal", sa.String(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("evidence_ref", sa.String(), nullable=True),
        sa.Column("payload_sha256", sa.String(length=64), nullable=True),
        sa.Column("claim_owner", sa.String(), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("skip_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_graph_resume_intent_event_id", "graph_resume_intent", ["event_id"])
    op.create_index("ix_graph_resume_intent_status", "graph_resume_intent", ["status"])
    op.create_index(
        "ix_graph_resume_intent_status_updated",
        "graph_resume_intent",
        ["status", "updated_at"],
    )
    op.create_index(
        "ix_graph_resume_intent_claim_expires",
        "graph_resume_intent",
        ["claim_expires_at"],
    )
    op.create_index(
        "uq_graph_resume_intent_operation_id",
        "graph_resume_intent",
        ["operation_id"],
        unique=True,
        postgresql_where=sa.text("operation_id IS NOT NULL"),
    )
    op.create_index(
        "uq_graph_resume_intent_active_hold",
        "graph_resume_intent",
        ["event_id", "hold_generation"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('pending', 'claimed', 'started', 'retry')"
        ),
    )


def downgrade() -> None:
    op.drop_index("uq_graph_resume_intent_active_hold", table_name="graph_resume_intent")
    op.drop_index("uq_graph_resume_intent_operation_id", table_name="graph_resume_intent")
    op.drop_index("ix_graph_resume_intent_claim_expires", table_name="graph_resume_intent")
    op.drop_index("ix_graph_resume_intent_status_updated", table_name="graph_resume_intent")
    op.drop_index("ix_graph_resume_intent_status", table_name="graph_resume_intent")
    op.drop_index("ix_graph_resume_intent_event_id", table_name="graph_resume_intent")
    op.drop_table("graph_resume_intent")
