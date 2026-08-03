"""detection context snapshot table (ISSUE-127 / #633)

Revision ID: 0025_detection_context_snapshot
Revises: 0024_detection_promotion
Create Date: 2026-08-03 15:30:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0025_detection_context_snapshot"
down_revision: str | None = "0024_detection_promotion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detection_context_snapshot",
        sa.Column("snapshot_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("event_revision", sa.Integer(), nullable=False),
        sa.Column("promotion_id", sa.String(), nullable=False),
        sa.Column("promotion_link_revision", sa.Integer(), nullable=False),
        sa.Column("promotion_key", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("supersedes_snapshot_id", sa.String(), nullable=True),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("body", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("snapshot_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_detection_context_snapshot_idempotency"),
    )
    op.create_index(
        "ix_detection_context_snapshot_event_revision",
        "detection_context_snapshot",
        ["tenant_id", "event_id", "revision"],
    )
    op.create_index(
        "ix_detection_context_snapshot_promotion",
        "detection_context_snapshot",
        ["promotion_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_detection_context_snapshot_promotion",
        table_name="detection_context_snapshot",
    )
    op.drop_index(
        "ix_detection_context_snapshot_event_revision",
        table_name="detection_context_snapshot",
    )
    op.drop_table("detection_context_snapshot")
