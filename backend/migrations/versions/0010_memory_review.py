"""memory_review queue for governed long-term memory

Revision ID: 0010_memory_review
Revises: 0009_entity_profile
Create Date: 2026-07-29 00:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_memory_review"
down_revision: str | None = "0009_entity_profile"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "memory_review",
        sa.Column("review_id", sa.String(), nullable=False),
        sa.Column("kb_name", sa.String(), nullable=False),
        sa.Column("candidate_type", sa.String(), nullable=False),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("status", sa.String(), server_default="pending", nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("operator", sa.String(), nullable=True),
        sa.CheckConstraint(
            "candidate_type IN ('fp_rule', 'history_case', 'profile')",
            name=op.f("ck_memory_review_candidate_type"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'promoted', 'demoted')",
            name=op.f("ck_memory_review_status"),
        ),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name=op.f("ck_memory_review_confidence"),
        ),
        sa.PrimaryKeyConstraint("review_id", name=op.f("pk_memory_review")),
    )
    op.create_index(
        "ix_memory_review_kb_status",
        "memory_review",
        ["kb_name", "status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_memory_review_kb_status", table_name="memory_review")
    op.drop_table("memory_review")
