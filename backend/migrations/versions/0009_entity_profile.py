"""entity_profile table for MemoryAgent knowledge consolidation (ISSUE-080)

Revision ID: 0009_entity_profile
Revises: 0008_approval_record
Create Date: 2026-07-28 00:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_entity_profile"
down_revision: str | None = "0008_approval_record"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "entity_profile",
        sa.Column("profile_id", sa.String(), nullable=False),
        sa.Column("entity_type", sa.String(), nullable=False),
        sa.Column("entity_value", sa.String(), nullable=False),
        sa.Column("event_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_event_id", sa.String(), nullable=False),
        sa.Column(
            "risk_history",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "behavior_tags",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("profile_id", name=op.f("pk_entity_profile")),
        sa.UniqueConstraint(
            "entity_type",
            "entity_value",
            name=op.f("uq_entity_profile_type_value"),
        ),
    )
    op.create_index(
        op.f("ix_entity_profile_entity_type"),
        "entity_profile",
        ["entity_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_entity_profile_last_event_id"),
        "entity_profile",
        ["last_event_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_entity_profile_last_event_id"), table_name="entity_profile")
    op.drop_index(op.f("ix_entity_profile_entity_type"), table_name="entity_profile")
    op.drop_table("entity_profile")
