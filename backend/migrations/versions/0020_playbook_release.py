"""playbook_release_object + action playbook binding columns (ISSUE-139 / #645 Phase A)

Revision ID: 0020_playbook_release
Revises: 0019_tool_call_grant
Create Date: 2026-08-03 09:30:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020_playbook_release"
down_revision: str | None = "0019_tool_call_grant"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "playbook_release_object",
        sa.Column("object_row_id", sa.String(), nullable=False),
        sa.Column("release_id", sa.String(), nullable=False),
        sa.Column("playbook_id", sa.String(), nullable=False),
        sa.Column("object_hash", sa.String(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["release_id"],
            ["knowledge_release.release_id"],
            name="fk_playbook_release_object_release_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("object_row_id"),
        sa.UniqueConstraint(
            "release_id",
            "playbook_id",
            name="uq_playbook_release_object_release_playbook_id",
        ),
    )
    op.create_index(
        "ix_playbook_release_object_release_id",
        "playbook_release_object",
        ["release_id"],
    )

    op.add_column("action", sa.Column("playbook_ref", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column(
        "action",
        sa.Column("action_template_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("action", "action_template_snapshot")
    op.drop_column("action", "playbook_ref")
    op.drop_index("ix_playbook_release_object_release_id", table_name="playbook_release_object")
    op.drop_table("playbook_release_object")
