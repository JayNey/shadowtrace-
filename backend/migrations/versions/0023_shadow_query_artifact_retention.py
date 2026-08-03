"""add retention_expires_at to shadow_query_artifact (ISSUE-135 / #641)

Revision ID: 0023_shadow_artifact_retention
Revises: 0022_shadow_run
Create Date: 2026-08-03 14:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023_shadow_artifact_retention"
down_revision: str | None = "0022_shadow_run"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "shadow_query_artifact",
        sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        sa.text(
            "UPDATE shadow_query_artifact SET retention_expires_at = created_at + interval '30 days' "
            "WHERE retention_expires_at IS NULL"
        )
    )
    op.alter_column("shadow_query_artifact", "retention_expires_at", nullable=False)


def downgrade() -> None:
    op.drop_column("shadow_query_artifact", "retention_expires_at")
