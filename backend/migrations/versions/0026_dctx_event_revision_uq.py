"""detection context snapshot event revision uniqueness (ISSUE-127 / #633)

Revision ID: 0026_dctx_event_revision_uq
Revises: 0025_detection_context_snapshot
Create Date: 2026-08-03 16:30:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0026_dctx_event_revision_uq"
down_revision: str | None = "0025_detection_context_snapshot"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_detection_context_snapshot_event_revision",
        "detection_context_snapshot",
        ["tenant_id", "event_id", "revision"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_detection_context_snapshot_event_revision",
        "detection_context_snapshot",
        type_="unique",
    )
