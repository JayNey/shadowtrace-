"""Widen alembic_version.version_num for long revision ids (ISSUE-214).

Alembic's default ``alembic_version.version_num`` is VARCHAR(32). Revision
``0032_investigation_intent_generate_report`` (41 chars) exceeds that limit and
causes ``StringDataRightTruncationError`` on stamp.

This migration must run **before** any revision id longer than 32 characters
is written to ``alembic_version``.

**Half-applied environments (ISSUE-204 / pre-214):** If
``investigation_intent.generate_report`` already exists but ``alembic_version``
is still ``0031_report_quality`` (upgrade succeeded, stamp failed):

1. ``ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(64);``
2. ``alembic stamp 0032_investigation_intent_generate_report`` (if column present)
   **or** ``alembic upgrade head`` (if column missing).

Do not drop ``generate_report`` to recover.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0032_alembic_version_widen"
down_revision = "0031_report_quality"
branch_labels = None
depends_on = None

# Keep in sync with scripts/check_migration_revisions.py
ALEMBIC_VERSION_NUM_WIDTH = 64


def upgrade() -> None:
    op.execute(
        sa.text(
            f"ALTER TABLE alembic_version "
            f"ALTER COLUMN version_num TYPE VARCHAR({ALEMBIC_VERSION_NUM_WIDTH})"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    max_len = bind.execute(
        sa.text("SELECT COALESCE(MAX(LENGTH(version_num)), 0) FROM alembic_version")
    ).scalar_one()
    if int(max_len) > 32:
        raise NotImplementedError(
            "Cannot shrink alembic_version.version_num to VARCHAR(32): "
            f"stamped revision length is {max_len}. "
            "Downgrade past 0032_alembic_version_widen only when revision ids fit 32 chars."
        )
    op.execute(
        sa.text("ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(32)")
    )
