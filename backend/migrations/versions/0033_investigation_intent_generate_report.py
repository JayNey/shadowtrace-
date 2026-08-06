"""Add investigation_intent.generate_report (ISSUE-204).

Revision id intentionally kept as ``0032_investigation_intent_generate_report``
for continuity with ISSUE-204 naming; file is ``0033_`` because ISSUE-214
inserted ``0032_alembic_version_widen`` ahead of this migration in the chain.

Upgrade is idempotent: half-applied ISSUE-204 environments may already have
``generate_report`` while ``alembic_version`` is still at ``0031_report_quality``.

See ``0032_alembic_version_widen.py`` for manual recovery when widen was skipped.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0032_investigation_intent_generate_report"
down_revision = "0032_alembic_version_widen"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return column_name in {col["name"] for col in inspector.get_columns(table_name)}


def upgrade() -> None:
    if not _has_column("investigation_intent", "generate_report"):
        op.add_column(
            "investigation_intent",
            sa.Column(
                "generate_report",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
        )


def downgrade() -> None:
    if _has_column("investigation_intent", "generate_report"):
        op.drop_column("investigation_intent", "generate_report")
