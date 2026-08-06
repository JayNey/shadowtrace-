"""Add investigation_intent.generate_report (ISSUE-204)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0032_investigation_intent_generate_report"
down_revision = "0031_report_quality"
branch_labels = None
depends_on = None


def upgrade() -> None:
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
    op.drop_column("investigation_intent", "generate_report")
