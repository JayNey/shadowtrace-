"""Add report.report_quality column (ISSUE-212)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0031_report_quality"
down_revision = "0030_ae_job_lease_idx"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "report",
        sa.Column(
            "report_quality",
            sa.String(),
            nullable=False,
            server_default="complete",
        ),
    )


def downgrade() -> None:
    op.drop_column("report", "report_quality")
