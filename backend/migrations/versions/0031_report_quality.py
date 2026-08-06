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
    # Backfill escape-hatch rows so migration default ``complete`` does not
    # mislabel existing quick-close / template reports as formal complete.
    op.execute(
        sa.text(
            "UPDATE report SET report_quality = 'quick_close' "
            "WHERE generated_by = 'quick_close'"
        )
    )
    op.execute(
        sa.text(
            "UPDATE report SET report_quality = 'degraded_template' "
            "WHERE generated_by = 'template'"
        )
    )
    # Legacy llm rows that still embed PLACEHOLDER 「暂无」 / incomplete markers
    # must not remain labeled complete after the column is added.
    op.execute(
        sa.text(
            "UPDATE report SET report_quality = 'incomplete_placeholder' "
            "WHERE report_quality = 'complete' "
            "AND ("
            "  sections::text LIKE '%暂无处置动作%' "
            "  OR sections::text LIKE '%暂无验证结果%' "
            "  OR sections::text LIKE '%incomplete_placeholder%'"
            ")"
        )
    )


def downgrade() -> None:
    op.drop_column("report", "report_quality")
