"""Add attempt + unique business key on action_target_result (ISSUE-272).

Revision ID: 0037_action_target_result_attempt_uq
Revises: 0036_evidence_raw_data_sanitize
Create Date: 2026-08-08 00:00:00.000000+00:00

Stable idempotent upsert key: (job_id, canonical_target, attempt).
Chained after ISSUE-269 sanitize migration to keep a single Alembic head.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0037_action_target_result_attempt_uq"
down_revision = "0036_evidence_raw_data_sanitize"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "action_target_result",
        sa.Column("attempt", sa.Integer(), server_default="0", nullable=False),
    )
    op.create_unique_constraint(
        "uq_action_target_result_job_target_attempt",
        "action_target_result",
        ["job_id", "canonical_target", "attempt"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_action_target_result_job_target_attempt",
        "action_target_result",
        type_="unique",
    )
    op.drop_column("action_target_result", "attempt")
