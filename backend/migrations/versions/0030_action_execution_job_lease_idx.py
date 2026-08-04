"""Add lease_expires_at index on action_execution_job (ISSUE-173)."""

from __future__ import annotations

from alembic import op

revision = "0030_ae_job_lease_idx"
down_revision = "0029_policy_profile_uq"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_action_execution_job_lease_expires_at",
        "action_execution_job",
        ["lease_expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_action_execution_job_lease_expires_at",
        table_name="action_execution_job",
    )
