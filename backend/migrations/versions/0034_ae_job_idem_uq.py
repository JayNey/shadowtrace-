"""Unique idempotency_key on action_execution_job (ISSUE-220).

Audit ID-REL-002: ``action_execution_job.idempotency_key`` was only an
ordinary Index, so lease reclaim (ISSUE-173) could re-insert a job with the
same key and re-invoke the Provider (duplicate side-effects).

Upgrade deduplicates legacy rows first — keeping the newest row per
idempotency_key (by created_at, then job_id as tiebreaker) — then replaces
the ordinary index with a unique constraint so the DB itself rejects a
second job for the same key.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0034_ae_job_idem_uq"
down_revision = "0032_investigation_intent_generate_report"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1) Repoint actions referencing duplicate jobs to the keeper row.
    op.execute(
        sa.text(
            """
            UPDATE action a
            SET execution_job_id = kept.job_id
            FROM action_execution_job doomed
            JOIN action_execution_job kept
              ON kept.idempotency_key = doomed.idempotency_key
             AND (kept.created_at, kept.job_id) > (doomed.created_at, doomed.job_id)
            WHERE a.execution_job_id = doomed.job_id
            """
        )
    )
    # 2) Drop child rows referencing duplicate jobs before deleting the jobs.
    op.execute(
        sa.text(
            """
            DELETE FROM action_target_result
            WHERE job_id IN (
                SELECT j2.job_id
                FROM action_execution_job j1
                JOIN action_execution_job j2
                  ON j2.idempotency_key = j1.idempotency_key
                 AND (j2.created_at, j2.job_id) < (j1.created_at, j1.job_id)
            )
            """
        )
    )
    # 3) Keep only the newest row per idempotency_key.
    op.execute(
        sa.text(
            """
            DELETE FROM action_execution_job j2
            USING action_execution_job j1
            WHERE j2.idempotency_key = j1.idempotency_key
              AND (j2.created_at, j2.job_id) < (j1.created_at, j1.job_id)
            """
        )
    )
    # 4) Replace the ordinary index with a unique one.
    op.drop_index("ix_action_execution_job_idempotency_key", table_name="action_execution_job")
    op.create_index(
        "uq_action_execution_job_idempotency_key",
        "action_execution_job",
        ["idempotency_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_action_execution_job_idempotency_key",
        table_name="action_execution_job",
    )
    op.create_index(
        "ix_action_execution_job_idempotency_key",
        "action_execution_job",
        ["idempotency_key"],
        unique=False,
    )
