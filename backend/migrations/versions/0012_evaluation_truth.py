"""evaluation_case_truth canonical truth table (ISSUE-113 Phase A)

Revision ID: 0012_evaluation_truth
Revises: 0011_decision_record
Create Date: 2026-07-31 08:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012_evaluation_truth"
down_revision: str | None = "0011_decision_record"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evaluation_case_truth",
        sa.Column("truth_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("source_tenant_id", sa.String(), nullable=True),
        sa.Column("source_product", sa.String(), nullable=True),
        sa.Column("connector_id", sa.String(), nullable=True),
        sa.Column("dataset_id", sa.String(), nullable=False),
        sa.Column("dataset_version", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("case_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column(
            "observation_refs",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "slice_expectation",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "label_provenance",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "operational_mapping",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("supersedes_truth_id", sa.String(), nullable=True),
        sa.Column("correction_reason", sa.String(), nullable=True),
        sa.Column(
            "retention_policy",
            sa.String(),
            server_default="evaluation_standard",
            nullable=False,
        ),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("truth_hash", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_truth_id"],
            ["evaluation_case_truth.truth_id"],
            name="fk_evaluation_case_truth_supersedes",
        ),
        sa.PrimaryKeyConstraint("truth_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_evaluation_case_truth_idempotency_key"),
    )
    op.create_index(
        "ix_evaluation_case_truth_tenant_dataset",
        "evaluation_case_truth",
        ["tenant_id", "dataset_id"],
    )
    op.create_index(
        "ix_evaluation_case_truth_tenant_dataset_case_rev",
        "evaluation_case_truth",
        ["tenant_id", "dataset_id", "case_id", "revision"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_evaluation_case_truth_tenant_dataset_case_rev",
        table_name="evaluation_case_truth",
    )
    op.drop_index(
        "ix_evaluation_case_truth_tenant_dataset",
        table_name="evaluation_case_truth",
    )
    op.drop_table("evaluation_case_truth")
