"""detection_scope_revision canonical scope table (ISSUE-120 Phase 0)

Revision ID: 0013_detection_scope
Revises: 0012_evaluation_truth
Create Date: 2026-08-01 03:30:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013_detection_scope"
down_revision: str | None = "0012_evaluation_truth"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detection_scope_revision",
        sa.Column("scope_revision_id", sa.String(), nullable=False),
        sa.Column("detection_scope_id", sa.String(), nullable=False),
        sa.Column("source_tenant_id", sa.String(), nullable=False),
        sa.Column("source_product", sa.String(), nullable=False),
        sa.Column("integration_instance_id", sa.String(), nullable=False),
        sa.Column("environment", sa.String(), nullable=True),
        sa.Column("region", sa.String(), nullable=True),
        sa.Column(
            "connector_set",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("connector_set_version", sa.Integer(), nullable=False),
        sa.Column("lifecycle_state", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("supersedes_scope_revision_id", sa.String(), nullable=True),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("identity_hash", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_scope_revision_id"],
            ["detection_scope_revision.scope_revision_id"],
            name="fk_detection_scope_revision_supersedes",
        ),
        sa.PrimaryKeyConstraint("scope_revision_id"),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_detection_scope_revision_idempotency_key",
        ),
    )
    op.create_index(
        "ix_detection_scope_revision_tenant_product_instance",
        "detection_scope_revision",
        ["source_tenant_id", "source_product", "integration_instance_id"],
    )
    op.create_index(
        "ix_detection_scope_revision_scope_id_rev",
        "detection_scope_revision",
        ["detection_scope_id", "revision"],
    )
    op.create_index(
        "ix_detection_scope_revision_scope_lifecycle",
        "detection_scope_revision",
        ["detection_scope_id", "lifecycle_state"],
    )
    op.create_index(
        "uq_detection_scope_revision_one_active_per_scope",
        "detection_scope_revision",
        ["detection_scope_id"],
        unique=True,
        postgresql_where=sa.text("lifecycle_state = 'active'"),
    )
    op.create_index(
        "uq_detection_scope_revision_one_active_per_instance",
        "detection_scope_revision",
        ["source_tenant_id", "source_product", "integration_instance_id"],
        unique=True,
        postgresql_where=sa.text("lifecycle_state = 'active'"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_detection_scope_revision_one_active_per_instance",
        table_name="detection_scope_revision",
    )
    op.drop_index(
        "uq_detection_scope_revision_one_active_per_scope",
        table_name="detection_scope_revision",
    )
    op.drop_index(
        "ix_detection_scope_revision_scope_lifecycle",
        table_name="detection_scope_revision",
    )
    op.drop_index(
        "ix_detection_scope_revision_scope_id_rev",
        table_name="detection_scope_revision",
    )
    op.drop_index(
        "ix_detection_scope_revision_tenant_product_instance",
        table_name="detection_scope_revision",
    )
    op.drop_table("detection_scope_revision")
