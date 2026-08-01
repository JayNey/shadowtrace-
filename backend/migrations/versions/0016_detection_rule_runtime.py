"""detection rule runtime tables (ISSUE-121 / #626)

Revision ID: 0016_detection_rule_runtime
Revises: 0015_feature_snapshot
Create Date: 2026-08-01 15:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016_detection_rule_runtime"
down_revision: str | None = "0015_feature_snapshot"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detection_rule_package",
        sa.Column("package_id", sa.String(), nullable=False),
        sa.Column("source_tenant_id", sa.String(), nullable=False),
        sa.Column("package_version", sa.Integer(), nullable=False),
        sa.Column("runtime_state", sa.String(), nullable=False),
        sa.Column(
            "rules",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "provenance",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("supersedes_package_id", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_package_id"],
            ["detection_rule_package.package_id"],
            name="fk_detection_rule_package_supersedes",
        ),
        sa.PrimaryKeyConstraint("package_id"),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_detection_rule_package_idempotency_key",
        ),
    )
    op.create_index(
        "ix_detection_rule_package_tenant_state",
        "detection_rule_package",
        ["source_tenant_id", "runtime_state"],
    )

    op.create_table(
        "candidate_detection",
        sa.Column("candidate_detection_id", sa.String(), nullable=False),
        sa.Column("source_tenant_id", sa.String(), nullable=False),
        sa.Column("detection_scope_id", sa.String(), nullable=False),
        sa.Column("package_id", sa.String(), nullable=False),
        sa.Column("package_version", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("operator", sa.String(), nullable=False),
        sa.Column(
            "group_key",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("cutoff_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_kind", sa.String(), nullable=False),
        sa.Column("matched_value", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("shadow_only", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "provenance",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("candidate_detection_id"),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_candidate_detection_idempotency_key",
        ),
    )
    op.create_index(
        "ix_candidate_detection_tenant_scope_cutoff",
        "candidate_detection",
        ["source_tenant_id", "detection_scope_id", "cutoff_at"],
    )
    op.create_index(
        "ix_candidate_detection_package_rule",
        "candidate_detection",
        ["source_tenant_id", "package_id", "rule_id"],
    )

    op.create_table(
        "detection_rule_runtime_error",
        sa.Column("error_id", sa.String(), nullable=False),
        sa.Column("source_tenant_id", sa.String(), nullable=False),
        sa.Column("package_id", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=True),
        sa.Column("error_category", sa.String(), nullable=False),
        sa.Column("error_message", sa.String(), nullable=False),
        sa.Column(
            "detail",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("error_id"),
    )
    op.create_index(
        "ix_detection_rule_runtime_error_tenant_package",
        "detection_rule_runtime_error",
        ["source_tenant_id", "package_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_detection_rule_runtime_error_tenant_package",
        table_name="detection_rule_runtime_error",
    )
    op.drop_table("detection_rule_runtime_error")
    op.drop_index("ix_candidate_detection_package_rule", table_name="candidate_detection")
    op.drop_index(
        "ix_candidate_detection_tenant_scope_cutoff",
        table_name="candidate_detection",
    )
    op.drop_table("candidate_detection")
    op.drop_index("ix_detection_rule_package_tenant_state", table_name="detection_rule_package")
    op.drop_table("detection_rule_package")
