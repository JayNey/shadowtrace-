"""detection promotion saga + derived connector tables (ISSUE-124 / #629)

Revision ID: 0024_detection_promotion
Revises: 0023_shadow_artifact_retention
Create Date: 2026-08-03 18:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0024_detection_promotion"
down_revision: str | None = "0023_shadow_artifact_retention"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "derived_detection_connector",
        sa.Column("connector_id", sa.String(), nullable=False),
        sa.Column("source_tenant_id", sa.String(), nullable=False),
        sa.Column("detection_scope_id", sa.String(), nullable=False),
        sa.Column("scope_revision_id", sa.String(), nullable=True),
        sa.Column("adapter_kind", sa.String(), nullable=False),
        sa.Column("adapter_version", sa.String(), nullable=False),
        sa.Column(
            "disposition_policy",
            sa.String(),
            server_default="not_required",
            nullable=False,
        ),
        sa.Column(
            "connector_metadata",
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
        sa.PrimaryKeyConstraint("connector_id"),
        sa.UniqueConstraint(
            "source_tenant_id",
            "detection_scope_id",
            "adapter_kind",
            "adapter_version",
            name="uq_derived_detection_connector_scope",
        ),
    )
    op.create_index(
        "ix_derived_detection_connector_scope",
        "derived_detection_connector",
        ["detection_scope_id"],
    )

    op.create_table(
        "detection_promotion",
        sa.Column("promotion_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("promotion_key", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("decision_id", sa.String(), nullable=False),
        sa.Column("candidate_detection_id", sa.String(), nullable=False),
        sa.Column("candidate_content_hash", sa.String(), nullable=False),
        sa.Column("package_id", sa.String(), nullable=False),
        sa.Column("package_version", sa.Integer(), nullable=False),
        sa.Column("package_content_hash", sa.String(), nullable=False),
        sa.Column("detection_scope_id", sa.String(), nullable=False),
        sa.Column("scope_revision_id", sa.String(), nullable=True),
        sa.Column("derived_connector_id", sa.String(), nullable=True),
        sa.Column("source_record_id", sa.String(), nullable=True),
        sa.Column("event_id", sa.String(), nullable=True),
        sa.Column("link_revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("ingest_result", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "reason_codes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column("reason_message", sa.String(), server_default="", nullable=False),
        sa.Column(
            "payload",
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
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'source_persisted', 'event_linked', 'completed', "
            "'retry', 'dead', 'manual')",
            name="ck_detection_promotion_status",
        ),
        sa.PrimaryKeyConstraint("promotion_id"),
        sa.UniqueConstraint("promotion_key", name="uq_detection_promotion_key"),
    )
    op.create_index(
        "ix_detection_promotion_tenant_status",
        "detection_promotion",
        ["tenant_id", "status"],
    )
    op.create_index(
        "ix_detection_promotion_candidate",
        "detection_promotion",
        ["candidate_detection_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_detection_promotion_candidate", table_name="detection_promotion")
    op.drop_index("ix_detection_promotion_tenant_status", table_name="detection_promotion")
    op.drop_table("detection_promotion")
    op.drop_index("ix_derived_detection_connector_scope", table_name="derived_detection_connector")
    op.drop_table("derived_detection_connector")
