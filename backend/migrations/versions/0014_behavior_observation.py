"""behavior_observation semantic projection tables (ISSUE-119 / #624)

Revision ID: 0014_behavior_observation
Revises: 0013_detection_scope
Create Date: 2026-08-01 12:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_behavior_observation"
down_revision: str | None = "0013_detection_scope"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "behavior_observation",
        sa.Column("observation_id", sa.String(), nullable=False),
        sa.Column("source_tenant_id", sa.String(), nullable=False),
        sa.Column("detection_scope_id", sa.String(), nullable=False),
        sa.Column("source_product", sa.String(), nullable=False),
        sa.Column("connector_id", sa.String(), nullable=False),
        sa.Column("source_kind", sa.String(), nullable=False),
        sa.Column("source_object_id", sa.String(), nullable=False),
        sa.Column("source_object_type", sa.String(), nullable=True),
        sa.Column("source_revision", sa.Integer(), nullable=False),
        sa.Column(
            "source_ref",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "entity_refs",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column("action", sa.String(), nullable=True),
        sa.Column("category", sa.String(), nullable=True),
        sa.Column(
            "normalized_attributes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("detection_score", sa.Float(), nullable=True),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("projection_schema_version", sa.String(), nullable=False),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("observation_hash", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column(
            "provenance",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("supersedes_observation_id", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_observation_id"],
            ["behavior_observation.observation_id"],
            name="fk_behavior_observation_supersedes",
        ),
        sa.PrimaryKeyConstraint("observation_id"),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_behavior_observation_idempotency_key",
        ),
    )
    op.create_index(
        "ix_behavior_observation_tenant_scope_observed",
        "behavior_observation",
        ["source_tenant_id", "detection_scope_id", "observed_at"],
    )
    op.create_index(
        "ix_behavior_observation_source_identity",
        "behavior_observation",
        [
            "source_tenant_id",
            "detection_scope_id",
            "source_kind",
            "source_object_id",
            "source_revision",
        ],
    )

    op.create_table(
        "behavior_observation_projection_failure",
        sa.Column("failure_id", sa.String(), nullable=False),
        sa.Column("source_record_id", sa.String(), nullable=False),
        sa.Column("source_tenant_id", sa.String(), nullable=False),
        sa.Column("attempt", sa.Integer(), server_default="1", nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("error_category", sa.String(), nullable=False),
        sa.Column(
            "detail",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("failure_id"),
    )
    op.create_index(
        "ix_behavior_obs_projection_failure_retry",
        "behavior_observation_projection_failure",
        ["status", "next_retry_at"],
    )
    op.create_index(
        "ix_behavior_obs_projection_failure_source",
        "behavior_observation_projection_failure",
        ["source_record_id", "status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_behavior_obs_projection_failure_source",
        table_name="behavior_observation_projection_failure",
    )
    op.drop_index(
        "ix_behavior_obs_projection_failure_retry",
        table_name="behavior_observation_projection_failure",
    )
    op.drop_table("behavior_observation_projection_failure")
    op.drop_index(
        "ix_behavior_observation_source_identity",
        table_name="behavior_observation",
    )
    op.drop_index(
        "ix_behavior_observation_tenant_scope_observed",
        table_name="behavior_observation",
    )
    op.drop_table("behavior_observation")
