"""feature_snapshot and detection_feature_baseline tables (ISSUE-120 Phase A/B)

Revision ID: 0015_feature_snapshot
Revises: 0014_behavior_observation
Create Date: 2026-08-01 14:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015_feature_snapshot"
down_revision: str | None = "0014_behavior_observation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "feature_snapshot",
        sa.Column("snapshot_id", sa.String(), nullable=False),
        sa.Column("source_tenant_id", sa.String(), nullable=False),
        sa.Column("detection_scope_id", sa.String(), nullable=False),
        sa.Column("entity_type", sa.String(), nullable=False),
        sa.Column("entity_id", sa.String(), nullable=False),
        sa.Column("feature_contract_version", sa.String(), nullable=False),
        sa.Column("window_kind", sa.String(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cutoff_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("allowed_lateness_seconds", sa.Integer(), nullable=False),
        sa.Column("source_watermark", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column(
            "features",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "provenance",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("supersedes_snapshot_id", sa.String(), nullable=True),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("cache_key", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_snapshot_id"],
            ["feature_snapshot.snapshot_id"],
            name="fk_feature_snapshot_supersedes",
        ),
        sa.PrimaryKeyConstraint("snapshot_id"),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_feature_snapshot_idempotency_key",
        ),
    )
    op.create_index(
        "ix_feature_snapshot_tenant_scope_entity_cutoff",
        "feature_snapshot",
        [
            "source_tenant_id",
            "detection_scope_id",
            "entity_type",
            "entity_id",
            "window_kind",
            "cutoff_at",
        ],
    )
    op.create_index(
        "ix_feature_snapshot_cache_key",
        "feature_snapshot",
        ["source_tenant_id", "cache_key"],
    )

    op.create_table(
        "detection_feature_baseline",
        sa.Column("baseline_id", sa.String(), nullable=False),
        sa.Column("source_tenant_id", sa.String(), nullable=False),
        sa.Column("detection_scope_id", sa.String(), nullable=False),
        sa.Column("entity_type", sa.String(), nullable=False),
        sa.Column("entity_id", sa.String(), nullable=False),
        sa.Column("peer_group_id", sa.String(), nullable=True),
        sa.Column("feature_contract_version", sa.String(), nullable=False),
        sa.Column("window_kind", sa.String(), nullable=False),
        sa.Column("cutoff_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column(
            "stats",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "seasonality_profile",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "snapshot_revision_refs",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("supersedes_baseline_id", sa.String(), nullable=True),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("cache_key", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_baseline_id"],
            ["detection_feature_baseline.baseline_id"],
            name="fk_detection_feature_baseline_supersedes",
        ),
        sa.PrimaryKeyConstraint("baseline_id"),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_detection_feature_baseline_idempotency_key",
        ),
    )
    op.create_index(
        "ix_detection_baseline_tenant_scope_entity_cutoff",
        "detection_feature_baseline",
        [
            "source_tenant_id",
            "detection_scope_id",
            "entity_type",
            "entity_id",
            "window_kind",
            "cutoff_at",
        ],
    )
    op.create_index(
        "ix_detection_baseline_peer_group",
        "detection_feature_baseline",
        ["source_tenant_id", "peer_group_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_detection_baseline_peer_group", table_name="detection_feature_baseline")
    op.drop_index(
        "ix_detection_baseline_tenant_scope_entity_cutoff",
        table_name="detection_feature_baseline",
    )
    op.drop_table("detection_feature_baseline")
    op.drop_index("ix_feature_snapshot_cache_key", table_name="feature_snapshot")
    op.drop_index(
        "ix_feature_snapshot_tenant_scope_entity_cutoff",
        table_name="feature_snapshot",
    )
    op.drop_table("feature_snapshot")
