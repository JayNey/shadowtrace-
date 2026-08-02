"""knowledge_release + knowledge_stix_object tables (ISSUE-128 / #634 Phase A)

Revision ID: 0018_knowledge_release
Revises: 0017_investigation_intent
Create Date: 2026-08-02 13:15:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018_knowledge_release"
down_revision: str | None = "0017_investigation_intent"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "knowledge_release",
        sa.Column("release_id", sa.String(), nullable=False),
        sa.Column("corpus_id", sa.String(), nullable=False),
        sa.Column("source_id", sa.String(), nullable=False),
        sa.Column("release_version", sa.String(), nullable=False),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("import_status", sa.String(), nullable=False),
        sa.Column("lifecycle_state", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("supersedes_release_id", sa.String(), nullable=True),
        sa.Column("object_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("relationship_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("vector_ready", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("embedding_release_id", sa.String(), nullable=True),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_release_id"],
            ["knowledge_release.release_id"],
            name="fk_knowledge_release_supersedes",
        ),
        sa.PrimaryKeyConstraint("release_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_knowledge_release_idempotency_key"),
    )
    op.create_index(
        "ix_knowledge_release_corpus_id",
        "knowledge_release",
        ["corpus_id"],
    )
    op.create_index(
        "ix_knowledge_release_corpus_lifecycle",
        "knowledge_release",
        ["corpus_id", "lifecycle_state"],
    )
    op.create_index(
        "uq_knowledge_release_one_active_per_corpus",
        "knowledge_release",
        ["corpus_id"],
        unique=True,
        postgresql_where=sa.text("lifecycle_state = 'active'"),
    )

    op.create_table(
        "knowledge_stix_object",
        sa.Column("object_row_id", sa.String(), nullable=False),
        sa.Column("release_id", sa.String(), nullable=False),
        sa.Column("stix_id", sa.String(), nullable=False),
        sa.Column("stix_type", sa.String(), nullable=False),
        sa.Column("external_id", sa.String(), nullable=True),
        sa.Column("object_hash", sa.String(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["release_id"],
            ["knowledge_release.release_id"],
            name="fk_knowledge_stix_object_release_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("object_row_id"),
        sa.UniqueConstraint(
            "release_id",
            "stix_id",
            name="uq_knowledge_stix_object_release_stix_id",
        ),
    )
    op.create_index(
        "ix_knowledge_stix_object_release_id",
        "knowledge_stix_object",
        ["release_id"],
    )
    op.create_index(
        "uq_knowledge_stix_object_release_external_id",
        "knowledge_stix_object",
        ["release_id", "external_id"],
        unique=True,
        postgresql_where=sa.text("external_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_knowledge_stix_object_release_external_id",
        table_name="knowledge_stix_object",
    )
    op.drop_index("ix_knowledge_stix_object_release_id", table_name="knowledge_stix_object")
    op.drop_table("knowledge_stix_object")
    op.drop_index(
        "uq_knowledge_release_one_active_per_corpus",
        table_name="knowledge_release",
    )
    op.drop_index("ix_knowledge_release_corpus_lifecycle", table_name="knowledge_release")
    op.drop_index("ix_knowledge_release_corpus_id", table_name="knowledge_release")
    op.drop_table("knowledge_release")
