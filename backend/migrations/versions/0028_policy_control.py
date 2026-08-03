"""policy/control corpus tables (ISSUE-129 / #635 Phase A)

Revision ID: 0028_policy_control
Revises: 0027_agent_task_ledger
Create Date: 2026-08-03 12:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0028_policy_control"
down_revision: str | None = "0027_agent_task_ledger"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organization_policy_profile",
        sa.Column("profile_row_id", sa.String(), nullable=False),
        sa.Column("profile_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("owner_principal", sa.String(), nullable=False),
        sa.Column("framework_allowlist", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("jurisdiction_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("industry_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.String(), nullable=True),
        sa.Column("audit_note", sa.Text(), nullable=True),
        sa.Column("schema_version", sa.String(), nullable=False),
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
        sa.PrimaryKeyConstraint("profile_row_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "profile_id",
            "revision",
            name="uq_organization_policy_profile_tenant_profile_revision",
        ),
    )
    op.create_index(
        "ix_organization_policy_profile_tenant_revision",
        "organization_policy_profile",
        ["tenant_id", "revision"],
    )
    op.create_index(
        "ix_organization_policy_profile_profile_id",
        "organization_policy_profile",
        ["profile_id"],
    )
    op.create_index(
        "ix_organization_policy_profile_tenant_id",
        "organization_policy_profile",
        ["tenant_id"],
    )

    op.create_table(
        "policy_release_object",
        sa.Column("object_row_id", sa.String(), nullable=False),
        sa.Column("release_id", sa.String(), nullable=False),
        sa.Column("control_id", sa.String(), nullable=False),
        sa.Column("framework_id", sa.String(), nullable=False),
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
            name="fk_policy_release_object_release_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("object_row_id"),
        sa.UniqueConstraint(
            "release_id",
            "control_id",
            name="uq_policy_release_object_release_control_id",
        ),
    )
    op.create_index(
        "ix_policy_release_object_release_id",
        "policy_release_object",
        ["release_id"],
    )

    op.create_table(
        "attack_control_mapping",
        sa.Column("mapping_row_id", sa.String(), nullable=False),
        sa.Column("release_id", sa.String(), nullable=False),
        sa.Column("mapping_id", sa.String(), nullable=False),
        sa.Column("technique_id", sa.String(), nullable=False),
        sa.Column("control_id", sa.String(), nullable=False),
        sa.Column("framework_id", sa.String(), nullable=False),
        sa.Column("approval_state", sa.String(), nullable=False),
        sa.Column("mapping_version", sa.String(), nullable=False),
        sa.Column("provenance", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["release_id"],
            ["knowledge_release.release_id"],
            name="fk_attack_control_mapping_release_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("mapping_row_id"),
        sa.UniqueConstraint(
            "release_id",
            "mapping_id",
            name="uq_attack_control_mapping_release_mapping_id",
        ),
    )
    op.create_index(
        "ix_attack_control_mapping_release_id",
        "attack_control_mapping",
        ["release_id"],
    )
    op.create_index(
        "ix_attack_control_mapping_release_technique",
        "attack_control_mapping",
        ["release_id", "technique_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_attack_control_mapping_release_technique", table_name="attack_control_mapping")
    op.drop_index("ix_attack_control_mapping_release_id", table_name="attack_control_mapping")
    op.drop_table("attack_control_mapping")
    op.drop_index("ix_policy_release_object_release_id", table_name="policy_release_object")
    op.drop_table("policy_release_object")
    op.drop_index("ix_organization_policy_profile_tenant_id", table_name="organization_policy_profile")
    op.drop_index("ix_organization_policy_profile_profile_id", table_name="organization_policy_profile")
    op.drop_index(
        "ix_organization_policy_profile_tenant_revision",
        table_name="organization_policy_profile",
    )
    op.drop_table("organization_policy_profile")
