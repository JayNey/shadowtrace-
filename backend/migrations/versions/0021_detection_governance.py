"""detection governance decision table (ISSUE-125 / #630 Phase A)

Revision ID: 0021_detection_governance
Revises: 0020_playbook_release
Create Date: 2026-08-03 10:30:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0021_detection_governance"
down_revision: str | None = "0020_playbook_release"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detection_governance_decision",
        sa.Column("decision_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("binding_hash", sa.String(), nullable=False),
        sa.Column("decision_hash", sa.String(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reviewer_subject", sa.String(), nullable=False),
        sa.Column("supersedes_decision_id", sa.String(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "decision IN ('approve', 'reject', 'expire', 'revoke')",
            name="ck_detection_governance_decision_kind",
        ),
        sa.PrimaryKeyConstraint("decision_id"),
    )
    op.create_index(
        "ix_detection_governance_tenant_binding",
        "detection_governance_decision",
        ["tenant_id", "binding_hash"],
    )
    op.create_index(
        "ix_detection_governance_supersedes",
        "detection_governance_decision",
        ["supersedes_decision_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_detection_governance_supersedes", table_name="detection_governance_decision")
    op.drop_index(
        "ix_detection_governance_tenant_binding",
        table_name="detection_governance_decision",
    )
    op.drop_table("detection_governance_decision")
