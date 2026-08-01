"""investigation_intent table (ISSUE-108 / #612)

Revision ID: 0017_investigation_intent
Revises: 0016_detection_rule_runtime
Create Date: 2026-08-01 18:35:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_investigation_intent"
down_revision: str | None = "0016_detection_rule_runtime"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "investigation_intent",
        sa.Column("intent_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("intent_kind", sa.String(), nullable=False),
        sa.Column("intent_version", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("claim_owner", sa.String(), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("broker_task_id", sa.String(), nullable=True),
        sa.Column("skip_reason", sa.String(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "include_response_execution",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
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
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["security_event.event_id"],
            name="fk_investigation_intent_event_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("intent_id"),
        sa.UniqueConstraint(
            "event_id",
            "intent_kind",
            "intent_version",
            name="uq_investigation_intent_event_kind_version",
        ),
    )
    op.create_index(
        "ix_investigation_intent_status_updated",
        "investigation_intent",
        ["status", "updated_at"],
    )
    op.create_index(
        "ix_investigation_intent_claim_expires",
        "investigation_intent",
        ["claim_expires_at"],
    )
    op.create_index("ix_investigation_intent_event_id", "investigation_intent", ["event_id"])
    op.create_index("ix_investigation_intent_status", "investigation_intent", ["status"])


def downgrade() -> None:
    op.drop_index("ix_investigation_intent_status", table_name="investigation_intent")
    op.drop_index("ix_investigation_intent_event_id", table_name="investigation_intent")
    op.drop_index("ix_investigation_intent_claim_expires", table_name="investigation_intent")
    op.drop_index("ix_investigation_intent_status_updated", table_name="investigation_intent")
    op.drop_table("investigation_intent")
