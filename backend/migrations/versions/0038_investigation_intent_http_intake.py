"""Extend investigation_intent for durable HTTP intake (ISSUE-276 / #872).

Revision ID: 0038_investigation_intent_http_intake
Revises: 0037_action_target_result_attempt_uq
Create Date: 2026-08-09 00:00:00.000000+00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0038_investigation_intent_http_intake"
down_revision = "0037_action_target_result_attempt_uq"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigation_intent",
        sa.Column("request_idempotency_key", sa.String(length=200), nullable=True),
    )
    op.add_column(
        "investigation_intent",
        sa.Column("request_payload_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "investigation_intent",
        sa.Column("requested_by", sa.String(), nullable=True),
    )
    op.add_column(
        "investigation_intent",
        sa.Column(
            "orchestration_mode",
            sa.String(),
            server_default="graph",
            nullable=False,
        ),
    )
    op.create_index(
        "uq_investigation_intent_request_key",
        "investigation_intent",
        ["requested_by", "request_idempotency_key"],
        unique=True,
        postgresql_where=sa.text("request_idempotency_key IS NOT NULL"),
    )
    op.create_index(
        "uq_investigation_intent_broker_task_id",
        "investigation_intent",
        ["broker_task_id"],
        unique=True,
        postgresql_where=sa.text("broker_task_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_investigation_intent_broker_task_id",
        table_name="investigation_intent",
    )
    op.drop_index(
        "uq_investigation_intent_request_key",
        table_name="investigation_intent",
    )
    op.drop_column("investigation_intent", "orchestration_mode")
    op.drop_column("investigation_intent", "requested_by")
    op.drop_column("investigation_intent", "request_payload_sha256")
    op.drop_column("investigation_intent", "request_idempotency_key")
