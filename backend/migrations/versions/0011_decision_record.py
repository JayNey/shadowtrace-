"""decision_record durable audit table + react CoT redaction (ISSUE-131)

Revision ID: 0011_decision_record
Revises: 0010_memory_review
Create Date: 2026-07-31 00:00:00.000000+00:00
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_decision_record"
down_revision: str | None = "0010_memory_review"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_logger = logging.getLogger("alembic.runtime.migration")


def upgrade() -> None:
    op.create_table(
        "decision_record",
        sa.Column("record_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("stage", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column(
            "input_refs",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "candidates",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "selected",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "reason_codes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("decision_summary", sa.String(), server_default="", nullable=False),
        sa.Column("rule_version", sa.String(), nullable=True),
        sa.Column("model_version", sa.String(), nullable=True),
        sa.Column("prompt_policy_version", sa.String(), nullable=True),
        sa.Column("kb_version", sa.String(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column(
            "uncertainty_codes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "guardrail_flags",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("degraded", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("trace_ref", sa.String(), nullable=True),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("record_hash", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("parent_record_id", sa.String(), nullable=True),
        sa.Column("supersedes_record_id", sa.String(), nullable=True),
        sa.Column("retention_policy", sa.String(), server_default="standard", nullable=False),
        sa.Column(
            "unresolved_refs",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("owner", sa.String(), server_default="", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["parent_record_id"], ["decision_record.record_id"]),
        sa.ForeignKeyConstraint(["supersedes_record_id"], ["decision_record.record_id"]),
        sa.PrimaryKeyConstraint("record_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_decision_record_idempotency_key"),
    )
    op.create_index("ix_decision_record_event_id", "decision_record", ["event_id"], unique=False)
    op.create_index("ix_decision_record_trace_ref", "decision_record", ["trace_ref"], unique=False)

    conn = op.get_bind()
    result = conn.execute(
        sa.text(
            """
            UPDATE agent_trace
            SET output_data = (
                COALESCE(output_data, '{}'::jsonb)
                - 'thought'
                - 'reflection'
                - 'rationale'
                - 'summary'
                - 'gap'
            ) || jsonb_build_object(
                'decision_summary',
                COALESCE(
                    NULLIF(output_data->>'decision_summary', ''),
                    LEFT(COALESCE(output_data->>'summary', ''), 512)
                )
            )
            WHERE agent_name = 'react_engine'
              AND (
                output_data ? 'thought'
                OR output_data ? 'reflection'
                OR output_data ? 'rationale'
                OR output_data ? 'summary'
                OR output_data ? 'gap'
              )
            RETURNING trace_id
            """
        )
    )
    redacted_count = len(result.fetchall())
    _logger.info("ISSUE-131: redacted CoT fields from %d react_engine agent_trace rows", redacted_count)

    basis_result = conn.execute(
        sa.text(
            """
            UPDATE agent_trace
            SET output_data = output_data - '_decision_basis'
            WHERE agent_name = 'react_engine'
              AND output_data ? '_decision_basis'
            RETURNING trace_id
            """
        )
    )
    basis_count = len(basis_result.fetchall())
    _logger.info(
        "ISSUE-131: removed legacy _decision_basis from %d react_engine agent_trace rows",
        basis_count,
    )

    cot_cleanup = conn.execute(
        sa.text(
            """
            UPDATE agent_trace
            SET output_data = output_data
                - 'thought'
                - 'reflection'
                - 'rationale'
                - 'reasoning'
                - 'chain_of_thought'
                - 'chain-of-thought'
            WHERE output_data ?| ARRAY[
                'thought', 'reflection', 'rationale', 'reasoning',
                'chain_of_thought', 'chain-of-thought'
            ]
            RETURNING trace_id
            """
        )
    )
    cot_cleanup_count = len(cot_cleanup.fetchall())
    _logger.info(
        "ISSUE-131: removed CoT keys/sentinels from %d agent_trace rows",
        cot_cleanup_count,
    )


def downgrade() -> None:
    op.drop_index("ix_decision_record_trace_ref", table_name="decision_record")
    op.drop_index("ix_decision_record_event_id", table_name="decision_record")
    op.drop_table("decision_record")
