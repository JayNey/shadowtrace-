"""Sanitize historical evidence.raw_data rows (ISSUE-269 / ID-SEC-003).

Revision ID: 0036_evidence_raw_data_sanitize
Revises: 0035_llm_call_log_error_fields
Create Date: 2026-08-08 00:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import orjson
import sqlalchemy as sa
from alembic import op

revision: str = "0036_evidence_raw_data_sanitize"
down_revision: str | None = "0035_llm_call_log_error_fields"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _sanitize_legacy_raw(raw: Any) -> dict[str, Any]:
    from app.services.evidence_safe_projection import sanitize_evidence_raw_data_legacy

    if not isinstance(raw, dict):
        return {"_sanitization_failed": True}
    return sanitize_evidence_raw_data_legacy(raw)


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT evidence_id, raw_data FROM evidence")).mappings().all()
    for row in rows:
        evidence_id = row["evidence_id"]
        current = row["raw_data"]
        if isinstance(current, str):
            try:
                current = orjson.loads(current)
            except Exception:
                current = {}
        sanitized = _sanitize_legacy_raw(current)
        if sanitized == current:
            continue
        bind.execute(
            sa.text(
                "UPDATE evidence SET raw_data = CAST(:raw_data AS jsonb) "
                "WHERE evidence_id = :evidence_id"
            ),
            {
                "raw_data": orjson.dumps(sanitized).decode(),
                "evidence_id": evidence_id,
            },
        )


def downgrade() -> None:
    # Data minimization is one-way; downgrade is intentionally a no-op.
    pass
