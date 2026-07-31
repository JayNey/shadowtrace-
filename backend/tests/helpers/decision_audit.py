"""Test helpers for minimum DecisionRecord audit seeds (ISSUE-131)."""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.decision_record import DecisionRecord, DecisionStage
from app.services.decision_record_service import (
    DECISION_RECORD_SCHEMA_VERSION,
    PROMPT_POLICY_VERSION,
    DecisionRecordService,
)


async def seed_minimum_disposition_audit(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    actor: str = "test_fixture",
) -> str:
    """Insert the minimum durable audit record required for auto-disposition paths."""
    service = DecisionRecordService(session_factory)
    record_id = f"dec-{uuid.uuid4().hex[:12]}"
    idempotency_key = f"{event_id}:verify:{actor}:minimum_audit:r1"
    record = DecisionRecord(
        record_id=record_id,
        event_id=event_id,
        stage=DecisionStage.VERIFY,
        actor=actor,
        input_refs=[{"ref_type": "event_id", "ref_id": event_id}],
        selected={"selected_action": "verify:minimum_audit"},
        reason_codes=["minimum_audit"],
        decision_summary="minimum disposition audit for test activation",
        prompt_policy_version=PROMPT_POLICY_VERSION,
        confidence=0.9,
        trace_ref=f"trc-audit-{event_id[-8:]}",
        schema_version=DECISION_RECORD_SCHEMA_VERSION,
        idempotency_key=idempotency_key,
        owner=actor,
    )
    async with session_factory() as session:
        async with session.begin():
            return await service.persist_in_session(session, record)
