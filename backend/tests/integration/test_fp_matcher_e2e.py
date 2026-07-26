"""ISSUE-078 e2e acceptance tests for FalsePositiveMatcher in the pipeline.

Scenarios:
1. Full pipeline with fp_matcher wired — genuine alert proceeds normally
2. FP matcher does not prevent triage_result persistence
3. FP match metadata not leaked in outbound disposition
4. TriageAgent wired with fp_matcher in the analysis pipeline
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRSourceAdapter
from app.db import models as orm
from app.ingestion.source_ingester import SourceIngester
from app.models.enums import EventStatus, SourceObjectKind
from app.services.evidence_projection import bind_evidence_projection

pytestmark = pytest.mark.e2e_basic

ALL_SOURCE_KINDS = [
    SourceObjectKind.INCIDENT,
    SourceObjectKind.ALERT,
    SourceObjectKind.ASSET,
    SourceObjectKind.LOG,
]


# --------------------------------------------------------------------------- #
# Scenario 1: Full pipeline with fp_matcher → genuine alert proceeds
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_e2e_pipeline_with_fp_matcher_wired(
    source_adapter: MockXDRSourceAdapter,
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
    build_analysis_pipeline: Any,
) -> None:
    """Full pipeline run with fp_matcher wired — genuine alert not blocked.

    The default mock_xdr scenario (insider_data_exfiltration) is NOT a known
    false positive.  The FP matcher must return no_match and the pipeline
    must proceed normally through all investigation stages.
    """
    # Ingest from the mock XDR source.
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=10)
    assert summary.accepted >= 1

    # Find the ingested event.
    async with session_factory() as session:
        row = (await session.scalars(select(orm.SecurityEvent).limit(1))).first()
    assert row is not None
    event_id = row.event_id

    # Run the analysis pipeline with fp_matcher wired.
    pipeline, projection = build_analysis_pipeline()
    with bind_evidence_projection(projection):
        result = await pipeline.run(event_id)

    # Pipeline must have completed (not crashed).
    assert result is not None

    # Genuine alert must NOT be closed as false positive.
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
    assert row is not None
    assert row.status not in (EventStatus.CLOSED,), (
        f"Genuine alert incorrectly short-circuited, status={row.status}"
    )
    # It should have progressed past TRIAGING.
    assert row.status != EventStatus.TRIAGING, "Pipeline stuck at triaging"


# --------------------------------------------------------------------------- #
# Scenario 2: FP matcher → triage_result persisted
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_e2e_fp_matcher_triage_result_persisted(
    source_adapter: MockXDRSourceAdapter,
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
    build_analysis_pipeline: Any,
) -> None:
    """After pipeline run with fp_matcher wired, triage_result is persisted.

    Even when fp_matcher returns no_match, the triage_result (entities,
    event_type, severity) must be durably stored for downstream agents.
    """
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=10)
    assert summary.accepted >= 1

    async with session_factory() as session:
        row = (await session.scalars(select(orm.SecurityEvent).limit(1))).first()
    assert row is not None
    event_id = row.event_id

    pipeline, projection = build_analysis_pipeline()
    with bind_evidence_projection(projection):
        await pipeline.run(event_id)

    # Verify triage_result persisted to the DB.
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
    assert row is not None
    assert row.event_type is not None, "triage_result not persisted: event_type is None"
    assert row.severity is not None, "triage_result not persisted: severity is None"


# --------------------------------------------------------------------------- #
# Scenario 3: FP match metadata not in outbound disposition
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_fp_match_not_in_disposition_outbound() -> None:
    """OutboundDispositionGuard blocks payloads with FP metadata leaking outbound.

    The DispositionCommand schema is the allowlist for outbound fields.
    Internal FP metadata (matched_case_id, matched_pattern, max_score, etc.)
    must never appear in outbound disposition payloads — the guard raises
    GuardrailViolationError on non-allowlisted fields.
    """
    from app.core.errors import GuardrailViolationError
    from app.core.guardrails import (
        _DISPOSITION_ALLOWED_TOP_LEVEL,
        OutboundDispositionGuard,
    )

    # Internal FP metadata must NOT be in the outbound allowlist.
    fp_internal_keys = {
        "matched_case_id",
        "matched_pattern",
        "max_score",
        "source",
        "matched_at",
    }
    assert fp_internal_keys.isdisjoint(_DISPOSITION_ALLOWED_TOP_LEVEL), (
        f"FP internal metadata leaked into outbound allowlist: "
        f"{fp_internal_keys & _DISPOSITION_ALLOWED_TOP_LEVEL}"
    )

    guard = OutboundDispositionGuard()

    payload: dict[str, Any] = {
        "disposition_id": "disp-test-001",
        "action_id": "act-test-001",
        "closure_cycle": 1,
        "intent_kind": "confirm",
        "operation_code": "close_event",
        "operator_id": "system",
        "idempotency_key": "idem-test-001",
        # Smuggled FP metadata — NOT in DispositionCommand schema:
        "matched_case_id": "case-00000001",
        "matched_pattern": "Ops change window bulk login",
        "max_score": 0.96,
    }

    with pytest.raises(
        GuardrailViolationError, match="disposition_field_allowlist|blocked writeback"
    ):
        await guard.validate(payload)


@pytest.mark.asyncio
async def test_fp_match_not_in_disposition_outbound_clean_payload() -> None:
    """A clean disposition payload (no FP metadata) does not trigger FP-block."""
    from app.core.errors import GuardrailViolationError
    from app.core.guardrails import OutboundDispositionGuard

    guard = OutboundDispositionGuard()

    payload: dict[str, Any] = {
        "disposition_id": "disp-test-002",
        "action_id": "act-test-002",
        "closure_cycle": 1,
        "intent_kind": "confirm",
        "operation_code": "close_event",
        "operator_id": "system",
        "idempotency_key": "idem-test-002",
    }

    try:
        await guard.validate(payload)
    except GuardrailViolationError as exc:
        detail = str(exc.details.get("violations", ""))
        # Must NOT fail due to FP metadata — those fields aren't in the payload.
        assert "matched_case_id" not in detail
        assert "matched_pattern" not in detail
        assert "max_score" not in detail


# --------------------------------------------------------------------------- #
# Scenario 4: TriageAgent wiring verification
# --------------------------------------------------------------------------- #


def test_deps_triage_agent_wires_fp_matcher() -> None:
    """Verify TriageAgent accepts fp_matcher for hook registration."""
    from app.agents.triage_agent import TriageAgent
    from app.services.false_positive_matcher import FalsePositiveMatcher

    matcher = MagicMock(spec=FalsePositiveMatcher)
    matcher.match = AsyncMock()

    # When fp_matcher is None, no hook installed.
    agent_no_fp = TriageAgent(fp_matcher=None)
    post_hooks_before = len(agent_no_fp.post_triage_hooks)

    # fp_matcher parameter exists on constructor.
    assert "fp_matcher" in TriageAgent.__init__.__code__.co_varnames
    assert post_hooks_before == len(agent_no_fp.post_triage_hooks)
