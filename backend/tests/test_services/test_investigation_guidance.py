"""Investigation guidance derivation tests (ISSUE-103)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    ExecutionSubstate,
    InvestigationIntentStatus,
    NextRecommendedAction,
    ResponsePhaseState,
    Severity,
)
from app.services.investigation_guidance import (
    derive_investigation_guidance,
    full_loop_available,
    resolve_include_response_execution_for_resume,
    workflow_path_from_request,
)


def test_full_loop_available_blocks_analysis_only_mode() -> None:
    assert full_loop_available("graph") is True
    assert full_loop_available("analysis_only") is False


def test_workflow_path_from_request() -> None:
    assert workflow_path_from_request(include_response_execution=False) == "analysis_only"
    assert workflow_path_from_request(include_response_execution=True) == "full_loop"


def test_reporting_analysis_only_deferred_no_start_response_cta() -> None:
    guidance = derive_investigation_guidance(
        status=EventStatus.REPORTING,
        disposition_policy=DispositionPolicy.REQUIRED,
        context_snapshot={"analysis_only_complete": True},
        orchestration_mode="graph",
    )
    assert guidance.response_phase_state is ResponsePhaseState.ANALYSIS_COMPLETE_DEFERRED
    assert guidance.next_recommended_action is NextRecommendedAction.NONE
    assert guidance.analysis_only_complete is True
    assert guidance.phase_message is not None
    assert "无法从 REPORTING" in guidance.phase_message
    assert "新事件" in guidance.phase_message


def test_reporting_not_required_suggests_close() -> None:
    guidance = derive_investigation_guidance(
        status=EventStatus.REPORTING,
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
        context_snapshot={"analysis_only_complete": True},
        orchestration_mode="graph",
    )
    assert guidance.next_recommended_action is NextRecommendedAction.CLOSE


def test_waiting_approval_suggests_approve() -> None:
    guidance = derive_investigation_guidance(
        status=EventStatus.WAITING_APPROVAL,
        disposition_policy=DispositionPolicy.REQUIRED,
        context_snapshot={
            "analysis_only_complete": False,
            "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
        },
        orchestration_mode="graph",
    )
    assert guidance.response_phase_state is ResponsePhaseState.AWAITING_APPROVAL
    assert guidance.next_recommended_action is NextRecommendedAction.APPROVE_ACTIONS


def test_new_event_not_started() -> None:
    guidance = derive_investigation_guidance(
        status=EventStatus.NEW,
        disposition_policy=DispositionPolicy.REQUIRED,
        context_snapshot=None,
        orchestration_mode="graph",
    )
    assert guidance.response_phase_state is ResponsePhaseState.NOT_STARTED


async def _seed_event(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    status: EventStatus,
) -> None:
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="test",
                    description="",
                    status=status.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )


@pytest.mark.asyncio
async def test_resolve_include_response_for_resume_prefers_intent_flag(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = f"evt-resume-intent-{uuid4().hex[:8]}"
    await _seed_event(session_factory, event_id=event_id, status=EventStatus.NEW)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.InvestigationIntent(
                    intent_id=f"iin-resume-{uuid4().hex[:8]}",
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=True,
                )
            )

    assert await resolve_include_response_execution_for_resume(session_factory, event_id) is True


@pytest.mark.asyncio
async def test_resolve_include_response_for_resume_from_workflow_trace_without_intent_flag(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from datetime import UTC, datetime

    event_id = f"evt-resume-trace-{uuid4().hex[:8]}"
    await _seed_event(session_factory, event_id=event_id, status=EventStatus.WAITING_APPROVAL)
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.AgentTrace(
                    trace_id=f"tr-resume-{uuid4().hex[:8]}",
                    event_id=event_id,
                    agent_name="super_agent",
                    input_data={
                        "workflow_path": "full_loop",
                        "include_response_execution": True,
                    },
                    output_data={"workflow_path": "full_loop"},
                    status="completed",
                    started_at=now,
                    completed_at=now,
                )
            )

    assert await resolve_include_response_execution_for_resume(session_factory, event_id) is True


@pytest.mark.asyncio
async def test_resolve_include_response_for_resume_from_auto_response_audit(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = f"evt-resume-audit-{uuid4().hex[:8]}"
    await _seed_event(session_factory, event_id=event_id, status=EventStatus.WAITING_APPROVAL)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    operator="AutoResponsePolicyService",
                    reason="auto_response:policy_match",
                )
            )

    assert await resolve_include_response_execution_for_resume(session_factory, event_id) is True


@pytest.mark.asyncio
async def test_resolve_include_response_for_resume_false_for_bare_response_status(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = f"evt-resume-status-{uuid4().hex[:8]}"
    await _seed_event(session_factory, event_id=event_id, status=EventStatus.WAITING_APPROVAL)

    assert await resolve_include_response_execution_for_resume(session_factory, event_id) is False


@pytest.mark.asyncio
async def test_resolve_include_response_for_resume_false_for_new_event_without_intent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = f"evt-resume-false-{uuid4().hex[:8]}"
    await _seed_event(session_factory, event_id=event_id, status=EventStatus.NEW)

    assert await resolve_include_response_execution_for_resume(session_factory, event_id) is False
