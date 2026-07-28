"""MemoryAgent knowledge-consolidation tests (ISSUE-080)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import yaml

from app.agents.memory_agent import MemoryAgent
from app.agents.super_agent import SuperAgent
from app.models.agent_io import InvestigationResult, MemoryAgentInput
from app.models.context import EventContext
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.models.report import InvestigationReport
from app.models.security_event import EventSummary
from app.services.case_kb_service import _response_succeeded
from app.services.profile_service import profile_id_for

EVENT_ID = "evt-memory-0001"


class _CaseKB:
    def __init__(self, *, fail: bool = False, ineligible: bool = False) -> None:
        self.fail = fail
        self.ineligible = ineligible
        self.archived: list[str] = []

    async def archive_event_as_case(self, event_id: str) -> str:
        if self.fail:
            raise RuntimeError("case archive unavailable")
        if self.ineligible:
            raise ValueError("event is not eligible for history_case_kb")
        self.archived.append(event_id)
        return "case-acde1234"


class _Profiles:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.updates: list[Any] = []

    async def upsert(self, update: Any) -> None:
        if self.fail:
            raise RuntimeError("profile store unavailable")
        self.updates.append(update)


class _ContextStore:
    def __init__(self, context: EventContext) -> None:
        self.context = context
        self.refresh_count = 0

    async def get_full_context(self, event_id: str) -> EventContext:
        assert event_id == EVENT_ID
        return self.context

    async def refresh_closed_snapshot(self, event_id: str) -> EventContext:
        assert event_id == EVENT_ID
        self.refresh_count += 1
        return self.context


class _WorkingMemory:
    def __init__(self, context: EventContext) -> None:
        self.context = context
        self.writes: list[tuple[str, str, Any]] = []

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.writes.append((event_id, key, value))
        self.context.memory_output = value


class _UnavailableLLM:
    async def chat(self, *_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("LLM unavailable")


class _FailingMemoryAgent:
    async def execute(self, _input: MemoryAgentInput) -> None:
        raise RuntimeError("memory failed")


class _SuccessfulMemoryAgent:
    def __init__(self) -> None:
        self.inputs: list[MemoryAgentInput] = []

    async def execute(self, input: MemoryAgentInput) -> None:
        self.inputs.append(input)


class _BlockingMemoryAgent:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def execute(self, _input: MemoryAgentInput) -> None:
        self.started.set()
        await self.release.wait()


class _Audit:
    def __init__(self) -> None:
        self.entries: list[tuple[Any, ...]] = []

    async def log_transition(self, *args: Any) -> str:
        self.entries.append(args)
        return "audit-1"


def _context(
    verdict: FinalVerdict,
    *,
    external_unsynced: bool = False,
) -> EventContext:
    return EventContext(
        event=EventSummary(
            event_id=EVENT_ID,
            event_type=EventType.DATA_EXFILTRATION,
            title="Suspicious upload by zhangsan",
            status=EventStatus.CLOSED,
            severity=Severity.HIGH,
            risk_score=88,
            final_verdict=verdict,
            writeback_required=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            disposition_policy=DispositionPolicy.NOT_REQUIRED,
            external_unsynced=external_unsynced,
        ),
        graph_output={
            "nodes": [
                {
                    "node_id": "node-account",
                    "event_id": EVENT_ID,
                    "entity_type": "account",
                    "entity_value": "zhangsan",
                    "properties": {},
                }
            ],
            "edges": [],
            "central_entities": ["zhangsan"],
            "attack_path_candidates": [],
        },
        storyline={
            "storyline_id": "story-1",
            "event_id": EVENT_ID,
            "narrative_summary": "Credential use followed by upload.",
            "phases": [
                {
                    "phase_order": 1,
                    "phase_name": "initial_access",
                    "narrative": "Account access",
                    "entries": [],
                }
            ],
            "generated_by": "rule",
        },
        evidence_output={
            "evidence_list": [
                {
                    "evidence_id": "evd-1",
                    "event_id": EVENT_ID,
                    "source": "xdr",
                    "evidence_type": "process_execution",
                    "description": "WebDAV upload",
                    "confidence": 0.95,
                    "related_entities": ["zhangsan"],
                    "raw_data": {},
                    "mitre_technique": "T1048",
                    "is_conflicting": False,
                }
            ],
            "conflicts": [],
            "gaps": [],
            "success_sources": ["xdr"],
            "failed_sources": [],
            "overall_confidence": 0.95,
            "collection_status": "complete",
        },
        report=InvestigationReport(
            report_id="rpt-memory-1",
            event_id=EVENT_ID,
            title="Confirmed exfiltration",
            summary="Evidence confirms a WebDAV upload.",
            final_verdict=verdict,
            risk_score=88,
            severity=Severity.HIGH,
        ),
    )


def _input(
    verdict: FinalVerdict,
    *,
    external_unsynced: bool = False,
) -> MemoryAgentInput:
    return MemoryAgentInput(
        event_id=EVENT_ID,
        investigation_result=InvestigationResult(
            event_id=EVENT_ID,
            final_status=EventStatus.CLOSED,
            final_verdict=verdict,
            external_unsynced=external_unsynced,
            writeback_required=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        ),
    )


@pytest.mark.asyncio
async def test_confirmed_threat_archives_case_updates_profile_and_builds_sigma() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    cases = _CaseKB()
    profiles = _Profiles()
    memory = _WorkingMemory(context)
    agent = MemoryAgent(
        case_kb_service=cases,  # type: ignore[arg-type]
        profile_service=profiles,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )

    output = await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT))

    assert cases.archived == [EVENT_ID]
    assert output.case_records[0].archived is True
    assert [update.entity_value for update in profiles.updates] == ["zhangsan"]
    assert profiles.updates[0].risk_score == 88
    assert output.profile_updates == profiles.updates
    assert len(output.sigma_drafts) == 1
    sigma = yaml.safe_load(output.sigma_drafts[0])
    assert EVENT_ID in sigma["title"]
    assert sigma["detection"]["condition"] == "selection"
    assert sigma["detection"]["selection"]["event_id"] == EVENT_ID
    assert memory.writes[0][1] == "memory_output"


@pytest.mark.asyncio
async def test_false_positive_candidate_is_pending_review_with_llm_fallback() -> None:
    context = _context(FinalVerdict.FALSE_POSITIVE)
    agent = MemoryAgent(
        case_kb_service=_CaseKB(),  # type: ignore[arg-type]
        profile_service=_Profiles(),  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=_WorkingMemory(context),
        llm_client=_UnavailableLLM(),
    )

    output = await agent.execute(_input(FinalVerdict.FALSE_POSITIVE))

    assert len(output.fp_rules) == 1
    assert output.fp_rules[0].pending_review is True
    assert output.fp_rules[0].source_event_id == EVENT_ID
    assert output.sigma_drafts == []


@pytest.mark.asyncio
async def test_individual_persistence_failures_degrade_without_losing_memory_output() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    memory = _WorkingMemory(context)
    agent = MemoryAgent(
        case_kb_service=_CaseKB(fail=True),  # type: ignore[arg-type]
        profile_service=_Profiles(fail=True),  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )

    output = await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT))

    assert output.case_records == []
    assert output.profile_updates == []
    assert len(output.sigma_drafts) == 1
    assert memory.writes


@pytest.mark.asyncio
async def test_ineligible_case_uses_info_log_without_hiding_other_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    memory = _WorkingMemory(context)
    info_calls: list[tuple[Any, ...]] = []
    warning_calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        "app.agents.memory_agent.logger.info",
        lambda *args, **_kwargs: info_calls.append(args),
    )
    monkeypatch.setattr(
        "app.agents.memory_agent.logger.warning",
        lambda *args, **_kwargs: warning_calls.append(args),
    )
    agent = MemoryAgent(
        case_kb_service=_CaseKB(ineligible=True),  # type: ignore[arg-type]
        profile_service=_Profiles(),  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )

    output = await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT))

    assert output.case_records == []
    assert output.profile_updates
    assert output.sigma_drafts
    assert "case archival ineligible" in info_calls[0][0]
    assert warning_calls == []


@pytest.mark.asyncio
async def test_external_unsynced_skips_all_consolidation() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT, external_unsynced=True)
    cases = _CaseKB()
    profiles = _Profiles()
    memory = _WorkingMemory(context)
    agent = MemoryAgent(
        case_kb_service=cases,  # type: ignore[arg-type]
        profile_service=profiles,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )

    output = await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT, external_unsynced=True))

    assert output.case_records == []
    assert output.fp_rules == []
    assert output.profile_updates == []
    assert output.sigma_drafts == []
    assert cases.archived == []
    assert profiles.updates == []
    assert memory.writes[0][2] == output.model_dump(mode="json")


@pytest.mark.asyncio
async def test_memory_failure_keeps_event_closed_and_records_audit() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    context_store = _ContextStore(context)
    audit = _Audit()
    super_agent = SuperAgent(
        memory_agent=_FailingMemoryAgent(),
        context_store=context_store,
        audit_service=audit,
    )

    task = await super_agent._schedule_memory_after_close(EVENT_ID, context)
    assert task is not None
    await task

    assert context.event is not None
    assert context.event.status is EventStatus.CLOSED
    assert context_store.refresh_count == 1
    assert len(audit.entries) == 1
    _, from_status, to_status, operator, reason = audit.entries[0]
    assert from_status == to_status == EventStatus.CLOSED.value
    assert operator == "MemoryAgent"
    assert "memory_agent_failed" in reason


@pytest.mark.asyncio
async def test_successful_post_close_hook_refreshes_snapshot() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    context_store = _ContextStore(context)
    memory_agent = _SuccessfulMemoryAgent()
    super_agent = SuperAgent(
        memory_agent=memory_agent,
        context_store=context_store,
    )

    task = await super_agent._schedule_memory_after_close(EVENT_ID, context)
    assert task is not None
    await task

    assert len(memory_agent.inputs) == 1
    assert memory_agent.inputs[0].investigation_result.final_status is EventStatus.CLOSED
    assert context_store.refresh_count == 2


@pytest.mark.asyncio
async def test_post_close_hook_runs_memory_without_blocking_caller() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    context_store = _ContextStore(context)
    memory_agent = _BlockingMemoryAgent()
    super_agent = SuperAgent(
        memory_agent=memory_agent,
        context_store=context_store,
    )

    task = await super_agent._schedule_memory_after_close(EVENT_ID, context)

    assert task is not None
    await asyncio.wait_for(memory_agent.started.wait(), timeout=1)
    assert not task.done()
    assert context_store.refresh_count == 1

    memory_agent.release.set()
    await asyncio.wait_for(task, timeout=1)
    assert context_store.refresh_count == 2


@pytest.mark.asyncio
async def test_existing_memory_output_makes_replay_idempotent() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    context.memory_output = {
        "case_records": [],
        "fp_rules": [],
        "profile_updates": [],
        "sigma_drafts": ["existing"],
    }
    cases = _CaseKB()
    profiles = _Profiles()
    memory = _WorkingMemory(context)
    agent = MemoryAgent(
        case_kb_service=cases,  # type: ignore[arg-type]
        profile_service=profiles,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )

    output = await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT))

    assert output.sigma_drafts == ["existing"]
    assert cases.archived == []
    assert profiles.updates == []
    assert memory.writes == []


def test_response_success_requires_verified_effect_and_synchronized_writeback() -> None:
    assert _response_succeeded(
        effect_status="verified",
        writeback_status=None,
        policy=DispositionPolicy.NOT_REQUIRED,
        terminal_confirmed=False,
    )
    assert _response_succeeded(
        effect_status="verified",
        writeback_status="confirmed",
        policy=DispositionPolicy.REQUIRED,
        terminal_confirmed=False,
    )
    assert _response_succeeded(
        effect_status="verified",
        writeback_status=None,
        policy=DispositionPolicy.REQUIRED,
        terminal_confirmed=True,
    )
    assert not _response_succeeded(
        effect_status="pending",
        writeback_status="confirmed",
        policy=DispositionPolicy.REQUIRED,
        terminal_confirmed=True,
    )
    assert not _response_succeeded(
        effect_status="verified",
        writeback_status="accepted",
        policy=DispositionPolicy.REQUIRED,
        terminal_confirmed=False,
    )


def test_profile_id_is_stable_and_case_insensitive() -> None:
    assert profile_id_for("account", "zhangsan").startswith("prf-")
    assert profile_id_for(" Account ", "ZhangSan") == profile_id_for("account", "zhangsan")
