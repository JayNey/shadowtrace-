"""Agent publication service and guard-before-publish tests (ISSUE-270)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from app.agents.risk_agent import RiskAgent
from app.agents.report_agent import ReportAgent
from app.core.errors import GuardrailViolationError
from app.core.guardrails import GuardrailMode, OutputGuard
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ReportAgentInput,
    RiskAgentInput,
    RiskAssessment,
    RiskFactor,
    ScoringMode,
    TriageResult,
)
from app.models.entities import EntitySet
from app.models.enums import EventType, EvidenceSource, FinalVerdict, Severity
from app.models.evidence import Evidence
from app.models.ids import new_evidence_id, report_id_for_event
from app.models.report import InvestigationReport
from app.services.agent_publication_service import (
    AgentPublicationService,
    GuardApprovedPublication,
    assert_guard_approved_publication,
)


class _MemoryStore:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}

    async def set(self, event_id: str, key: str, value: Any) -> None:
        self.values[(event_id, key)] = value


class _FakeWorkingMemory:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}

    async def read(self, event_id: str, key: str) -> Any:
        return self.values.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.values[(event_id, key)] = value


class _RecordingEventService:
    def __init__(self, *, fail_publish: bool = False) -> None:
        self.fail_publish = fail_publish
        self.risk_publications: list[dict[str, Any]] = []
        self.report_publications: list[dict[str, Any]] = []
        self.verdict_events: list[Any] = []
        self.summary_syncs: list[Any] = []
        self.report_generated_flags: list[tuple[str, bool]] = []

    async def publish_risk_assessment(
        self,
        event_id: str,
        *,
        assessment: RiskAssessment,
        verdict: FinalVerdict,
        operator: str,
        publication: GuardApprovedPublication,
    ) -> tuple[bool, Any, Any]:
        if self.fail_publish:
            raise RuntimeError("publication transaction failed")
        self.risk_publications.append(
            {
                "event_id": event_id,
                "assessment": assessment,
                "verdict": verdict,
                "operator": operator,
            }
        )
        return False, object(), object()

    async def publish_investigation_report(
        self,
        report: InvestigationReport,
        *,
        plan_revision: int = 1,
        operator: str,
        publication: GuardApprovedPublication,
    ) -> InvestigationReport:
        if self.fail_publish:
            raise RuntimeError("publication transaction failed")
        self.report_publications.append(
            {
                "report": report,
                "plan_revision": plan_revision,
                "operator": operator,
            }
        )
        return report.model_copy(update={"version": 1})

    async def publish_final_verdict_mutation(self, *args: Any, **kwargs: Any) -> None:
        self.verdict_events.append((args, kwargs))

    async def sync_event_summary_mutation(self, *args: Any, **kwargs: Any) -> None:
        self.summary_syncs.append((args, kwargs))

    async def merge_report_generated_context_snapshot(
        self,
        event_id: str,
        generated: bool,
    ) -> None:
        self.report_generated_flags.append((event_id, generated))


def _triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(),
        reasoning="test",
    )


def _evidence(event_id: str) -> EvidenceOutput:
    evd_id = new_evidence_id()
    return EvidenceOutput(
        evidence_list=[
            Evidence(
                evidence_id=evd_id,
                event_id=event_id,
                source=EvidenceSource.ENDPOINT,
                evidence_type="process",
                description="known evidence",
                confidence=0.8,
            )
        ],
        overall_confidence=0.8,
        collection_status=CollectionStatus.COMPLETED,
    )


def _risk_assessment(*, reasoning: str = "supported by evidence") -> RiskAssessment:
    return RiskAssessment(
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.8,
        risk_factors=[
            RiskFactor(
                factor_name="lateral_movement",
                weight=0.5,
                raw_score=80,
                weighted_score=40,
                reasoning=reasoning,
            )
        ],
        scoring_mode=ScoringMode.RULE_ONLY,
    )


@pytest.mark.asyncio
async def test_guard_block_leaves_risk_durable_state_unchanged() -> None:
    guard = OutputGuard(mode=GuardrailMode.ENFORCE)
    event_service = _RecordingEventService()
    wm = _FakeWorkingMemory()
    publisher = AgentPublicationService(event_service)
    event_id = f"evt-guard-risk-{uuid4().hex[:8]}"

    class _GroundingRiskAgent(RiskAgent):
        async def _run(self, input: RiskAgentInput) -> RiskAssessment:
            assessment = await super()._run(input)
            return assessment.model_copy(
                update={
                    "risk_factors": [
                        assessment.risk_factors[0].model_copy(
                            update={"reasoning": "supported by evd-missing-001"}
                        )
                    ]
                }
            )

    agent = _GroundingRiskAgent(
        working_memory=wm,
        output_guard=guard,
        event_service=event_service,
        publication_service=publisher,
    )
    with pytest.raises(GuardrailViolationError):
        await agent.execute(
            RiskAgentInput(
                event_id=event_id,
                triage_result=_triage(),
                evidence_output=_evidence(event_id),
            )
        )
    assert event_service.risk_publications == []
    assert await wm.read(event_id, "risk_assessment") is None


@pytest.mark.asyncio
async def test_guard_block_leaves_report_unpersisted() -> None:
    guard = OutputGuard(mode=GuardrailMode.ENFORCE)
    event_service = _RecordingEventService()
    wm = _FakeWorkingMemory()
    publisher = AgentPublicationService(event_service)
    event_id = f"evt-guard-report-{uuid4().hex[:8]}"
    await wm.write(event_id, "triage_result", _triage().model_dump(mode="json"))

    class _LeakyReportAgent(ReportAgent):
        async def _run(self, input: ReportAgentInput) -> InvestigationReport:
            report = await super()._run(input)
            return report.model_copy(
                update={"summary": "token=sk-abcdefghijklmnopqrstuvwxyz012345"}
            )

    agent = _LeakyReportAgent(
        working_memory=wm,
        output_guard=guard,
        event_service=event_service,
        publication_service=publisher,
    )
    with pytest.raises(GuardrailViolationError):
        await agent.execute(
            ReportAgentInput(
                event_id=event_id,
                evidence_output=_evidence(event_id),
                risk_assessment=_risk_assessment(),
            )
        )
    assert event_service.report_publications == []
    assert await wm.read(event_id, "report") is None


@pytest.mark.asyncio
async def test_approved_risk_publication_projects_after_guard() -> None:
    event_service = _RecordingEventService()
    wm = _FakeWorkingMemory()
    publisher = AgentPublicationService(event_service)
    event_id = f"evt-risk-ok-{uuid4().hex[:8]}"
    agent = RiskAgent(
        working_memory=wm,
        event_service=event_service,
        publication_service=publisher,
    )
    result = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_triage(),
            evidence_output=_evidence(event_id),
        )
    )
    assert result.risk_score >= 0
    assert len(event_service.risk_publications) == 1
    assert await wm.read(event_id, "risk_assessment") is not None


@pytest.mark.asyncio
async def test_publication_failure_leaves_wm_unprojected() -> None:
    event_service = _RecordingEventService(fail_publish=True)
    wm = _FakeWorkingMemory()
    publisher = AgentPublicationService(event_service)
    event_id = f"evt-risk-fail-{uuid4().hex[:8]}"
    agent = RiskAgent(
        working_memory=wm,
        event_service=event_service,
        publication_service=publisher,
    )
    with pytest.raises(RuntimeError, match="publication transaction failed"):
        await agent.execute(
            RiskAgentInput(
                event_id=event_id,
                triage_result=_triage(),
                evidence_output=_evidence(event_id),
            )
        )
    assert await wm.read(event_id, "risk_assessment") is None


def test_agent_durable_writer_fence_blocks_risk_agent_without_token() -> None:
    with pytest.raises(GuardrailViolationError):
        assert_guard_approved_publication(operator="RiskAgent", publication=None)


def test_guard_approved_token_allows_risk_agent_operator() -> None:
    token = GuardApprovedPublication.issue(agent_name="risk_agent", event_id="evt-1")
    assert_guard_approved_publication(operator="RiskAgent", publication=token)


@pytest.mark.asyncio
async def test_report_publication_emits_report_generated() -> None:
    event_service = _RecordingEventService()
    wm = _FakeWorkingMemory()
    store = _MemoryStore()
    bus_events: list[tuple[str, str, dict[str, Any]]] = []

    class _Bus:
        async def publish_event(
            self, event_id: str, message_type: str, payload: dict[str, Any] | None = None
        ) -> bool:
            bus_events.append((event_id, message_type, dict(payload or {})))
            return True

    publisher = AgentPublicationService(event_service, event_bus=_Bus(), context_store=store)
    event_id = f"evt-report-ok-{uuid4().hex[:8]}"
    await wm.write(event_id, "triage_result", _triage().model_dump(mode="json"))
    agent = ReportAgent(
        working_memory=wm,
        event_service=event_service,
        publication_service=publisher,
    )
    report = await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=_evidence(event_id),
            risk_assessment=_risk_assessment(),
        )
    )
    assert report.report_id == report_id_for_event(event_id)
    assert len(event_service.report_publications) == 1
    assert await wm.read(event_id, "report") is not None
    assert any(item[1] == "report_generated" for item in bus_events)
    assert store.values.get((event_id, "report_generated")) is True
