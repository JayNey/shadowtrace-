"""AnalysisOnlyPipeline Celery redelivery resume (first HTTP run stays NEW-only)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.errors import InvalidStateTransitionError
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    RAGOutput,
    RiskAssessment,
    ScoringMode,
    TriageResult,
)
from app.models.enums import DispositionPolicy, EventStatus, EventType, Severity
from app.services.analysis_only_pipeline import AnalysisOnlyPipeline


def _event(*, status: EventStatus) -> SimpleNamespace:
    return SimpleNamespace(
        status=status,
        title="resume-title",
        description="",
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
        creation_source_ref=SimpleNamespace(source_tenant_id=None),
        occurred_at=None,
        final_verdict=None,
    )


class _Triage:
    def __init__(self) -> None:
        self.calls = 0

    async def execute(self, _inp: object) -> TriageResult:
        self.calls += 1
        return TriageResult(
            event_type=EventType.OTHER,
            severity=Severity.LOW,
            need_investigation=True,
            decision_summary="triage",
        )


class _Evidence:
    async def execute(self, _inp: object) -> EvidenceOutput:
        return EvidenceOutput(collection_status=CollectionStatus.COMPLETED)


class _Rag:
    async def execute(self, _inp: object) -> RAGOutput:
        return RAGOutput()


class _Risk:
    async def execute(self, _inp: object) -> RiskAssessment:
        return RiskAssessment(
            risk_score=10,
            severity=Severity.LOW,
            confidence=0.5,
            scoring_mode=ScoringMode.RULE_ONLY,
        )


@pytest.mark.asyncio
async def test_first_run_still_requires_new(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.services.analysis_only_pipeline.assert_analysis_only_mode",
        lambda settings=None: None,
    )
    event_service = MagicMock()
    event_service.get_event = AsyncMock(return_value=_event(status=EventStatus.TRIAGING))
    pipeline = AnalysisOnlyPipeline(
        triage_agent=_Triage(),
        evidence_agent=_Evidence(),
        rag_agent=_Rag(),
        risk_agent=_Risk(),
        report_agent=MagicMock(),
        event_service=event_service,
        state_machine=MagicMock(),
    )
    with pytest.raises(InvalidStateTransitionError, match="NEW status"):
        await pipeline.run("evt-ao-first")


@pytest.mark.asyncio
async def test_allow_resume_continues_from_triaging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.services.analysis_only_pipeline.assert_analysis_only_mode",
        lambda settings=None: None,
    )
    triage = _Triage()
    event_service = MagicMock()
    event_service.get_event = AsyncMock(return_value=_event(status=EventStatus.TRIAGING))
    state_machine = MagicMock()
    state_machine.transition = AsyncMock()
    pipeline = AnalysisOnlyPipeline(
        triage_agent=triage,
        evidence_agent=_Evidence(),
        rag_agent=_Rag(),
        risk_agent=_Risk(),
        report_agent=MagicMock(),
        event_service=event_service,
        state_machine=state_machine,
    )
    pipeline._persist_report_skipped = AsyncMock()
    pipeline._persist_analysis_only_complete = AsyncMock()
    pipeline._run_fp_adjudication = AsyncMock(return_value=None)
    result = await pipeline.run("evt-ao-resume", generate_report=False, allow_resume=True)
    assert result.event_id == "evt-ao-resume"
    assert triage.calls == 1
    assert result.analysis_only_complete is True
