"""Report section builder outward severity contract (ISSUE-330)."""

from __future__ import annotations

from app.agents.report_section_builder import ReportSectionBuilder, build_decision_brief
from app.models.agent_io import RiskAssessment, ScoringMode, TriageResult
from app.models.enums import EventType, FinalVerdict, Severity


def _triage(*, severity: Severity = Severity.MEDIUM) -> TriageResult:
    return TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=severity,
        need_investigation=True,
        decision_summary=(
            f"event_type=data_exfiltration, severity={severity.value}, "
            "need_investigation=True; external upload suspected"
        ),
    )


def _risk(*, severity: Severity = Severity.HIGH, score: int = 77) -> RiskAssessment:
    return RiskAssessment(
        risk_score=score,
        severity=severity,
        confidence=0.8,
        risk_factors=[],
        possible_false_positive=False,
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def test_build_decision_brief_uses_risk_severity_not_triage_snapshot() -> None:
    brief = build_decision_brief(
        triage_result=_triage(severity=Severity.MEDIUM),
        risk_assessment=_risk(severity=Severity.HIGH),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
    )
    assert "严重级别 high" in brief
    assert "分诊快照" in brief
    assert "分诊严重级别 medium" in brief
    assert "severity=medium" not in brief.lower()


def test_build_decision_brief_omits_triage_snapshot_when_severities_match() -> None:
    brief = build_decision_brief(
        triage_result=_triage(severity=Severity.HIGH),
        risk_assessment=_risk(severity=Severity.HIGH),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
    )
    assert "严重级别 high" in brief
    assert "分诊结论" in brief
    assert "分诊快照" not in brief
    assert "severity=" not in brief.lower()


def test_severity_level_section_exposes_triage_severity_when_divergent() -> None:
    builder = ReportSectionBuilder()
    sections = builder.build(
        event_id="evt-severity-dual",
        evidence_output=_empty_evidence(),
        risk_assessment=_risk(severity=Severity.HIGH),
        triage_result=_triage(severity=Severity.MEDIUM),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
    )
    severity_section = next(section for section in sections if section.key == "severity_level")
    assert "severity=high" in severity_section.content
    assert "triage_severity=medium" in severity_section.content
    overview = next(section for section in sections if section.key == "overview")
    assert "severity: high" in overview.content
    assert "triage_severity: medium" in overview.content
    assert "severity=medium" not in overview.content.lower()
    assert "external upload suspected" in overview.content


def _empty_evidence():
    from app.models.agent_io import CollectionStatus, EvidenceOutput

    return EvidenceOutput(
        evidence_list=[],
        conflicts=[],
        gaps=[],
        success_sources=[],
        failed_sources=[],
        overall_confidence=0.0,
        collection_status=CollectionStatus.COMPLETED,
    )
