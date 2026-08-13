"""Tests for ISSUE-200 triage vs risk consistency detection."""

from __future__ import annotations

from app.agents.triage_risk_consistency import (
    format_triage_decision_excerpt,
    resolve_outward_severity,
    should_flag_triage_risk_inconsistency,
    strip_triage_machine_prefix,
    triage_has_weak_classification_signal,
)
from app.models.agent_io import TriageResult
from app.models.enums import EventType, FinalVerdict, Severity
from tests.adversarial.audit_report import resolve_observed_severity


def test_weak_signal_other_event_type() -> None:
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.MEDIUM,
        need_investigation=True,
        decision_summary="Structured entities present; awaiting pattern match.",
    )
    assert triage_has_weak_classification_signal(triage)


def test_weak_signal_from_no_clear_threat_summary() -> None:
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        decision_summary="No clear threat pattern detected.",
    )
    assert triage_has_weak_classification_signal(triage)


def test_strong_triage_not_weak() -> None:
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        decision_summary="Insider data exfiltration pattern with external upload.",
    )
    assert not triage_has_weak_classification_signal(triage)


def test_flags_conflict_when_other_and_high_risk_confirmed_threat() -> None:
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.MEDIUM,
        need_investigation=True,
        decision_summary="No clear threat pattern detected.",
    )
    assert should_flag_triage_risk_inconsistency(
        triage=triage,
        risk_score=80,
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
    )


def test_no_flag_when_risk_below_threshold() -> None:
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=True,
        decision_summary="No clear threat pattern detected.",
    )
    assert not should_flag_triage_risk_inconsistency(
        triage=triage,
        risk_score=45,
        final_verdict=FinalVerdict.NONE,
    )


def test_no_flag_when_consistent_high_confidence_triage() -> None:
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        decision_summary="Confirmed data exfiltration to external staging host.",
    )
    assert not should_flag_triage_risk_inconsistency(
        triage=triage,
        risk_score=85,
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
    )


def test_no_flag_when_false_positive_verdict() -> None:
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        decision_summary="No clear threat pattern detected.",
    )
    assert not should_flag_triage_risk_inconsistency(
        triage=triage,
        risk_score=80,
        final_verdict=FinalVerdict.FALSE_POSITIVE,
    )


def test_no_flag_when_verdict_none_despite_high_risk() -> None:
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.MEDIUM,
        need_investigation=True,
        decision_summary="No clear threat pattern detected.",
    )
    assert not should_flag_triage_risk_inconsistency(
        triage=triage,
        risk_score=82,
        final_verdict=FinalVerdict.NONE,
    )


def test_no_flag_when_possible_false_positive() -> None:
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.MEDIUM,
        need_investigation=True,
        decision_summary="No clear threat pattern detected.",
    )
    assert not should_flag_triage_risk_inconsistency(
        triage=triage,
        risk_score=82,
        final_verdict=FinalVerdict.POSSIBLE_FALSE_POSITIVE,
    )


def test_strong_triage_with_not_a_threat_substring_not_weak() -> None:
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        decision_summary=("Confirmed exfiltration; not a threat to unrelated production segments."),
    )
    assert not triage_has_weak_classification_signal(triage)
    assert not should_flag_triage_risk_inconsistency(
        triage=triage,
        risk_score=85,
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
    )


def test_strip_triage_machine_prefix() -> None:
    raw = (
        "event_type=data_exfiltration, severity=medium, need_investigation=True; "
        "external upload suspected"
    )
    assert strip_triage_machine_prefix(raw) == "external upload suspected"


def test_format_triage_decision_excerpt_labels_divergent_severity() -> None:
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
        need_investigation=True,
        decision_summary=(
            "event_type=data_exfiltration, severity=medium, need_investigation=True; "
            "notes only"
        ),
    )
    excerpt = format_triage_decision_excerpt(triage, outward_severity=Severity.HIGH)
    assert excerpt is not None
    assert excerpt.startswith("分诊快照：")
    assert "分诊严重级别 medium" in excerpt
    assert "severity=medium" not in excerpt


def test_resolve_outward_severity_prefers_risk_assessment() -> None:
    assert (
        resolve_outward_severity(
            risk_assessment={"severity": "high"},
            event_severity="medium",
        )
        is Severity.HIGH
    )


def test_resolve_observed_severity_never_falls_back_to_triage() -> None:
    outward, triage = resolve_observed_severity(
        risk_ctx={"severity": "high"},
        event_severity="high",
        triage_ctx={"severity": "medium"},
    )
    assert outward == "high"
    assert triage == "medium"
