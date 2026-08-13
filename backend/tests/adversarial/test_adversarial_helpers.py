"""Unit tests for adversarial helper contracts (ISSUE-203)."""

from __future__ import annotations

import pytest

from tests.adversarial.audit_report import AdversarialAuditChecks
from tests.adversarial.full_loop_runner import resolve_full_loop_timeout_s
from tests.adversarial.helpers import missing_response_targets, response_plan_targets
from tests.adversarial.scenario_credential_db_staging_exfil import GROUND_TRUTH

_CLOSED_SEQUENCE = [
    "new",
    "investigating",
    "planning_response",
    "waiting_approval",
    "executing_response",
    "verifying",
    "reporting",
    "closed",
]
_REPORTING_ONLY_SEQUENCE = [
    "new",
    "investigating",
    "verifying",
    "reporting",
]


def _analysis_pass_checks(**overrides: object) -> AdversarialAuditChecks:
    defaults = {
        "ground_truth": GROUND_TRUTH,
        "event_type": "account_anomaly",
        "severity": "high",
        "risk_score": 80,
        "final_verdict": "confirmed_threat",
        "entities_found": list(GROUND_TRUTH["must_identify_entities"]),
        "indicators_found": list(GROUND_TRUTH["must_identify_indicators"]),
        "report_excerpt": "Confirmed threat summary",
        "triage_summary": "",
        "evidence_collection_status": "completed",
        "status_sequence": _REPORTING_ONLY_SEQUENCE,
    }
    defaults.update(overrides)
    return AdversarialAuditChecks(**defaults)  # type: ignore[arg-type]


def test_response_plan_targets_normalizes_case() -> None:
    actions = [{"target": "WKS-DATA-031"}, {"target": "198.51.100.44"}]
    assert response_plan_targets(actions) == {"wks-data-031", "198.51.100.44"}


def test_missing_response_targets_reports_gaps() -> None:
    actions = [{"tool_name": "disable_account", "target": "svc-analytics-47"}]
    gaps = missing_response_targets(ground_truth=GROUND_TRUTH, actions=actions)
    assert "WKS-DATA-031" in gaps
    assert "198.51.100.44" in gaps


def test_human_verdict_requires_reporting_for_pass() -> None:
    checks = AdversarialAuditChecks(
        ground_truth=GROUND_TRUTH,
        event_type="account_anomaly",
        severity="high",
        risk_score=80,
        final_verdict="confirmed_threat",
        entities_found=list(GROUND_TRUTH["must_identify_entities"]),
        indicators_found=list(GROUND_TRUTH["must_identify_indicators"]),
        report_excerpt="",
        triage_summary="",
        evidence_collection_status="completed",
        status_sequence=["verifying"],
    )
    report = checks.to_dict()
    assert report["verdict_for_human"].startswith("FAIL")


def test_analysis_only_pass_does_not_require_closed() -> None:
    report = _analysis_pass_checks().to_dict()
    assert report["audit_mode"] == "analysis_only"
    assert report["checks"]["reached_reporting"] is True
    assert "closed_reached" not in report["checks"]
    assert report["score"]["total_dimensions"] == 5
    assert report["verdict_for_human"].startswith("PASS")


def test_full_loop_pass_requires_closed() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_REPORTING_ONLY_SEQUENCE,
    ).to_dict()
    assert report["checks"]["closed_reached"] is False
    assert report["score"]["total_dimensions"] == 6
    assert report["score"]["passed"] == 5
    assert report["verdict_for_human"].startswith("FAIL")
    assert "not release-grade" in report["verdict_for_human"]
    assert "PASS" not in report["verdict_for_human"]


def test_full_loop_pass_when_closed_and_analysis_met() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_CLOSED_SEQUENCE,
    ).to_dict()
    assert report["checks"]["closed_reached"] is True
    assert report["score"]["passed"] == report["score"]["total_dimensions"] == 6
    assert report["verdict_for_human"].startswith("PASS")
    assert "CLOSED" in report["verdict_for_human"]


def test_full_loop_fail_when_closed_missing_and_analysis_weak() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        risk_score=1,
        final_verdict="false_positive",
        status_sequence=["new", "investigating", "verifying"],
    ).to_dict()
    assert report["checks"]["closed_reached"] is False
    assert report["checks"]["reached_reporting"] is False
    assert report["verdict_for_human"] == "FAIL — full loop did not reach CLOSED"
    assert "PASS" not in report["verdict_for_human"]


def test_full_loop_fail_verdict_has_no_pass_token() -> None:
    """FAIL strings must not contain PASS (grep / substring false-green)."""
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_REPORTING_ONLY_SEQUENCE,
    ).to_dict()
    verdict = report["verdict_for_human"]
    assert verdict.startswith("FAIL")
    assert "PASS" not in verdict


def test_full_loop_writeback_ok_does_not_override_closed_gate() -> None:
    """Scorecard ignores disposition_writeback_ok; only status_sequence drives CLOSED."""
    # Mimic artifact shape: writeback confirmed while loop never reached CLOSED.
    production_checks = {
        "disposition_writeback_ok": True,
        "terminal_status": "failed",
        "status_sequence_includes_closed": False,
    }
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_REPORTING_ONLY_SEQUENCE,
    ).to_dict()
    assert production_checks["disposition_writeback_ok"] is True
    assert report["checks"]["closed_reached"] is False
    assert report["score"]["passed"] == 5
    assert report["verdict_for_human"].startswith("FAIL")
    assert "PASS" not in report["verdict_for_human"]


def test_full_loop_closed_without_reporting_is_not_pass() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=["new", "investigating", "verifying", "closed"],
    ).to_dict()
    assert report["checks"]["closed_reached"] is True
    assert report["checks"]["reached_reporting"] is False
    assert not report["verdict_for_human"].startswith("PASS")


def test_audit_mode_rejects_unknown_value() -> None:
    with pytest.raises(ValueError, match="audit_mode"):
        _analysis_pass_checks(audit_mode="release")  # type: ignore[arg-type]


def test_resolve_full_loop_timeout_defaults(monkeypatch) -> None:
    monkeypatch.delenv("ADVERSARIAL_FULL_LOOP_TIMEOUT_S", raising=False)
    monkeypatch.setenv("LLM_MODE", "mock")
    assert resolve_full_loop_timeout_s() == 120.0


def test_resolve_full_loop_timeout_live_default(monkeypatch) -> None:
    monkeypatch.delenv("ADVERSARIAL_FULL_LOOP_TIMEOUT_S", raising=False)
    monkeypatch.setenv("LLM_MODE", "openai_compatible")
    assert resolve_full_loop_timeout_s() == 600.0


def test_resolve_full_loop_timeout_env_override(monkeypatch) -> None:
    monkeypatch.setenv("ADVERSARIAL_FULL_LOOP_TIMEOUT_S", "90")
    assert resolve_full_loop_timeout_s() == 90.0
    monkeypatch.setenv("ADVERSARIAL_FULL_LOOP_TIMEOUT_S", "10")
    assert resolve_full_loop_timeout_s() == 30.0


def test_resolve_observed_severity_prefers_risk_over_triage() -> None:
    from tests.adversarial.audit_report import resolve_observed_severity

    outward, triage = resolve_observed_severity(
        risk_ctx={"severity": "high"},
        event_severity="high",
        triage_ctx={"severity": "medium"},
    )
    assert outward == "high"
    assert triage == "medium"
