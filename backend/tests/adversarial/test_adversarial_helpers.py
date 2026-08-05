"""Unit tests for adversarial helper contracts (ISSUE-203)."""

from __future__ import annotations

from tests.adversarial.audit_report import AdversarialAuditChecks
from tests.adversarial.full_loop_runner import resolve_full_loop_timeout_s
from tests.adversarial.helpers import missing_response_targets, response_plan_targets
from tests.adversarial.scenario_credential_db_staging_exfil import GROUND_TRUTH


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
