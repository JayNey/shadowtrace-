"""Auto-investigate policy unit tests (ISSUE-108 / #612)."""

from __future__ import annotations

from app.core.config import Settings
from app.db import models as orm
from app.models.enums import EventStatus, Severity
from app.services.auto_investigate_policy import AutoInvestigatePolicyService


def _event(
    *,
    status: str = EventStatus.NEW.value,
    severity: str = Severity.HIGH.value,
    event_type: str = "malicious_process",
    source_product: str = "mock_xdr",
) -> orm.SecurityEvent:
    return orm.SecurityEvent(
        event_id="evt-auto-1",
        event_type=event_type,
        title="test",
        description="",
        status=status,
        severity=severity,
        final_verdict="none",
        creation_source_ref={"source_product": source_product},
        source_reference_snapshots=[],
        disposition_policy="not_required",
        raw_alert_ids=[],
        source_type=source_product,
    )


def test_policy_disabled_by_default() -> None:
    policy = AutoInvestigatePolicyService(Settings(AUTO_INVESTIGATE_ENABLED=False))
    decision = policy.evaluate(_event(), link_role="primary", source_product="mock_xdr")
    assert decision.eligible is False
    assert decision.reason == "disabled"


def test_policy_requires_mock_xdr_source_mode() -> None:
    policy = AutoInvestigatePolicyService(
        Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="file")
    )
    decision = policy.evaluate(_event(), link_role="primary", source_product="mock_xdr")
    assert decision.eligible is False
    assert decision.reason == "source_mode_not_mock_xdr"


def test_policy_holds_provisional_events() -> None:
    policy = AutoInvestigatePolicyService(
        Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    )
    decision = policy.evaluate(_event(), link_role="provisional", source_product="mock_xdr")
    assert decision.eligible is False
    assert decision.reason == "provisional_hold"


def test_policy_min_severity_high_excludes_low() -> None:
    policy = AutoInvestigatePolicyService(
        Settings(
            AUTO_INVESTIGATE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            AUTO_INVESTIGATE_MIN_SEVERITY="high",
        )
    )
    decision = policy.evaluate(
        _event(severity=Severity.LOW.value, event_type="account_anomaly_fp"),
        link_role="primary",
        source_product="mock_xdr",
    )
    assert decision.eligible is False
    assert decision.reason == "below_min_severity"


def test_policy_matches_high_new_mock_event() -> None:
    policy = AutoInvestigatePolicyService(
        Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    )
    decision = policy.evaluate(_event(), link_role="primary", source_product="mock_xdr")
    assert decision.eligible is True
    assert decision.reason == "auto_investigate:policy_match"


def test_policy_event_type_allowlist() -> None:
    policy = AutoInvestigatePolicyService(
        Settings(
            AUTO_INVESTIGATE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            AUTO_INVESTIGATE_EVENT_TYPES="malicious_process",
        )
    )
    allowed = policy.evaluate(_event(event_type="malicious_process"), link_role="primary")
    blocked = policy.evaluate(_event(event_type="account_anomaly_fp"), link_role="primary")
    assert allowed.eligible is True
    assert blocked.eligible is False
    assert blocked.reason == "event_type_not_allowed"


def test_policy_rejects_non_new_status() -> None:
    policy = AutoInvestigatePolicyService(
        Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    )
    decision = policy.evaluate(
        _event(status=EventStatus.TRIAGING.value),
        link_role="primary",
    )
    assert decision.eligible is False
    assert decision.reason == "status_not_new"


def test_policy_rejects_mockish_source_product_provenance() -> None:
    policy = AutoInvestigatePolicyService(
        Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    )
    decision = policy.evaluate(
        _event(source_product="mockish"),
        link_role="primary",
        source_product="mockish",
    )
    assert decision.eligible is False
    assert decision.reason == "untrusted_provenance"
