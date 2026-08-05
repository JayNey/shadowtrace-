"""Tests for ISSUE-199 scenario context resolution."""

from __future__ import annotations

from app.core.llm.scenario_context import resolve_llm_scenario_id


def test_resolve_prefers_explicit_override() -> None:
    assert (
        resolve_llm_scenario_id(
            override="host_compromise",
            source_snapshot={"scenario": "account_anomaly_fp"},
        )
        == "host_compromise"
    )


def test_resolve_from_source_snapshot_top_level() -> None:
    assert (
        resolve_llm_scenario_id(
            source_snapshot={"scenario": "malicious_process"},
        )
        == "malicious_process"
    )


def test_resolve_from_normalized_scenario() -> None:
    assert (
        resolve_llm_scenario_id(
            source_snapshot={"normalized": {"scenario": "lateral_movement"}},
        )
        == "lateral_movement"
    )


def test_resolve_from_raw_alert_snapshot() -> None:
    assert (
        resolve_llm_scenario_id(
            raw_alert_snapshot={"scenario": "suspicious_domain_access"},
        )
        == "suspicious_domain_access"
    )


def test_resolve_from_nested_raw_alert_snapshot_in_source_snapshot() -> None:
    assert (
        resolve_llm_scenario_id(
            source_snapshot={"raw_alert_snapshot": {"scenario": "host_compromise"}},
        )
        == "host_compromise"
    )


def test_resolve_defaults_to_none_without_context() -> None:
    assert resolve_llm_scenario_id() is None
    assert resolve_llm_scenario_id(source_snapshot={}) is None
    assert resolve_llm_scenario_id(source_snapshot={"normalized": {}}) is None
