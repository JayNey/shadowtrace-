"""ISSUE-313 dynamic eval profile unit tests."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = REPO_ROOT / "scripts"


def _load_module(name: str, path: Path):
    scripts_dir = str(SCRIPTS)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def profiles_mod():
    return _load_module("dynamic_eval_profiles_under_test", SCRIPTS / "dynamic_eval_profiles.py")


@pytest.fixture(scope="module")
def diagnostics_mod():
    return _load_module(
        "dynamic_eval_diagnostics_under_test",
        SCRIPTS / "dynamic_eval_diagnostics.py",
    )


def test_fp_profile_uses_analysis_only_semantic_without_pressure(profiles_mod) -> None:
    profile = profiles_mod.profile_for_scenario("account_anomaly_fp")
    assert profile.semantic == "analysis_only_fp"
    assert profile.pressure == "none"
    assert profile.pressure_blocks_pass is False


def test_domain_profile_requires_pressure_pass(profiles_mod) -> None:
    profile = profiles_mod.profile_for_scenario("suspicious_domain_access")
    assert profile.semantic == "analysis_only_domain"
    assert profile.pressure_blocks_pass is True


def test_insider_profile_is_strict_full_loop_only(profiles_mod) -> None:
    profile = profiles_mod.profile_for_scenario("insider_data_exfiltration")
    assert profile.semantic == "full_loop_strict"
    assert profile.pressure == "none"


def test_scenario_eval_profiles_remain_issue313_three(profiles_mod) -> None:
    assert set(profiles_mod.SCENARIO_EVAL_PROFILES) == {
        "insider_data_exfiltration",
        "account_anomaly_fp",
        "suspicious_domain_access",
    }
    assert profiles_mod.profile_for_scenario("account_anomaly_fp").semantic == "analysis_only_fp"
    with pytest.raises(KeyError, match="unknown scenario profile"):
        profiles_mod.profile_for_scenario("host_compromise")


def test_eventtype8_profiles_are_full_loop_strict(profiles_mod) -> None:
    assert len(profiles_mod.EVENTTYPE8_SCENARIOS) == 8
    assert profiles_mod.allowed_scenarios_for_suite("demo") == (
        "insider_data_exfiltration",
        "account_anomaly_fp",
        "suspicious_domain_access",
    )
    assert (
        profiles_mod.allowed_scenarios_for_suite("eventtype8")
        == profiles_mod.EVENTTYPE8_SCENARIOS
    )
    for scenario in profiles_mod.EVENTTYPE8_SCENARIOS:
        profile = profiles_mod.eventtype8_profile_for_scenario(scenario)
        assert profile.semantic == "full_loop_strict"
        assert profile.pressure == "none"
        assert profile.pressure_blocks_pass is False


def test_format_eval_failure_includes_status_trace(diagnostics_mod) -> None:
    message = diagnostics_mod.format_eval_failure_message(
        headline="semantic gate failed",
        event_id="evt-1",
        diagnostics={
            "status": "failed",
            "final_verdict": "none",
            "status_trace": ["new", "triaging", "failed"],
            "degraded_flags": ["org_baseline_available"],
            "elapsed_s": 12.5,
        },
    )
    assert "status_trace=new -> triaging -> failed" in message
    assert "degraded_flags" in message
    assert "evidence/entities" not in message
