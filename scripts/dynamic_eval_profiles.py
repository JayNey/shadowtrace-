"""Per-scenario dynamic-eval profiles (ISSUE-313).

Separates semantic acceptance gates from full-loop response pressure tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SemanticProfile = Literal[
    "full_loop_strict",
    "analysis_only_fp",
    "analysis_only_domain",
]
PressureProfile = Literal["none", "full_loop_compat", "full_loop_strict"]


@dataclass(frozen=True)
class ScenarioEvalProfile:
    scenario: str
    semantic: SemanticProfile
    pressure: PressureProfile
    pressure_blocks_pass: bool


SCENARIO_EVAL_PROFILES: dict[str, ScenarioEvalProfile] = {
    "insider_data_exfiltration": ScenarioEvalProfile(
        scenario="insider_data_exfiltration",
        semantic="full_loop_strict",
        pressure="none",
        pressure_blocks_pass=False,
    ),
    "account_anomaly_fp": ScenarioEvalProfile(
        scenario="account_anomaly_fp",
        semantic="analysis_only_fp",
        pressure="none",
        pressure_blocks_pass=False,
    ),
    "suspicious_domain_access": ScenarioEvalProfile(
        scenario="suspicious_domain_access",
        semantic="analysis_only_domain",
        pressure="full_loop_compat",
        pressure_blocks_pass=True,
    ),
}

# 8 EventType gold suite (docs/eval-8-eventtype-gold-paths-plan.md §4).
# Separate from GOLD_SCENARIOS / SCENARIO_EVAL_PROFILES — do not merge.
EVENTTYPE8_SCENARIOS: tuple[str, ...] = (
    "account_anomaly_fp",
    "suspicious_domain_access",
    "insider_data_exfiltration",
    "host_compromise",
    "insider_privilege_abuse",
    "malicious_process",
    "lateral_movement",
    "other_unclassified",
)

EVENTTYPE8_EVAL_PROFILES: dict[str, ScenarioEvalProfile] = {
    scenario: ScenarioEvalProfile(
        scenario=scenario,
        semantic="full_loop_strict",
        pressure="none",
        pressure_blocks_pass=False,
    )
    for scenario in EVENTTYPE8_SCENARIOS
}

BASELINE_DEPENDENT_SCENARIOS = frozenset({"account_anomaly_fp"})


def profile_for_scenario(scenario: str) -> ScenarioEvalProfile:
    try:
        return SCENARIO_EVAL_PROFILES[scenario]
    except KeyError as exc:
        raise KeyError(f"unknown scenario profile: {scenario!r}") from exc


def eventtype8_profile_for_scenario(scenario: str) -> ScenarioEvalProfile:
    try:
        return EVENTTYPE8_EVAL_PROFILES[scenario]
    except KeyError as exc:
        raise KeyError(f"unknown eventtype8 scenario profile: {scenario!r}") from exc


def allowed_scenarios_for_suite(suite: str) -> tuple[str, ...]:
    if suite == "eventtype8":
        return EVENTTYPE8_SCENARIOS
    if suite == "demo":
        return (
            "insider_data_exfiltration",
            "account_anomaly_fp",
            "suspicious_domain_access",
        )
    raise KeyError(f"unknown eval suite: {suite!r}")


def scenario_requires_demo_baseline(scenario: str) -> bool:
    return scenario in BASELINE_DEPENDENT_SCENARIOS


__all__ = [
    "BASELINE_DEPENDENT_SCENARIOS",
    "EVENTTYPE8_EVAL_PROFILES",
    "EVENTTYPE8_SCENARIOS",
    "SCENARIO_EVAL_PROFILES",
    "ScenarioEvalProfile",
    "allowed_scenarios_for_suite",
    "eventtype8_profile_for_scenario",
    "profile_for_scenario",
    "scenario_requires_demo_baseline",
]
