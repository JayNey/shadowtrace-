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
        pressure="full_loop_compat",
        pressure_blocks_pass=True,
    ),
    "suspicious_domain_access": ScenarioEvalProfile(
        scenario="suspicious_domain_access",
        semantic="analysis_only_domain",
        pressure="full_loop_compat",
        pressure_blocks_pass=True,
    ),
}

BASELINE_DEPENDENT_SCENARIOS = frozenset({"account_anomaly_fp"})


def profile_for_scenario(scenario: str) -> ScenarioEvalProfile:
    try:
        return SCENARIO_EVAL_PROFILES[scenario]
    except KeyError as exc:
        raise KeyError(f"unknown scenario profile: {scenario!r}") from exc


def scenario_requires_demo_baseline(scenario: str) -> bool:
    return scenario in BASELINE_DEPENDENT_SCENARIOS


__all__ = [
    "BASELINE_DEPENDENT_SCENARIOS",
    "SCENARIO_EVAL_PROFILES",
    "ScenarioEvalProfile",
    "profile_for_scenario",
    "scenario_requires_demo_baseline",
]
