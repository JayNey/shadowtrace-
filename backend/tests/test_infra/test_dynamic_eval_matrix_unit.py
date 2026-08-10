"""ISSUE-301 unit tests: dynamic eval matrix helpers (no Docker required)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MATRIX_PATH = REPO_ROOT / "scripts" / "dynamic_eval_matrix.py"


def _load_matrix_module():
    scripts_dir = str(REPO_ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(
        "dynamic_eval_matrix_under_test",
        MATRIX_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["dynamic_eval_matrix_under_test"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def matrix_mod():
    return _load_matrix_module()


def test_event_ids_from_seed_summary_returns_explicit_ids(matrix_mod) -> None:
    summary = {"accepted": 1, "event_ids": ["evt-a", "evt-b"]}
    assert matrix_mod.event_ids_from_seed_summary(
        summary,
        scenario="insider_data_exfiltration",
        max_events=1,
    ) == ["evt-a"]


def test_event_ids_from_seed_summary_raises_when_missing(matrix_mod) -> None:
    with pytest.raises(matrix_mod.MatrixError, match="missing event_ids"):
        matrix_mod.event_ids_from_seed_summary(
            {"accepted": 1},
            scenario="insider_data_exfiltration",
            max_events=1,
        )


def test_scenario_seed_offset_is_stable(matrix_mod) -> None:
    first = matrix_mod.scenario_seed_offset(42, "insider_data_exfiltration")
    second = matrix_mod.scenario_seed_offset(42, "insider_data_exfiltration")
    assert first == second
    assert first != matrix_mod.scenario_seed_offset(42, "account_anomaly_fp")


def test_service_row_unhealthy_flags_running_unhealthy(matrix_mod) -> None:
    required = {"backend"}
    row = {"Service": "backend", "State": "running", "Health": "unhealthy"}
    assert matrix_mod._service_row_unhealthy(row, required=required) is True


def test_service_row_unhealthy_accepts_running_healthy(matrix_mod) -> None:
    required = {"backend"}
    row = {"Service": "backend", "State": "running", "Health": "healthy"}
    assert matrix_mod._service_row_unhealthy(row, required=required) is False


def test_sanitize_error_text_redacts_bearer(matrix_mod) -> None:
    raw = "failed Authorization: Bearer secret-token-value"
    sanitized = matrix_mod._sanitize_error_text(raw)
    assert "secret-token-value" not in sanitized
    assert "<redacted>" in sanitized


def test_matrix_main_stops_after_first_scenario_failure(matrix_mod) -> None:
    calls: list[str] = []

    def _fake_run_scenario(*, scenario: str, **kwargs):
        calls.append(scenario)
        if scenario == "insider_data_exfiltration":
            raise matrix_mod.MatrixError("simulated failure")
        return {"status": "passed"}

    with patch.object(matrix_mod, "run_scenario", side_effect=_fake_run_scenario):
        rc = matrix_mod.main(
            [
                "--scenarios",
                "insider_data_exfiltration,account_anomaly_fp",
                "--no-build",
            ]
        )
    assert rc == 1
    assert calls == ["insider_data_exfiltration"]
