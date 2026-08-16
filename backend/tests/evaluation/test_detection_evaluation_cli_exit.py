"""Exit-code contract for detection evaluation CLI (ISSUE-167 / #686, ISSUE-263)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts.run_detection_evaluation import cli_exit_code


def test_cli_exit_code_fails_on_baseline_drift_even_with_allow_gate_fail() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict="fail_closed",
            baseline_compare_failed=True,
            allow_gate_fail=True,
            required_scorer_error_count=2,
        )
        == 1
    )


def test_cli_exit_code_observe_mode_allows_pinned_fail_closed() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict="fail_closed",
            baseline_compare_failed=False,
            allow_gate_fail=True,
            required_scorer_error_count=2,
        )
        == 0
    )


def test_cli_exit_code_required_mode_hard_fails_on_gate() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict="fail_closed",
            baseline_compare_failed=False,
            allow_gate_fail=False,
            required_scorer_error_count=2,
        )
        == 1
    )
    assert (
        cli_exit_code(
            artifact_status="completed",
            gate_verdict="fail",
            baseline_compare_failed=False,
            allow_gate_fail=False,
        )
        == 1
    )


def test_cli_exit_code_success_when_completed_and_gate_pass() -> None:
    assert (
        cli_exit_code(
            artifact_status="completed",
            gate_verdict="pass",
            baseline_compare_failed=False,
            allow_gate_fail=False,
        )
        == 0
    )


def test_cli_exit_code_required_mode_fails_on_non_completed_status() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict=None,
            baseline_compare_failed=False,
            allow_gate_fail=False,
        )
        == 1
    )


def test_cli_exit_code_required_mode_fails_on_required_scorer_errors() -> None:
    assert (
        cli_exit_code(
            artifact_status="completed",
            gate_verdict="pass",
            baseline_compare_failed=False,
            allow_gate_fail=False,
            required_scorer_error_count=1,
        )
        == 1
    )


def test_cli_exit_code_observe_mode_allows_non_completed_with_gate_pass() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict="pass",
            baseline_compare_failed=False,
            allow_gate_fail=True,
        )
        == 0
    )


def test_shipped_gate_baseline_is_zero_in_required_mode() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    baseline = json.loads(
        (
            repo_root / "data" / "evaluation" / "detection_shadow_v1" / "baseline_artifact.json"
        ).read_text(encoding="utf-8")
    )
    inputs = {
        "artifact_status": baseline["status"],
        "gate_verdict": baseline["gate"]["verdict"],
        "baseline_compare_failed": False,
        "required_scorer_error_count": baseline["aggregates"]["required_scorer_error_count"],
    }

    assert cli_exit_code(**inputs, allow_gate_fail=False) == 0
    assert cli_exit_code(**inputs, allow_gate_fail=True) == 0


def test_shipped_failing_baseline_is_nonzero_only_in_required_mode() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    baseline = json.loads(
        (
            repo_root
            / "data"
            / "evaluation"
            / "detection_shadow_v1_fail_closed"
            / "baseline_artifact.json"
        ).read_text(encoding="utf-8")
    )
    inputs = {
        "artifact_status": baseline["status"],
        "gate_verdict": baseline["gate"]["verdict"],
        "baseline_compare_failed": False,
        "required_scorer_error_count": baseline["aggregates"]["required_scorer_error_count"],
    }

    assert cli_exit_code(**inputs, allow_gate_fail=False) == 1
    assert cli_exit_code(**inputs, allow_gate_fail=True) == 0


@pytest.mark.evaluation
def test_ci_required_detection_step_and_artifact_upload_are_strict() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    workflow = yaml.safe_load(
        (repo_root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["backend-evaluation"]["steps"]
    by_name = {step.get("name"): step for step in steps if step.get("name")}

    required = by_name["Run mock detection evaluation (required gate)"]
    observe = by_name["Run mock detection fail-closed evaluation (observe gate)"]
    assert "continue-on-error" not in required
    assert "continue-on-error" not in observe
    assert observe.get("if") == "success() || failure()"
    for bypass in ("--allow-gate-fail", "|| true", "|| :", "set +e"):
        assert bypass not in required["run"]
    assert "--dataset-dir" in required["run"]
    assert "data/evaluation/detection_shadow_v1" in required["run"]
    assert "detection_shadow_v1_fail_closed" not in required["run"]
    assert "--allow-gate-fail" in observe["run"]
    assert (
        "data/evaluation/detection_shadow_v1_fail_closed/baseline_artifact.json" in observe["run"]
    )

    detection_upload = by_name["Upload required detection artifact"]
    assert detection_upload["if"] == "always()"
    assert detection_upload["with"]["if-no-files-found"] == "error"
    assert detection_upload["with"]["path"].strip() == (
        "artifacts/evaluation/detection_ci_run.json"
    )

    observe_upload = by_name["Upload detection fail-closed observe artifact"]
    assert observe_upload["if"] == "always()"
    assert observe_upload["with"]["if-no-files-found"] == "error"
    assert observe_upload["with"]["path"].strip() == (
        "artifacts/evaluation/detection_fail_closed_ci_run.json"
    )


@pytest.mark.evaluation
def test_format_evaluation_summary_includes_gate_and_policy() -> None:
    from types import SimpleNamespace

    from scripts.run_detection_evaluation import format_evaluation_summary

    threshold_path = (
        Path(__file__).resolve().parents[3]
        / "data"
        / "evaluation"
        / "detection_shadow_v1"
        / "threshold_manifest.json"
    )
    artifact = SimpleNamespace(
        status=SimpleNamespace(value="failed"),
        gate=SimpleNamespace(
            verdict=SimpleNamespace(value="fail_closed"),
            diffs=[SimpleNamespace(field="pass_rate", reason="pass_rate below manifest minimum")],
        ),
        aggregates=SimpleNamespace(pass_rate=0.66, required_scorer_error_count=2),
        artifact_hash="abc123",
    )
    summary = format_evaluation_summary(
        artifact=artifact,
        threshold_path=threshold_path,
        baseline_compare="failed",
        baseline_drift_count=3,
    )
    assert "**status**: `failed`" in summary
    assert "**gate_verdict**: `fail_closed`" in summary
    assert "**required_gate** (manifest): `True`" in summary
    assert "**execution_mode**: `required`" in summary
    assert "**baseline_compare**: `failed`" in summary
    assert "**baseline_drift_count**: `3`" in summary
    assert "pass_rate below manifest minimum" in summary


@pytest.mark.evaluation
def test_write_evaluation_summary_preserves_drift_failure_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from scripts.run_detection_evaluation import write_evaluation_summary

    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    artifact = SimpleNamespace(
        status=SimpleNamespace(value="failed"),
        gate=SimpleNamespace(verdict=SimpleNamespace(value="fail_closed"), diffs=[]),
        aggregates=SimpleNamespace(pass_rate=0.5, required_scorer_error_count=1),
        artifact_hash="drift-hash",
    )

    written = write_evaluation_summary(
        artifact=artifact,
        threshold_path=None,
        allow_gate_fail=True,
        baseline_compare="failed",
        baseline_drift_count=2,
    )

    assert written is True
    summary = summary_path.read_text(encoding="utf-8")
    assert "**execution_mode**: `observe`" in summary
    assert "**baseline_compare**: `failed`" in summary
    assert "**baseline_drift_count**: `2`" in summary
