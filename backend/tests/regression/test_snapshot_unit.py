"""Unit tests for SnapshotDiffer tolerances (ISSUE-087)."""

from __future__ import annotations

from tests.regression.snapshot import SnapshotDiffer


def _base_snapshot() -> dict:
    return {
        "final_verdict": "confirmed_threat",
        "risk_score": 82,
        "executed_actions": ["create_ticket", "isolate_host"],
        "trajectory_metrics": {"evidence_yield": 1.0, "steps_to_verdict": 10.0},
        "quality_scores": {"triage": 0.80, "risk": 0.75},
    }


def test_diff_zero_when_snapshots_match() -> None:
    baseline = _base_snapshot()
    drifts = SnapshotDiffer().diff(baseline, dict(baseline))
    assert drifts == []


def test_final_verdict_mismatch_is_block() -> None:
    current = _base_snapshot()
    current["final_verdict"] = "false_positive"
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert any(item.field == "final_verdict" and item.severity == "block" for item in drifts)


def test_executed_actions_mismatch_is_block() -> None:
    current = _base_snapshot()
    current["executed_actions"] = ["create_ticket"]
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert any(item.field == "executed_actions" and item.severity == "block" for item in drifts)


def test_risk_score_within_tolerance_passes() -> None:
    current = _base_snapshot()
    current["risk_score"] = 86
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert not SnapshotDiffer.blocking_drifts(drifts)


def test_risk_score_beyond_tolerance_blocks() -> None:
    current = _base_snapshot()
    current["risk_score"] = 88
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert any(item.field == "risk_score" and item.severity == "block" for item in drifts)


def test_trajectory_metric_drift_over_twenty_percent_is_warn_only() -> None:
    current = _base_snapshot()
    current["trajectory_metrics"] = {"evidence_yield": 0.7, "steps_to_verdict": 10.0}
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert not SnapshotDiffer.blocking_drifts(drifts)
    assert any(item.field == "trajectory_metrics.evidence_yield" for item in drifts)
    assert all(item.severity == "warn" for item in drifts)


def test_quality_score_drift_is_warn_only() -> None:
    current = _base_snapshot()
    current["quality_scores"] = {"triage": 0.60, "risk": 0.75}
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert not SnapshotDiffer.blocking_drifts(drifts)
    assert any(item.field == "quality_scores.triage" for item in drifts)
