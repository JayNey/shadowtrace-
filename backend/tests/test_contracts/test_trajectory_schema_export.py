"""Trajectory contract schema export tests (ISSUE-178 / #712)."""

from __future__ import annotations

import json
from pathlib import Path

from app.models import MODEL_REGISTRY
from app.models.trajectory import TrajectoryReport

CONTRACTS = Path(__file__).resolve().parents[3] / "contracts" / "schemas"


def test_trajectory_report_registered() -> None:
    """TrajectoryReport must be present in MODEL_REGISTRY."""
    assert "TrajectoryReport" in MODEL_REGISTRY
    assert MODEL_REGISTRY["TrajectoryReport"] is TrajectoryReport


def test_committed_trajectory_report_schema_matches_model() -> None:
    """Committed contracts/schemas/TrajectoryReport.json must match the live model."""
    path = CONTRACTS / "TrajectoryReport.json"
    assert path.is_file(), "missing contract schema TrajectoryReport.json"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = TrajectoryReport.model_json_schema(mode="serialization")
    assert committed == current


def test_trajectory_report_insufficient_trace_semantic_preserved() -> None:
    """insufficient_trace field must remain — it is a deliberate UX soft-return.

    Removing or renaming it would break the API contract for events with
    no recorded trajectory.
    """
    schema = TrajectoryReport.model_json_schema(mode="serialization")
    props = schema.get("properties", {})
    assert "insufficient_trace" in props
    assert props["insufficient_trace"]["type"] == "boolean"
    assert props["insufficient_trace"].get("default") is False


def test_trajectory_report_event_id_required() -> None:
    """event_id is the only required field (others have defaults)."""
    schema = TrajectoryReport.model_json_schema(mode="serialization")
    assert schema.get("required") == ["event_id"]
