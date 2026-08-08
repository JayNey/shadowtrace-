"""EventContext / InvestigationReport contract schema export tests (ISSUE-265 / #861)."""

from __future__ import annotations

import json
from pathlib import Path

from app.models.context import EventContext
from app.models.report import InvestigationReport

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "contracts" / "schemas"


def _load_committed_schema(name: str) -> dict:
    path = SCHEMA_DIR / f"{name}.json"
    assert path.is_file(), f"missing committed schema: {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def test_event_context_committed_schema_matches_serialization_export() -> None:
    committed = _load_committed_schema("EventContext")
    current = EventContext.model_json_schema(mode="serialization")
    assert committed == current
    assert {
        "classification_override",
        "detection_context_snapshot",
        "memory_output_early",
        "report_generated",
    } <= set(committed["properties"])


def test_investigation_report_committed_schema_includes_degraded() -> None:
    committed = _load_committed_schema("InvestigationReport")
    current = InvestigationReport.model_json_schema(mode="serialization")
    assert committed == current
    assert "degraded" in committed["properties"]
    assert "degraded" in committed["required"]

