"""Detection context snapshot contract schema export tests (ISSUE-127 / #633)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.api.v1 import schemas as api_schemas
from app.models.context import EventContext
from app.models.detection_context_snapshot import (
    DetectionContextSnapshot,
    DetectionContextSnapshotRef,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "contracts" / "schemas"


@pytest.mark.parametrize(
    ("model_cls", "schema_file"),
    [
        (DetectionContextSnapshot, "DetectionContextSnapshot.json"),
        (DetectionContextSnapshotRef, "DetectionContextSnapshotRef.json"),
    ],
)
def test_committed_detection_context_schemas_match_models(
    model_cls: type,
    schema_file: str,
) -> None:
    path = SCHEMA_DIR / schema_file
    assert path.is_file(), f"missing committed schema: {path}"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = model_cls.model_json_schema(mode="serialization")
    assert committed == current


def test_event_context_schema_includes_detection_context_snapshot_field() -> None:
    path = SCHEMA_DIR / "EventContext.json"
    assert path.is_file(), f"missing committed schema: {path}"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = EventContext.model_json_schema(mode="serialization")
    assert committed == current


@pytest.mark.parametrize(
    ("model_cls", "schema_file"),
    [
        (api_schemas.DetectionContextSnapshotSummary, "DetectionContextSnapshotSummary.json"),
        (
            api_schemas.DetectionContextProjectionErrorSummary,
            "DetectionContextProjectionErrorSummary.json",
        ),
    ],
)
def test_committed_detection_context_api_summary_schemas_match_models(
    model_cls: type,
    schema_file: str,
) -> None:
    path = SCHEMA_DIR / schema_file
    assert path.is_file(), f"missing committed schema: {path}"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = model_cls.model_json_schema(mode="serialization")
    assert committed == current
