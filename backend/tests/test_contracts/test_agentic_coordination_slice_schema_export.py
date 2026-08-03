"""Agentic/coordination slice contract schema export tests (ISSUE-136 / #642 Phase B/C)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models import MODEL_REGISTRY
from app.models.evaluation_run import AgenticCaseObservation, CoordinationCaseObservation
from app.models.evaluation_truth import AgenticSliceExpectation, CoordinationSliceExpectation

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "contracts" / "schemas"


def test_agentic_coordination_contract_models_are_registered() -> None:
    expected = {
        "AgenticSliceExpectation",
        "CoordinationSliceExpectation",
        "AgenticCaseObservation",
        "CoordinationCaseObservation",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


@pytest.mark.parametrize(
    ("model_cls", "schema_file"),
    [
        (AgenticSliceExpectation, "AgenticSliceExpectation.json"),
        (CoordinationSliceExpectation, "CoordinationSliceExpectation.json"),
        (AgenticCaseObservation, "AgenticCaseObservation.json"),
        (CoordinationCaseObservation, "CoordinationCaseObservation.json"),
    ],
)
def test_committed_agentic_coordination_schemas_match_models(
    model_cls: type,
    schema_file: str,
) -> None:
    path = SCHEMA_DIR / schema_file
    assert path.is_file(), f"missing committed schema: {path}"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = model_cls.model_json_schema(mode="serialization")
    assert committed == current
