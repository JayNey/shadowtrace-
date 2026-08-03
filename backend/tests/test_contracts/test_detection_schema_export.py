"""Detection evaluation contract schema export tests (ISSUE-126)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models import MODEL_REGISTRY
from app.models.detection_evaluation import (
    DetectionCandidateRefs,
    DetectionCaseObservation,
    DetectionCaseResult,
    DetectionEvaluationArtifact,
    DetectionEvaluationConfig,
    DetectionResourceMetrics,
    DetectionResourceSummary,
    DetectionTenantSafetyProbe,
    DetectionTenantSafetySummary,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "contracts" / "schemas"


def test_detection_evaluation_models_are_registered() -> None:
    expected = {
        "DetectionEvaluationArtifact",
        "DetectionEvaluationConfig",
        "DetectionCandidateRefs",
        "DetectionCaseObservation",
        "DetectionCaseResult",
        "DetectionResourceMetrics",
        "DetectionResourceSummary",
        "DetectionTenantSafetyProbe",
        "DetectionTenantSafetySummary",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


@pytest.mark.parametrize(
    ("model_cls", "schema_file"),
    [
        (DetectionEvaluationArtifact, "DetectionEvaluationArtifact.json"),
        (DetectionEvaluationConfig, "DetectionEvaluationConfig.json"),
        (DetectionCandidateRefs, "DetectionCandidateRefs.json"),
        (DetectionCaseObservation, "DetectionCaseObservation.json"),
        (DetectionCaseResult, "DetectionCaseResult.json"),
        (DetectionResourceMetrics, "DetectionResourceMetrics.json"),
        (DetectionResourceSummary, "DetectionResourceSummary.json"),
        (DetectionTenantSafetyProbe, "DetectionTenantSafetyProbe.json"),
        (DetectionTenantSafetySummary, "DetectionTenantSafetySummary.json"),
    ],
)
def test_committed_detection_schemas_match_models(
    model_cls: type,
    schema_file: str,
) -> None:
    path = SCHEMA_DIR / schema_file
    assert path.is_file(), f"missing committed schema: {path}"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = model_cls.model_json_schema(mode="serialization")
    assert committed == current


def test_shipped_threshold_manifest_requires_gate_fail_closed() -> None:
    from app.evaluation.threshold import load_threshold_manifest

    dataset_dir = REPO_ROOT / "data" / "evaluation" / "detection_shadow_v1"
    manifest = load_threshold_manifest(dataset_dir / "threshold_manifest.json")
    assert manifest.required_gate is True
