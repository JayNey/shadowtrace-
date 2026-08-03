"""Detection production comparison contract schema export tests (ISSUE-126 Phase B)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models import MODEL_REGISTRY
from app.models.detection_production_comparison import (
    DetectionProductionBindingManifest,
    DetectionProductionCaseBinding,
    DetectionProductionCaseComparison,
    DetectionProductionComparisonArtifact,
    DetectionProductionComparisonConfig,
    DetectionProductionCoverageDrift,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "contracts" / "schemas"


def test_detection_production_comparison_models_are_registered() -> None:
    expected = {
        "DetectionProductionComparisonArtifact",
        "DetectionProductionComparisonConfig",
        "DetectionProductionCaseBinding",
        "DetectionProductionCaseComparison",
        "DetectionProductionBindingManifest",
        "DetectionProductionCoverageDrift",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


@pytest.mark.parametrize(
    ("model_cls", "schema_file"),
    [
        (DetectionProductionComparisonArtifact, "DetectionProductionComparisonArtifact.json"),
        (DetectionProductionComparisonConfig, "DetectionProductionComparisonConfig.json"),
        (DetectionProductionCaseBinding, "DetectionProductionCaseBinding.json"),
        (DetectionProductionCaseComparison, "DetectionProductionCaseComparison.json"),
        (DetectionProductionBindingManifest, "DetectionProductionBindingManifest.json"),
        (DetectionProductionCoverageDrift, "DetectionProductionCoverageDrift.json"),
    ],
)
def test_committed_detection_production_schemas_match_models(
    model_cls: type,
    schema_file: str,
) -> None:
    path = SCHEMA_DIR / schema_file
    assert path.is_file(), f"missing committed schema: {path}"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = model_cls.model_json_schema(mode="serialization")
    assert committed == current
