"""Detection promotion contract schema export tests (ISSUE-124 / #629)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models.detection_promotion import (
    DerivedDetectionConnectorRecord,
    DetectionPromotionRecord,
    DetectionPromotionRequest,
    DetectionPromotionResult,
    TypedIngestResult,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "contracts" / "schemas"


@pytest.mark.parametrize(
    ("model_cls", "schema_file"),
    [
        (TypedIngestResult, "TypedIngestResult.json"),
        (DetectionPromotionRequest, "DetectionPromotionRequest.json"),
        (DetectionPromotionRecord, "DetectionPromotionRecord.json"),
        (DetectionPromotionResult, "DetectionPromotionResult.json"),
        (DerivedDetectionConnectorRecord, "DerivedDetectionConnectorRecord.json"),
    ],
)
def test_committed_detection_promotion_schemas_match_models(
    model_cls: type,
    schema_file: str,
) -> None:
    path = SCHEMA_DIR / schema_file
    assert path.is_file(), f"missing committed schema: {path}"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = model_cls.model_json_schema(mode="serialization")
    assert committed == current
