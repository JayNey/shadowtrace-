"""Shadow run contract schema export tests (ISSUE-135 / #641 Phase A)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models import MODEL_REGISTRY
from app.models.shadow_run import (
    ShadowQueryArtifact,
    ShadowQueryPivotRequest,
    ShadowQueryPivotResult,
    ShadowRun,
    ShadowRunProvenance,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "contracts" / "schemas"


def test_shadow_run_contract_models_are_registered() -> None:
    expected = {
        "ShadowRun",
        "ShadowRunProvenance",
        "ShadowQueryArtifact",
        "ShadowQueryPivotRequest",
        "ShadowQueryPivotResult",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


@pytest.mark.parametrize(
    ("model_cls", "schema_file"),
    [
        (ShadowRun, "ShadowRun.json"),
        (ShadowRunProvenance, "ShadowRunProvenance.json"),
        (ShadowQueryArtifact, "ShadowQueryArtifact.json"),
        (ShadowQueryPivotRequest, "ShadowQueryPivotRequest.json"),
        (ShadowQueryPivotResult, "ShadowQueryPivotResult.json"),
    ],
)
def test_committed_shadow_run_schemas_match_models(
    model_cls: type,
    schema_file: str,
) -> None:
    path = SCHEMA_DIR / schema_file
    assert path.is_file(), f"missing committed schema: {path}"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = model_cls.model_json_schema(mode="serialization")
    assert committed == current


def test_shadow_run_schema_exports_core_fields() -> None:
    schema = ShadowRun.model_json_schema(mode="serialization")
    properties = schema.get("properties", {})
    for field in (
        "shadow_run_id",
        "event_id",
        "tenant_id",
        "namespace_key",
        "status",
        "retention_expires_at",
    ):
        assert field in properties
