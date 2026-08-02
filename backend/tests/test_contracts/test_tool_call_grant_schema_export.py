"""ToolCallGrant contract schema export tests (ISSUE-134)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models import MODEL_REGISTRY
from app.models.tool_call_grant import (
    BoundExecutionPrincipal,
    SafeToolProjection,
    ToolCallAttemptRecord,
    ToolCallGrant,
    ToolCallGrantScope,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "contracts" / "schemas"


def test_tool_call_grant_contract_models_are_registered() -> None:
    expected = {
        "ToolCallGrant",
        "ToolCallGrantScope",
        "BoundExecutionPrincipal",
        "ToolCallAttemptRecord",
        "SafeToolProjection",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


@pytest.mark.parametrize(
    ("model_cls", "schema_file"),
    [
        (ToolCallGrant, "ToolCallGrant.json"),
        (ToolCallGrantScope, "ToolCallGrantScope.json"),
        (BoundExecutionPrincipal, "BoundExecutionPrincipal.json"),
        (ToolCallAttemptRecord, "ToolCallAttemptRecord.json"),
        (SafeToolProjection, "SafeToolProjection.json"),
    ],
)
def test_committed_tool_call_grant_schemas_match_models(
    model_cls: type,
    schema_file: str,
) -> None:
    """Committed JSON schemas must stay aligned with pydantic models."""
    path = SCHEMA_DIR / schema_file
    assert path.is_file(), f"missing committed schema: {path}"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = model_cls.model_json_schema(mode="serialization")
    assert committed == current


def test_tool_call_grant_schema_exports_core_fields() -> None:
    schema = ToolCallGrant.model_json_schema(mode="serialization")
    properties = schema.get("properties", {})
    for field in (
        "grant_id",
        "mode",
        "namespace_key",
        "event_id",
        "scope",
        "execution_principal",
        "max_calls",
        "policy_version",
    ):
        assert field in properties
