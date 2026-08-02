"""ToolCallGrant contract schema export tests (ISSUE-134)."""

from __future__ import annotations

from app.models import MODEL_REGISTRY


def test_tool_call_grant_contract_models_are_registered() -> None:
    expected = {
        "ToolCallGrant",
        "ToolCallGrantScope",
        "BoundExecutionPrincipal",
        "ToolCallAttemptRecord",
        "SafeToolProjection",
    }
    assert expected <= set(MODEL_REGISTRY.keys())
