"""AgentTask contract schema export tests (ISSUE-133)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models.agent_task import (
    AgentArtifact,
    AgentTask,
    AgentTaskAttemptRecord,
    AgentTaskClaim,
    AgentTaskContextRef,
    AgentTaskEnqueueRequest,
    AgentTaskGoal,
    ContentProjection,
)

CONTRACTS = Path(__file__).resolve().parents[3] / "contracts" / "schemas"


def test_agent_task_goal_schema_exports_grant_binding_field() -> None:
    schema = AgentTaskGoal.model_json_schema(mode="serialization")
    props = schema.get("properties", {})
    assert "tool_call_grant_id" in props
    assert "task_type" in props
    assert "context_refs" in props


@pytest.mark.parametrize(
    ("model_cls", "schema_file"),
    [
        (AgentTask, "AgentTask.json"),
        (AgentArtifact, "AgentArtifact.json"),
        (AgentTaskClaim, "AgentTaskClaim.json"),
        (AgentTaskGoal, "AgentTaskGoal.json"),
        (AgentTaskContextRef, "AgentTaskContextRef.json"),
        (ContentProjection, "ContentProjection.json"),
        (AgentTaskEnqueueRequest, "AgentTaskEnqueueRequest.json"),
        (AgentTaskAttemptRecord, "AgentTaskAttemptRecord.json"),
    ],
)
def test_committed_agent_task_schemas_match_models(
    model_cls: type,
    schema_file: str,
) -> None:
    path = CONTRACTS / schema_file
    assert path.is_file(), f"missing contract schema {schema_file}"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = model_cls.model_json_schema(mode="serialization")
    assert committed == current
