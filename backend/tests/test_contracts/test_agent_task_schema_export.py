"""AgentTask contract schema export tests (ISSUE-133)."""

from __future__ import annotations

import json
from pathlib import Path

from app.models.agent_task import (
    AgentArtifact,
    AgentTask,
    AgentTaskClaim,
    AgentTaskContextRef,
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


def test_committed_agent_task_goal_schema_matches_model() -> None:
    path = CONTRACTS / "AgentTaskGoal.json"
    committed = json.loads(path.read_text(encoding="utf-8"))
    live = AgentTaskGoal.model_json_schema(mode="serialization")
    assert committed.get("title") == live.get("title")
    for field in ("task_type", "context_refs", "parameters", "tool_call_grant_id"):
        assert field in committed.get("properties", {})
        assert field in live.get("properties", {})


def test_agent_task_schema_files_exist_and_validate() -> None:
    models = [
        (AgentTask, "AgentTask.json"),
        (AgentArtifact, "AgentArtifact.json"),
        (AgentTaskClaim, "AgentTaskClaim.json"),
        (AgentTaskGoal, "AgentTaskGoal.json"),
        (AgentTaskContextRef, "AgentTaskContextRef.json"),
        (ContentProjection, "ContentProjection.json"),
    ]
    for model, filename in models:
        path = CONTRACTS / filename
        assert path.is_file(), f"missing contract schema {filename}"
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema.get("title") == model.__name__
