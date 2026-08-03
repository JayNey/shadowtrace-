"""AgentTask service wiring tests (ISSUE-133)."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.api.v1 import deps
from app.services.agent_artifact_service import AgentArtifactService
from app.services.agent_task_service import AgentTaskService
from app.services.content_projection_service import ContentProjectionService


def test_reset_deps_clears_agent_task_singletons(monkeypatch) -> None:
    monkeypatch.setattr(deps, "_get_session_factory", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_tool_call_grant_service", lambda: MagicMock())

    deps.reset_deps()
    task_svc = deps._get_agent_task_service()
    artifact_svc = deps._get_agent_artifact_service()
    projection_svc = deps._get_content_projection_service()

    assert isinstance(task_svc, AgentTaskService)
    assert isinstance(artifact_svc, AgentArtifactService)
    assert isinstance(projection_svc, ContentProjectionService)

    deps.reset_deps()
    task_svc_2 = deps._get_agent_task_service()
    assert task_svc is not task_svc_2
