"""Unit tests for graph checkpoint resume helpers (ISSUE-192)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.enums import EventStatus
from app.orchestration.graph_resume import resume_investigation_from_checkpoint


class _ScalarSession:
    def __init__(self, status: str) -> None:
        self._status = status

    async def scalar(self, _stmt: Any) -> str:
        return self._status


class _SessionCtx:
    def __init__(self, status: str) -> None:
        self._status = status

    async def __aenter__(self) -> _ScalarSession:
        return _ScalarSession(self._status)

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _SessionFactory:
    def __init__(self, status: str) -> None:
        self._status = status

    def __call__(self) -> _SessionCtx:
        return _SessionCtx(self._status)


@pytest.mark.asyncio
async def test_resume_skips_full_restart_when_checkpoint_missing_mid_flight() -> None:
    """ISSUE-192: lost checkpoint during pause must not call investigate() restart."""
    graph = MagicMock()
    graph.aget_state = AsyncMock(return_value=MagicMock(values={}))
    agent = MagicMock()
    agent._investigation_graph = graph
    agent.investigate = AsyncMock()

    async def _get_super_agent() -> Any:
        return agent

    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock()

    async def _get_runtime() -> Any:
        return runtime

    session_factory = _SessionFactory(EventStatus.EXECUTING_RESPONSE.value)

    with patch(
        "app.tasks.investigation_tasks.execute_investigation",
        new_callable=AsyncMock,
    ) as execute:
        await resume_investigation_from_checkpoint(
            session_factory,
            "evt-no-checkpoint",
            get_super_agent=_get_super_agent,
            get_workflow_runtime=_get_runtime,
        )

    agent.investigate.assert_not_called()
    graph.ainvoke.assert_not_called()
    execute.assert_not_called()


@pytest.mark.asyncio
async def test_resume_fallback_execute_investigation_when_graph_never_started() -> None:
    """ISSUE-192: no checkpoint + NEW status may delegate to Celery investigate task."""
    graph = MagicMock()
    graph.aget_state = AsyncMock(return_value=MagicMock(values={}))
    agent = MagicMock()
    agent._investigation_graph = graph

    async def _get_super_agent() -> Any:
        return agent

    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock()

    async def _get_runtime() -> Any:
        return runtime

    session_factory = _SessionFactory(EventStatus.NEW.value)

    with (
        patch(
            "app.services.investigation_guidance.resolve_include_response_execution_for_resume",
            new_callable=AsyncMock,
            return_value=True,
        ) as resolve_include,
        patch(
            "app.tasks.investigation_tasks.execute_investigation",
            new_callable=AsyncMock,
        ) as execute,
    ):
        await resume_investigation_from_checkpoint(
            session_factory,
            "evt-never-started",
            get_super_agent=_get_super_agent,
            get_workflow_runtime=_get_runtime,
        )

    resolve_include.assert_awaited_once()
    execute.assert_awaited_once_with(
        "evt-never-started",
        include_response_execution=True,
    )
    graph.ainvoke.assert_not_called()
