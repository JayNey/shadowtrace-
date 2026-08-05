"""Unit tests for graph checkpoint resume helpers (ISSUE-192)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.orchestration.graph_resume import resume_investigation_from_checkpoint


@pytest.mark.asyncio
async def test_resume_skips_full_restart_when_checkpoint_missing() -> None:
    """ISSUE-192: missing checkpoint must not call investigate() full restart."""
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

    session_factory = MagicMock()

    await resume_investigation_from_checkpoint(
        session_factory,
        "evt-no-checkpoint",
        get_super_agent=_get_super_agent,
        get_workflow_runtime=_get_runtime,
    )

    agent.investigate.assert_not_called()
    graph.ainvoke.assert_not_called()
