"""Unit tests for graph checkpoint resume helpers (ISSUE-192 / ISSUE-196)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.enums import EventStatus, ExecutionSubstate, WritebackStatus
from app.orchestration.graph_resume import (
    _reconcile_verify_resume_patch,
    resume_investigation_from_checkpoint,
)
from app.orchestration.graph_resume_observability import GraphResumeFailedError


class _SessionFactory:
    def __init__(
        self,
        status: str,
        *,
        outbox_wb_statuses: list[str | None] | None = None,
    ) -> None:
        self._status = status
        self._outbox_wb_statuses = outbox_wb_statuses or []

    def __call__(self) -> _SessionCtx:
        return _SessionCtx(self._status, outbox_wb_statuses=self._outbox_wb_statuses)


class _OutboxScalars:
    def __init__(self, statuses: list[str | None]) -> None:
        self._statuses = statuses

    def __iter__(self) -> Any:
        return iter(self._statuses)


class _ScalarSession:
    def __init__(
        self,
        status: str,
        *,
        outbox_wb_statuses: list[str | None] | None = None,
    ) -> None:
        self._status = status
        self._outbox_wb_statuses = outbox_wb_statuses or []

    async def scalar(self, _stmt: Any) -> str:
        return self._status

    async def scalars(self, _stmt: Any) -> _OutboxScalars:
        return _OutboxScalars(self._outbox_wb_statuses)


class _SessionCtx:
    def __init__(
        self,
        status: str,
        *,
        outbox_wb_statuses: list[str | None] | None = None,
    ) -> None:
        self._status = status
        self._outbox_wb_statuses = outbox_wb_statuses

    async def __aenter__(self) -> _ScalarSession:
        return _ScalarSession(
            self._status,
            outbox_wb_statuses=self._outbox_wb_statuses,
        )

    async def __aexit__(self, *_args: Any) -> None:
        return None


@pytest.mark.asyncio
async def test_reconcile_verify_resume_clears_stale_manual_when_writeback_confirmed() -> None:
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_wb_statuses=[WritebackStatus.CONFIRMED.value],
        ),
        "evt-196",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "verify_need_writeback_recovery": False,
            "verify_failed_writebacks": [],
            "degraded_flags": ["verify_degraded=True"],
        },
    )
    assert patch["halted"] is False
    assert patch["verify_need_manual_resolution"] is False
    assert patch["execution_substate"] == ExecutionSubstate.NONE.value
    assert "verify_degraded=True" not in patch.get("degraded_flags", [])


@pytest.mark.asyncio
async def test_reconcile_verify_resume_keeps_legitimate_manual_hold() -> None:
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_wb_statuses=[WritebackStatus.CONFIRMED.value],
        ),
        "evt-196-legit",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "degraded_flags": ["missing_response_plan_for_required_policy=True"],
        },
    )
    assert patch.get("halted") is False
    assert "verify_need_manual_resolution" not in patch


@pytest.mark.asyncio
async def test_reconcile_verify_resume_keeps_manual_when_no_outbox() -> None:
    """ISSUE-196: verify_degraded without outbox evidence must stay manual."""
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_wb_statuses=[],
        ),
        "evt-196-no-outbox",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "verify_need_writeback_recovery": False,
            "verify_failed_writebacks": [],
            "degraded_flags": ["verify_degraded=True"],
        },
    )
    assert patch.get("halted") is False
    assert patch.get("verify_need_manual_resolution") is not False


@pytest.mark.asyncio
async def test_reconcile_verify_resume_clears_stale_manual_when_writeback_accepted() -> None:
    """ISSUE-196: ACCEPTED outbox is sufficient to resume toward REPORTING."""
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_wb_statuses=[WritebackStatus.ACCEPTED.value],
        ),
        "evt-196-accepted",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "verify_need_writeback_recovery": False,
            "verify_failed_writebacks": [],
            "degraded_flags": ["verify_degraded=True"],
        },
    )
    assert patch["halted"] is False
    assert patch["verify_need_manual_resolution"] is False


@pytest.mark.asyncio
async def test_resume_raises_when_checkpoint_missing_mid_flight() -> None:
    """ISSUE-193: lost checkpoint during pause surfaces GraphResumeFailedError."""
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

    with pytest.raises(GraphResumeFailedError) as exc_info:
        await resume_investigation_from_checkpoint(
            session_factory,
            "evt-no-checkpoint",
            get_super_agent=_get_super_agent,
            get_workflow_runtime=_get_runtime,
        )

    assert exc_info.value.error_type == "checkpoint_missing"
    agent.investigate.assert_not_called()
    graph.ainvoke.assert_not_called()


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
