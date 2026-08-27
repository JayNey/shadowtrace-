"""Unit tests for graph resume failure observability (ISSUE-193)."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.errors import InvalidStateTransitionError, ValidationError
from app.models.enums import ActionStatus, EventStatus
from app.orchestration.graph_resume_observability import (
    GRAPH_RESUME_FAILED_FLAG,
    GraphResumeDeferredError,
    GraphResumeFailedError,
    GraphResumeFailureContext,
    execute_graph_resume_with_retry,
    record_graph_resume_failure,
)
from app.services.approval_engine import ApprovalEngine


def _fresh_event_lease() -> Any:
    from app.orchestration.lease import EventLease
    from tests.support.fake_redis import InMemoryFakeRedisClient

    return EventLease(InMemoryFakeRedisClient())


class _BeginCtx:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _ScalarSession:
    def __init__(self, status: str) -> None:
        self._status = status

    def begin(self) -> _BeginCtx:
        return _BeginCtx()

    async def scalar(self, _stmt: Any) -> str:
        return self._status

    async def scalars(self, _stmt: Any) -> Any:
        class _Empty:
            def all(self) -> list[Any]:
                return []

        return _Empty()

    def add(self, _row: Any) -> None:
        return None

    async def get(self, _model: Any, _key: str) -> MagicMock:
        row = MagicMock()
        row.degraded_flags = []
        return row


class _SessionCtx:
    def __init__(self, status: str) -> None:
        self._status = status

    async def __aenter__(self) -> _ScalarSession:
        return _ScalarSession(self._status)

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _SessionFactory:
    def __init__(self, status: str = EventStatus.EXECUTING_RESPONSE.value) -> None:
        self._status = status

    def __call__(self) -> _SessionCtx:
        return _SessionCtx(self._status)


@pytest.mark.asyncio
async def test_execute_graph_resume_records_degraded_and_raises() -> None:
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=["graph_resume_failed=checkpoint_missing"])
    degraded.has_flag = AsyncMock(return_value=False)

    graph = MagicMock()
    graph.aget_state = AsyncMock(return_value=MagicMock(values={}))
    agent = MagicMock()
    agent._investigation_graph = graph
    agent.lease = _fresh_event_lease()

    async def _get_super_agent() -> Any:
        return agent

    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock()

    async def _get_runtime() -> Any:
        return runtime

    session_factory = _SessionFactory()

    with pytest.raises(GraphResumeFailedError) as exc_info:
        await execute_graph_resume_with_retry(
            "evt-resume-fail",
            session_factory=session_factory,
            get_super_agent=_get_super_agent,
            get_workflow_runtime=_get_runtime,
            degraded_flags=degraded,
        )

    assert exc_info.value.error_type == "checkpoint_missing"
    degraded.set_flag.assert_awaited_once()
    call = degraded.set_flag.await_args
    assert call is not None
    assert call.args[1] == GRAPH_RESUME_FAILED_FLAG


@pytest.mark.asyncio
async def test_reporting_checkpoint_missing_keeps_status_reporting() -> None:
    """ISSUE-247: checkpoint_missing on REPORTING must not mark the event FAILED."""
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=["graph_resume_failed=checkpoint_missing"])
    degraded.has_flag = AsyncMock(return_value=False)

    graph = MagicMock()
    graph.aget_state = AsyncMock(return_value=MagicMock(values={}))
    agent = MagicMock()
    agent._investigation_graph = graph
    agent.lease = _fresh_event_lease()
    factory = _SessionFactory(EventStatus.REPORTING.value)

    with pytest.raises(GraphResumeFailedError) as exc_info:
        await execute_graph_resume_with_retry(
            "evt-247-keep-reporting",
            session_factory=factory,
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(
                return_value=MagicMock(set_execution_substate=AsyncMock())
            ),
            degraded_flags=degraded,
        )

    assert exc_info.value.error_type == "checkpoint_missing"
    # Observability records degraded/audit in-place; status stays REPORTING.
    assert factory._status == EventStatus.REPORTING.value
    degraded.set_flag.assert_awaited_once()


@pytest.mark.asyncio
async def test_execute_graph_resume_retries_transient_errors() -> None:
    degraded = MagicMock()
    degraded.has_flag = AsyncMock(return_value=False)
    degraded.set_flag = AsyncMock()
    graph = MagicMock()
    call_count = 0

    async def _aget_state(_config: dict[str, Any]) -> MagicMock:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise TimeoutError("redis read timeout")
        return MagicMock(
            values={
                "halted": False,
                "event_status": EventStatus.EXECUTING_RESPONSE.value,
            }
        )

    graph.aget_state = _aget_state
    graph.aupdate_state = AsyncMock()
    graph.ainvoke = AsyncMock(return_value={"halted": False})
    from app.orchestration.lease import EventLease
    from tests.support.fake_redis import InMemoryFakeRedisClient

    agent = MagicMock()
    agent._investigation_graph = graph
    agent.lease = EventLease(InMemoryFakeRedisClient())

    async def _get_super_agent() -> Any:
        return agent

    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock()

    async def _get_runtime() -> Any:
        return runtime

    await execute_graph_resume_with_retry(
        "evt-retry",
        session_factory=_SessionFactory(),
        get_super_agent=_get_super_agent,
        get_workflow_runtime=_get_runtime,
        degraded_flags=degraded,
    )

    assert call_count == 3
    degraded.set_flag.assert_not_awaited()


@pytest.mark.asyncio
async def test_approve_returns_resume_failed_without_rollback() -> None:
    async def _failing_resume(_event_id: str) -> None:
        raise GraphResumeFailedError(
            "invalid transition",
            event_id=_event_id,
            error_type="invalid_state_transition",
        )

    engine = ApprovalEngine(
        MagicMock(),
        resume_investigation=_failing_resume,
    )
    engine.is_plan_fully_decided = AsyncMock(return_value=True)  # type: ignore[method-assign]
    engine._load_plan_response_actions = AsyncMock(return_value=[MagicMock(status=MagicMock())])  # type: ignore[method-assign]
    engine._event_status = AsyncMock(return_value=EventStatus.WAITING_APPROVAL)  # type: ignore[method-assign]
    engine._state_machine = None

    status = await engine._maybe_advance_plan("evt-1", 1)
    assert status == "failed"


@pytest.mark.asyncio
async def test_maybe_advance_plan_still_resumes_after_transition_error() -> None:
    from app.models.enums import ActionStatus

    resume = AsyncMock()
    engine = ApprovalEngine(MagicMock(), resume_investigation=resume)
    engine.is_plan_fully_decided = AsyncMock(return_value=True)  # type: ignore[method-assign]
    approved = MagicMock()
    approved.status = ActionStatus.APPROVED
    approved.tool_name = "block_ip"
    approved.writeback_required = False
    engine._load_plan_response_actions = AsyncMock(return_value=[approved])  # type: ignore[method-assign]
    engine._event_status = AsyncMock(return_value=EventStatus.WAITING_APPROVAL)  # type: ignore[method-assign]
    machine = MagicMock()
    machine.transition = AsyncMock(side_effect=RuntimeError("cas conflict"))
    engine._state_machine = machine

    status = await engine._maybe_advance_plan("evt-transition-err", 1)

    assert status == "ok"
    resume.assert_awaited_once_with("evt-transition-err")


@pytest.mark.asyncio
async def test_maybe_advance_plan_returns_skipped_without_resume_hook() -> None:
    engine = ApprovalEngine(MagicMock(), resume_investigation=None)
    engine.is_plan_fully_decided = AsyncMock(return_value=True)  # type: ignore[method-assign]
    engine._load_plan_response_actions = AsyncMock(return_value=[MagicMock(status=MagicMock())])  # type: ignore[method-assign]
    engine._event_status = AsyncMock(return_value=EventStatus.WAITING_APPROVAL)  # type: ignore[method-assign]
    engine._state_machine = None

    status = await engine._maybe_advance_plan("evt-skipped", 1)
    assert status == "skipped"


@pytest.mark.asyncio
async def test_record_graph_resume_failure_uses_error_type_in_flag() -> None:
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=[])

    await record_graph_resume_failure(
        _SessionFactory(),
        degraded,
        GraphResumeFailureContext(
            event_id="evt-audit",
            error_type="invalid_state_transition",
            message="bad transition",
            execution_substate="waiting_approval",
        ),
    )

    degraded.set_flag.assert_awaited_once()
    call = degraded.set_flag.await_args
    assert call is not None
    assert call.kwargs["writer"] == "GraphResumeService"
    assert "invalid_state_transition" in str(call.args[2])


@pytest.mark.asyncio
async def test_execute_graph_resume_classifies_invalid_transition() -> None:
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=[])
    degraded.has_flag = AsyncMock(return_value=False)
    exc = InvalidStateTransitionError(
        "bad transition",
        current=EventStatus.EXECUTING_RESPONSE.value,
        target=EventStatus.COLLECTING_EVIDENCE.value,
    )
    agent = MagicMock()
    agent._investigation_graph = MagicMock(aget_state=AsyncMock(side_effect=exc))
    agent.lease = _fresh_event_lease()

    with pytest.raises(GraphResumeFailedError) as exc_info:
        await execute_graph_resume_with_retry(
            "evt-invalid",
            session_factory=_SessionFactory(),
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=MagicMock()),
            degraded_flags=degraded,
        )

    assert exc_info.value.error_type == "invalid_state_transition"
    degraded.set_flag.assert_awaited_once()


@pytest.mark.asyncio
async def test_execute_graph_resume_skips_nested_active_graph() -> None:
    agent = MagicMock()
    agent._investigation_graph = MagicMock()

    async def _get_super_agent() -> Any:
        return agent

    from app.orchestration.graph_invocation import (
        bind_investigation_graph,
        get_nested_resume_runner,
        set_nested_resume_runner,
    )

    previous = get_nested_resume_runner()
    set_nested_resume_runner(AsyncMock())
    try:
        async with bind_investigation_graph("evt-nested"):
            with pytest.raises(GraphResumeDeferredError) as exc_info:
                await execute_graph_resume_with_retry(
                    "evt-nested",
                    session_factory=_SessionFactory(),
                    get_super_agent=_get_super_agent,
                    get_workflow_runtime=AsyncMock(return_value=MagicMock()),
                    degraded_flags=MagicMock(),
                )
            assert exc_info.value.error_type == "graph_still_bound"
    finally:
        set_nested_resume_runner(previous)

    agent._investigation_graph.aget_state.assert_not_called()


@pytest.mark.asyncio
async def test_execute_graph_resume_flushes_nested_defer_after_unbind() -> None:
    flushed: list[str] = []

    async def _runner(event_id: str) -> None:
        flushed.append(event_id)

    from app.orchestration.graph_invocation import (
        bind_investigation_graph,
        get_nested_resume_runner,
        set_nested_resume_runner,
    )

    previous = get_nested_resume_runner()
    set_nested_resume_runner(_runner)
    try:
        async with bind_investigation_graph("evt-nested-flush"):
            with pytest.raises(GraphResumeDeferredError) as exc_info:
                await execute_graph_resume_with_retry(
                    "evt-nested-flush",
                    session_factory=_SessionFactory(),
                    get_super_agent=AsyncMock(),
                    get_workflow_runtime=AsyncMock(),
                    degraded_flags=MagicMock(),
                )
            assert exc_info.value.error_type == "graph_still_bound"
            assert flushed == []
        assert flushed == ["evt-nested-flush"]
    finally:
        set_nested_resume_runner(previous)


@pytest.mark.asyncio
async def test_bind_fails_closed_when_nested_resume_has_no_runner() -> None:
    from app.orchestration.graph_invocation import (
        NestedGraphResumeError,
        bind_investigation_graph,
        defer_nested_graph_resume,
        get_nested_resume_durability_writer,
        get_nested_resume_failure_handler,
        get_nested_resume_runner,
        set_nested_resume_durability_writer,
        set_nested_resume_failure_handler,
        set_nested_resume_runner,
    )

    persisted: list[tuple[str, str]] = []
    notified: list[str] = []

    async def _writer(event_id: str, reason: str) -> None:
        persisted.append((event_id, reason))

    async def _handler(event_id: str, exc: BaseException, pending: list[str]) -> None:
        del event_id, pending
        notified.append(type(exc).__name__)

    previous = get_nested_resume_runner()
    previous_writer = get_nested_resume_durability_writer()
    previous_handler = get_nested_resume_failure_handler()
    set_nested_resume_runner(None)
    set_nested_resume_durability_writer(_writer)
    set_nested_resume_failure_handler(_handler)
    try:
        async with bind_investigation_graph("evt-no-runner"):
            assert defer_nested_graph_resume("evt-no-runner") is True
    finally:
        set_nested_resume_runner(previous)
        set_nested_resume_durability_writer(previous_writer)
        set_nested_resume_failure_handler(previous_handler)

    assert persisted == [("evt-no-runner", "nested_resume_no_runner")]
    assert notified == [NestedGraphResumeError.__name__]


@pytest.mark.asyncio
async def test_bind_persists_when_nested_resume_flush_fails() -> None:
    from app.orchestration.graph_invocation import (
        bind_investigation_graph,
        defer_nested_graph_resume,
        get_nested_resume_durability_writer,
        get_nested_resume_failure_handler,
        get_nested_resume_runner,
        set_nested_resume_durability_writer,
        set_nested_resume_failure_handler,
        set_nested_resume_runner,
    )

    persisted: list[tuple[str, str]] = []
    notified: list[str] = []

    async def _boom(_event_id: str) -> None:
        raise RuntimeError("flush failed")

    async def _writer(event_id: str, reason: str) -> None:
        persisted.append((event_id, reason))

    async def _handler(event_id: str, exc: BaseException, pending: list[str]) -> None:
        del event_id, pending
        notified.append(type(exc).__name__)

    previous = get_nested_resume_runner()
    previous_writer = get_nested_resume_durability_writer()
    previous_handler = get_nested_resume_failure_handler()
    set_nested_resume_runner(_boom)
    set_nested_resume_durability_writer(_writer)
    set_nested_resume_failure_handler(_handler)
    try:
        async with bind_investigation_graph("evt-flush-boom"):
            assert defer_nested_graph_resume("evt-flush-boom") is True
    finally:
        set_nested_resume_runner(previous)
        set_nested_resume_durability_writer(previous_writer)
        set_nested_resume_failure_handler(previous_handler)

    assert persisted == [("evt-flush-boom", "nested_resume_flush_failed")]
    assert notified == ["RuntimeError"]


@pytest.mark.asyncio
async def test_bind_does_not_fail_parent_when_nested_resume_plan_advance_fails() -> None:
    from app.orchestration.graph_invocation import (
        bind_investigation_graph,
        defer_nested_graph_resume,
        get_nested_resume_durability_writer,
        get_nested_resume_runner,
        set_nested_resume_durability_writer,
        set_nested_resume_runner,
    )

    persisted: list[tuple[str, str]] = []

    async def _boom(_event_id: str) -> None:
        raise GraphResumeFailedError(
            "plan advance CAS failed while WAITING_APPROVAL",
            event_id=_event_id,
            error_type="plan_advance_failed",
        )

    async def _writer(event_id: str, reason: str) -> None:
        persisted.append((event_id, reason))

    previous = get_nested_resume_runner()
    previous_writer = get_nested_resume_durability_writer()
    set_nested_resume_runner(_boom)
    set_nested_resume_durability_writer(_writer)
    try:
        async with bind_investigation_graph("evt-plan-advance-flush"):
            assert defer_nested_graph_resume("evt-plan-advance-flush") is True
    finally:
        set_nested_resume_runner(previous)
        set_nested_resume_durability_writer(previous_writer)

    assert persisted == [("evt-plan-advance-flush", "nested_resume_flush_failed")]


@pytest.mark.asyncio
async def test_bind_notifies_failure_handler_when_nested_resume_has_no_runner() -> None:
    from app.orchestration.graph_invocation import (
        NestedGraphResumeError,
        bind_investigation_graph,
        defer_nested_graph_resume,
        get_nested_resume_failure_handler,
        get_nested_resume_runner,
        set_nested_resume_failure_handler,
        set_nested_resume_runner,
    )

    notified: list[tuple[str, str, list[str]]] = []

    async def _handler(event_id: str, exc: BaseException, pending: list[str]) -> None:
        notified.append((event_id, type(exc).__name__, list(pending)))

    previous_runner = get_nested_resume_runner()
    previous_handler = get_nested_resume_failure_handler()
    set_nested_resume_runner(None)
    set_nested_resume_failure_handler(_handler)
    try:
        async with bind_investigation_graph("evt-no-runner-obs"):
            assert defer_nested_graph_resume("evt-no-runner-obs") is True
    finally:
        set_nested_resume_runner(previous_runner)
        set_nested_resume_failure_handler(previous_handler)

    assert notified == [
        ("evt-no-runner-obs", "NestedGraphResumeError", ["evt-no-runner-obs"])
    ]


@pytest.mark.asyncio
async def test_bind_skips_nested_resume_flush_on_cancellation() -> None:
    from app.orchestration.graph_invocation import (
        bind_investigation_graph,
        defer_nested_graph_resume,
        get_nested_resume_failure_handler,
        get_nested_resume_runner,
        set_nested_resume_failure_handler,
        set_nested_resume_runner,
    )

    flushed: list[str] = []

    async def _runner(event_id: str) -> None:
        flushed.append(event_id)

    notified: list[tuple[str, str, str]] = []

    async def _handler(event_id: str, exc: BaseException, pending: list[str]) -> None:
        error_type = getattr(exc, "error_type", type(exc).__name__)
        notified.append((event_id, str(error_type), list(pending)[0] if pending else ""))

    persisted: list[tuple[str, str]] = []

    async def _writer(event_id: str, reason: str) -> None:
        persisted.append((event_id, reason))

    previous_runner = get_nested_resume_runner()
    previous_handler = get_nested_resume_failure_handler()
    from app.orchestration.graph_invocation import (
        get_nested_resume_durability_writer,
        set_nested_resume_durability_writer,
    )

    previous_writer = get_nested_resume_durability_writer()
    set_nested_resume_runner(_runner)
    set_nested_resume_failure_handler(_handler)
    set_nested_resume_durability_writer(_writer)
    try:
        with pytest.raises(asyncio.CancelledError):
            async with bind_investigation_graph("evt-cancel"):
                assert defer_nested_graph_resume("evt-cancel") is True
                raise asyncio.CancelledError()
    finally:
        set_nested_resume_runner(previous_runner)
        set_nested_resume_failure_handler(previous_handler)
        set_nested_resume_durability_writer(previous_writer)

    assert flushed == []
    assert persisted == [("evt-cancel", "nested_resume_cancelled")]
    assert notified == []


@pytest.mark.asyncio
async def test_bind_flush_cancelled_persists_deferred_approval_wakeup() -> None:
    from app.orchestration.graph_invocation import (
        bind_investigation_graph,
        defer_nested_graph_resume,
        get_nested_resume_durability_writer,
        get_nested_resume_failure_handler,
        get_nested_resume_runner,
        set_nested_resume_durability_writer,
        set_nested_resume_failure_handler,
        set_nested_resume_runner,
    )

    flushed: list[str] = []

    async def _runner(event_id: str) -> None:
        flushed.append(event_id)
        raise asyncio.CancelledError()

    persisted: list[tuple[str, str]] = []

    async def _writer(event_id: str, reason: str) -> None:
        persisted.append((event_id, reason))

    previous_runner = get_nested_resume_runner()
    previous_handler = get_nested_resume_failure_handler()
    previous_writer = get_nested_resume_durability_writer()
    set_nested_resume_runner(_runner)
    set_nested_resume_failure_handler(None)
    set_nested_resume_durability_writer(_writer)
    try:
        with pytest.raises(asyncio.CancelledError):
            async with bind_investigation_graph("evt-flush-cancel"):
                assert defer_nested_graph_resume("evt-flush-cancel") is True
    finally:
        set_nested_resume_runner(previous_runner)
        set_nested_resume_failure_handler(previous_handler)
        set_nested_resume_durability_writer(previous_writer)

    assert flushed == ["evt-flush-cancel"]
    assert ("evt-flush-cancel", "nested_resume_cancelled") in persisted
    assert all(reason == "nested_resume_cancelled" for _event_id, reason in persisted)


@pytest.mark.asyncio
async def test_bind_flush_treats_deferred_resume_as_success() -> None:
    from app.orchestration.graph_invocation import (
        bind_investigation_graph,
        defer_nested_graph_resume,
        get_nested_resume_durability_writer,
        get_nested_resume_failure_handler,
        get_nested_resume_runner,
        set_nested_resume_durability_writer,
        set_nested_resume_failure_handler,
        set_nested_resume_runner,
    )
    from app.orchestration.graph_resume_observability import GraphResumeDeferredError

    notified: list[str] = []
    persisted: list[tuple[str, str]] = []

    async def _deferred(event_id: str) -> None:
        raise GraphResumeDeferredError(
            "cannot resume while event is still WAITING_APPROVAL",
            event_id=event_id,
            error_type="waiting_approval",
        )

    async def _handler(event_id: str, exc: BaseException, _pending: list[str]) -> None:
        notified.append(event_id)

    async def _writer(event_id: str, reason: str) -> None:
        persisted.append((event_id, reason))

    previous_runner = get_nested_resume_runner()
    previous_handler = get_nested_resume_failure_handler()
    previous_writer = get_nested_resume_durability_writer()
    set_nested_resume_runner(_deferred)
    set_nested_resume_failure_handler(_handler)
    set_nested_resume_durability_writer(_writer)
    try:
        async with bind_investigation_graph("evt-defer-flush"):
            assert defer_nested_graph_resume("evt-defer-flush") is True
    finally:
        set_nested_resume_runner(previous_runner)
        set_nested_resume_failure_handler(previous_handler)
        set_nested_resume_durability_writer(previous_writer)

    assert persisted == [("evt-defer-flush", "waiting_approval")]
    assert notified == []


@pytest.mark.asyncio
async def test_bind_persists_nested_resume_on_soft_time_limit() -> None:
    from celery.exceptions import SoftTimeLimitExceeded

    from app.orchestration.graph_invocation import (
        bind_investigation_graph,
        defer_nested_graph_resume,
        get_nested_resume_durability_writer,
        get_nested_resume_runner,
        set_nested_resume_durability_writer,
        set_nested_resume_runner,
    )

    flushed: list[str] = []

    async def _runner(event_id: str) -> None:
        flushed.append(event_id)

    persisted: list[tuple[str, str]] = []

    async def _writer(event_id: str, reason: str) -> None:
        persisted.append((event_id, reason))

    previous_runner = get_nested_resume_runner()
    previous_writer = get_nested_resume_durability_writer()
    set_nested_resume_runner(_runner)
    set_nested_resume_durability_writer(_writer)
    try:
        with pytest.raises(SoftTimeLimitExceeded):
            async with bind_investigation_graph("evt-soft-limit"):
                assert defer_nested_graph_resume("evt-soft-limit") is True
                raise SoftTimeLimitExceeded()
    finally:
        set_nested_resume_runner(previous_runner)
        set_nested_resume_durability_writer(previous_writer)

    assert flushed == []
    assert persisted == [("evt-soft-limit", "nested_resume_soft_time_limit")]


@pytest.mark.asyncio
async def test_bind_preserves_graph_error_when_flush_fails() -> None:
    from app.orchestration.graph_invocation import (
        bind_investigation_graph,
        defer_nested_graph_resume,
        get_nested_resume_durability_writer,
        get_nested_resume_runner,
        set_nested_resume_durability_writer,
        set_nested_resume_runner,
    )

    async def _boom(_event_id: str) -> None:
        raise RuntimeError("flush failed")

    persisted: list[tuple[str, str]] = []

    async def _writer(event_id: str, reason: str) -> None:
        persisted.append((event_id, reason))

    previous = get_nested_resume_runner()
    previous_writer = get_nested_resume_durability_writer()
    set_nested_resume_runner(_boom)
    set_nested_resume_durability_writer(_writer)
    try:
        with pytest.raises(ValueError, match="graph boom"):
            async with bind_investigation_graph("evt-graph-boom"):
                assert defer_nested_graph_resume("evt-graph-boom") is True
                raise ValueError("graph boom")
    finally:
        set_nested_resume_runner(previous)
        set_nested_resume_durability_writer(previous_writer)

    assert persisted == [("evt-graph-boom", "nested_resume_flush_failed")]


def test_reset_deps_clears_nested_resume_hooks() -> None:
    from app.api.v1.deps import reset_deps
    from app.orchestration.graph_invocation import (
        get_nested_resume_durability_writer,
        get_nested_resume_failure_handler,
        get_nested_resume_runner,
        set_nested_resume_durability_writer,
        set_nested_resume_failure_handler,
        set_nested_resume_runner,
    )

    previous_runner = get_nested_resume_runner()
    previous_handler = get_nested_resume_failure_handler()
    previous_writer = get_nested_resume_durability_writer()
    set_nested_resume_runner(AsyncMock())
    set_nested_resume_failure_handler(AsyncMock())
    set_nested_resume_durability_writer(AsyncMock())
    try:
        reset_deps()
        assert get_nested_resume_runner() is None
        assert get_nested_resume_failure_handler() is None
        assert get_nested_resume_durability_writer() is None
    finally:
        set_nested_resume_runner(previous_runner)
        set_nested_resume_failure_handler(previous_handler)
        set_nested_resume_durability_writer(previous_writer)


@pytest.mark.asyncio
async def test_execute_graph_resume_state_mismatch_is_not_retried() -> None:
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=[])
    degraded.has_flag = AsyncMock(return_value=False)
    exc = ValidationError(
        "caller EventStatus does not match authoritative state",
        details={
            "caller_status": EventStatus.EXECUTING_RESPONSE.value,
            "authoritative_status": EventStatus.FAILED.value,
        },
    )
    graph = MagicMock()
    graph.aget_state = AsyncMock(
        return_value=MagicMock(
            values={
                "halted": True,
                "needs_approval_wait": True,
                "execution_substate": "waiting_approval",
            }
        )
    )
    agent = MagicMock()
    agent._investigation_graph = graph
    agent.lease = _fresh_event_lease()
    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock(side_effect=exc)

    with pytest.raises(GraphResumeFailedError) as exc_info:
        await execute_graph_resume_with_retry(
            "evt-state-mismatch",
            session_factory=_SessionFactory(),
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=runtime),
            degraded_flags=degraded,
        )

    assert exc_info.value.error_type == "state_mismatch"
    degraded.set_flag.assert_awaited_once()
    assert runtime.set_execution_substate.await_count == 1


@pytest.mark.asyncio
async def test_execute_graph_resume_transient_exhaustion_records_single_failure() -> None:
    degraded = MagicMock()
    degraded.has_flag = AsyncMock(return_value=False)
    degraded.set_flag = AsyncMock(return_value=[])
    agent = MagicMock()
    agent._investigation_graph = MagicMock()
    agent._investigation_graph.aget_state = AsyncMock(side_effect=TimeoutError("redis timeout"))
    agent.lease = _fresh_event_lease()

    with pytest.raises(GraphResumeFailedError):
        await execute_graph_resume_with_retry(
            "evt-exhaust",
            session_factory=_SessionFactory(),
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=MagicMock()),
            degraded_flags=degraded,
        )

    assert agent._investigation_graph.aget_state.await_count == 3
    degraded.set_flag.assert_awaited_once()


@pytest.mark.asyncio
async def test_execute_graph_resume_with_retry_preserves_soft_time_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-314: SoftTimeLimit must not be wrapped as GraphResumeFailedError."""
    from celery.exceptions import SoftTimeLimitExceeded

    degraded = MagicMock()
    degraded.has_flag = AsyncMock(return_value=False)
    degraded.set_flag = AsyncMock(return_value=[])
    record = AsyncMock()
    monkeypatch.setattr(
        "app.orchestration.graph_resume_observability.record_graph_resume_failure",
        record,
    )
    monkeypatch.setattr(
        "app.orchestration.graph_resume_observability.resume_investigation_from_checkpoint",
        AsyncMock(side_effect=SoftTimeLimitExceeded()),
    )

    with pytest.raises(SoftTimeLimitExceeded):
        await execute_graph_resume_with_retry(
            "evt-soft-resume",
            session_factory=_SessionFactory(),
            get_super_agent=AsyncMock(return_value=MagicMock()),
            get_workflow_runtime=AsyncMock(return_value=MagicMock()),
            degraded_flags=degraded,
        )

    record.assert_not_awaited()
    degraded.set_flag.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_graph_resume_waiting_approval_is_deferred_not_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    persisted: list[tuple[str, str]] = []

    async def _persist(event_id: str, reason: str = "nested_wakeup") -> bool:
        persisted.append((event_id, reason))
        return True

    monkeypatch.setattr(
        "app.orchestration.graph_resume_observability.persist_nested_graph_wakeup",
        _persist,
    )
    monkeypatch.setattr(
        "app.orchestration.graph_resume_observability._RESUME_RETRY_BASE_SECONDS",
        0,
    )
    monkeypatch.setattr(
        "app.orchestration.graph_resume._load_response_actions_for_resume",
        AsyncMock(
            return_value=[
                MagicMock(
                    status=ActionStatus.WAITING_APPROVAL,
                    tool_name="block_ip",
                    writeback_required=False,
                    plan_revision=1,
                )
            ]
        ),
    )
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=[])
    degraded.has_flag = AsyncMock(return_value=False)
    agent = MagicMock()
    agent._investigation_graph = MagicMock()
    agent.lease = _fresh_event_lease()

    with pytest.raises(GraphResumeDeferredError) as exc_info:
        await execute_graph_resume_with_retry(
            "evt-waiting-deferred",
            session_factory=_SessionFactory(EventStatus.WAITING_APPROVAL.value),
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=MagicMock()),
            degraded_flags=degraded,
        )

    assert exc_info.value.error_type == "waiting_approval"
    assert persisted == [("evt-waiting-deferred", "waiting_approval")]
    degraded.set_flag.assert_not_awaited()


@pytest.mark.asyncio
async def test_persist_nested_graph_wakeup_propagates_cancelled_error() -> None:
    from app.orchestration.graph_invocation import (
        get_nested_resume_durability_writer,
        persist_nested_graph_wakeup,
        set_nested_resume_durability_writer,
    )

    async def _cancel(_event_id: str, _reason: str) -> None:
        raise asyncio.CancelledError()

    previous = get_nested_resume_durability_writer()
    set_nested_resume_durability_writer(_cancel)
    try:
        with pytest.raises(asyncio.CancelledError):
            await persist_nested_graph_wakeup("evt-cancel-persist", "nested_resume_cancelled")
    finally:
        set_nested_resume_durability_writer(previous)


def test_claimed_intent_deferred_path_does_not_use_mark_failure() -> None:
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[2]
        / "app"
        / "services"
        / "manual_resolution_service.py"
    ).read_text(encoding="utf-8")
    start = source.index("async def _run_claimed_intent")
    end = source.index("async def _clear_manual_resolution_for_resume")
    body = source[start:end]
    assert "GraphResumeDeferredError" in body
    assert body.index("await self._mark_deferred") < body.index("await self._mark_failure")
    deferred = body[
        body.index("if isinstance(exc, GraphResumeDeferredError)") : body.index(
            "await self._mark_failure"
        )
    ]
    assert "attempt" not in deferred


@pytest.mark.asyncio
async def test_bind_flush_while_outer_lease_held_does_not_start_second_ainvoke() -> None:
    from app.orchestration.graph_invocation import (
        bind_investigation_graph,
        defer_nested_graph_resume,
        get_nested_resume_durability_writer,
        get_nested_resume_failure_handler,
        get_nested_resume_runner,
        set_nested_resume_durability_writer,
        set_nested_resume_failure_handler,
        set_nested_resume_runner,
    )
    from app.orchestration.graph_resume import resume_investigation_from_checkpoint
    from app.orchestration.lease import EventLease, generate_owner_id
    from tests.support.fake_redis import InMemoryFakeRedisClient

    event_id = "evt-bind-lease"
    lease = EventLease(InMemoryFakeRedisClient())
    assert await lease.acquire(event_id, generate_owner_id()) is True

    graph = MagicMock()
    graph.aget_state = AsyncMock(
        return_value=MagicMock(
            values={
                "halted": True,
                "event_status": EventStatus.EXECUTING_RESPONSE.value,
            }
        )
    )
    graph.aupdate_state = AsyncMock()
    graph.ainvoke = AsyncMock()
    agent = MagicMock()
    agent._investigation_graph = graph
    agent.lease = lease
    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock()

    async def _runner(resume_event_id: str) -> None:
        await resume_investigation_from_checkpoint(
            _SessionFactory(EventStatus.EXECUTING_RESPONSE.value),
            resume_event_id,
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=runtime),
        )

    persisted: list[tuple[str, str]] = []

    async def _writer(resume_event_id: str, reason: str) -> None:
        persisted.append((resume_event_id, reason))

    previous_runner = get_nested_resume_runner()
    previous_handler = get_nested_resume_failure_handler()
    previous_writer = get_nested_resume_durability_writer()
    set_nested_resume_runner(_runner)
    set_nested_resume_failure_handler(None)
    set_nested_resume_durability_writer(_writer)
    try:
        async with bind_investigation_graph(event_id):
            assert defer_nested_graph_resume(event_id) is True
    finally:
        set_nested_resume_runner(previous_runner)
        set_nested_resume_failure_handler(previous_handler)
        set_nested_resume_durability_writer(previous_writer)

    graph.ainvoke.assert_not_called()
    graph.aupdate_state.assert_not_awaited()
    graph.aget_state.assert_not_called()
    assert persisted == [(event_id, "investigation_in_progress")]

