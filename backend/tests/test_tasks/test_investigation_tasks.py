"""Celery investigation task tests (ISSUE-056)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from kombu.exceptions import OperationalError

from app.core.celery_app import celery_app
from app.core.errors import DependencyUnavailableError, InvestigationInProgressError
from app.tasks import investigation_tasks as tasks


@pytest.mark.asyncio
async def test_execute_investigation_skips_when_lease_already_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _boom(_event_id: str, **_kwargs: Any) -> None:
        raise InvestigationInProgressError(
            message="investigation already in progress for this event",
            error_code="investigation_in_progress",
            details={"event_id": "evt-skip"},
        )

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _boom
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation("evt-skip")
    assert result == {"status": "skipped", "event_id": "evt-skip"}


@pytest.mark.asyncio
async def test_execute_investigation_runs_super_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def _investigate(event_id: str, **_kwargs: Any) -> None:
        calls.append(event_id)

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation("evt-run")
    assert result == {"status": "completed", "event_id": "evt-run"}
    assert calls == ["evt-run"]


def _null_context() -> Any:
    from contextlib import nullcontext

    return nullcontext()


def test_run_investigation_eager_executes_task(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        return {"status": "completed", "event_id": event_id}

    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)
    result = tasks.run_investigation.apply(args=["evt-eager"]).result
    assert result == {"status": "completed", "event_id": "evt-eager"}


def test_duplicate_delivery_is_idempotent(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}

    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        if calls["n"] == 1:
            return {"status": "completed", "event_id": event_id}
        return {"status": "skipped", "event_id": event_id}

    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)

    first = tasks.run_investigation.apply(args=["evt-dup"]).result
    second = tasks.run_investigation.apply(args=["evt-dup"]).result
    assert first["status"] == "completed"
    assert second["status"] == "skipped"


@pytest.mark.asyncio
async def test_execute_investigation_forwards_include_response_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    async def _investigate(event_id: str, **kwargs: Any) -> None:
        seen["event_id"] = event_id
        seen["include_response_execution"] = kwargs.get("include_response_execution")

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation(
        "evt-include",
        include_response_execution=True,
    )
    assert result == {"status": "completed", "event_id": "evt-include"}
    assert seen == {
        "event_id": "evt-include",
        "include_response_execution": True,
    }


@pytest.mark.asyncio
async def test_dispatch_investigation_passes_include_response_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tasks, "register_task_metadata", _noop_register)
    captured: dict[str, Any] = {}

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        captured.update(kwargs)
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _fake_apply_async)

    task_id = await tasks.dispatch_investigation(
        "evt-dispatch-include",
        include_response_execution=True,
    )
    assert task_id
    assert captured["args"] == ["evt-dispatch-include"]
    assert captured["kwargs"] == {"include_response_execution": True}


@pytest.mark.asyncio
async def test_dispatch_investigation_returns_celery_task_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tasks, "register_task_metadata", _noop_register)

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _fake_apply_async)

    task_id = await tasks.dispatch_investigation("evt-dispatch")
    assert task_id
    assert task_id != "evt-dispatch"


@pytest.mark.asyncio
async def test_resolve_task_state_reads_registered_event_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tasks, "register_task_metadata", _noop_register)

    async def _fake_lookup(task_id: str) -> str | None:
        return "evt-status"

    monkeypatch.setattr(tasks, "lookup_task_event_id", _fake_lookup)

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _fake_apply_async)

    task_id = await tasks.dispatch_investigation("evt-status")
    state, event_id = await tasks.resolve_task_state(task_id)
    assert event_id == "evt-status"
    assert state in {"SUCCESS", "PENDING", "STARTED", "FAILURE"}


@pytest.mark.asyncio
async def test_dispatch_broker_unavailable_raises_503(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tasks, "register_task_metadata", _noop_register)
    monkeypatch.setattr(tasks, "delete_task_metadata", _noop_delete)

    def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise OperationalError("broker down")

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _boom)

    with pytest.raises(DependencyUnavailableError) as exc_info:
        await tasks.dispatch_investigation("evt-broker-down")

    assert exc_info.value.error_code == "task_unavailable"


@pytest.mark.asyncio
async def test_dispatch_metadata_failure_prevents_enqueue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def _fail_register(*_args: Any, **_kwargs: Any) -> None:
        raise DependencyUnavailableError(
            message="task metadata store unavailable",
            error_code="dependency_unavailable",
            details={"dependency": "redis"},
        )

    def _apply_async(*_args: Any, **_kwargs: Any) -> MagicMock:
        calls.append("apply_async")
        return MagicMock(id="should-not-run")

    monkeypatch.setattr(tasks, "register_task_metadata", _fail_register)
    monkeypatch.setattr(tasks.run_investigation, "apply_async", _apply_async)

    with pytest.raises(DependencyUnavailableError):
        await tasks.dispatch_investigation("evt-meta-fail")

    assert calls == []


def test_celery_task_uses_locked_name_and_queue() -> None:
    task = celery_app.tasks[tasks.TASK_NAME]
    assert task.name == "shadowtrace.run_investigation"
    assert task.acks_late is True
    assert task.max_retries == 2
    assert task.retry_backoff is True
    assert task.soft_time_limit == 600
    route = celery_app.conf.task_routes.get(tasks.TASK_NAME)
    assert route == {"queue": "investigation"}


async def _noop_register(*_args: Any, **_kwargs: Any) -> None:
    return None


async def _noop_delete(*_args: Any, **_kwargs: Any) -> None:
    return None
