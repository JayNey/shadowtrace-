from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest
from celery.app.task import Context

from app.models.investigation_intent import IntentDeliveryAdmission
from app.tasks import investigation_tasks as tasks


def test_celery_wrapper_uses_one_asyncio_runner_before_sync_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_run = asyncio.run
    run_calls = 0
    order: list[str] = []

    def counted_run(coro: Any) -> Any:
        nonlocal run_calls
        run_calls += 1
        return real_run(coro)

    async def flow(*_args: object, **_kwargs: object) -> dict[str, str]:
        order.append("flow")
        return {"status": "completed", "event_id": "event-a"}

    monkeypatch.setattr(tasks.asyncio, "run", counted_run)
    monkeypatch.setattr(tasks, "_run_investigation_flow", flow)
    monkeypatch.setattr(
        tasks,
        "_release_celery_task_loop_resources",
        lambda: order.append("sync-reset"),
    )
    ctx = Context(id="task-loop-unit", delivery_info={}, retries=0)
    tasks.run_investigation.request_stack.push(ctx)
    try:
        result = tasks.run_investigation.run("event-a")
    finally:
        tasks.run_investigation.request_stack.pop()

    assert result == {"status": "completed", "event_id": "event-a"}
    assert run_calls == 1
    assert order == ["flow", "sync-reset"]


@pytest.mark.asyncio
async def test_mark_dead_and_resource_close_share_body_loop_and_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop_ids: dict[str, int] = {}
    order: list[str] = []

    async def body(*_args: object, **_kwargs: object) -> dict[str, str]:
        loop_ids["body"] = id(asyncio.get_running_loop())
        order.append("body")
        raise RuntimeError("boom")

    class IntentService:
        def __init__(self, _factory: object) -> None:
            pass

        async def mark_dead(self, *_args: object, **_kwargs: object) -> None:
            loop_ids["mark_dead"] = id(asyncio.get_running_loop())
            order.append("mark_dead")

    async def close() -> None:
        loop_ids["close"] = id(asyncio.get_running_loop())
        order.append("close")

    monkeypatch.setattr(tasks, "_run_investigation_body", body)
    monkeypatch.setattr(tasks, "_close_task_owned_resources", close)
    monkeypatch.setattr(
        tasks,
        "_admit_intent_delivery",
        AsyncMock(return_value=IntentDeliveryAdmission.ACCEPTED),
    )
    monkeypatch.setattr("app.db.session.get_session_factory", lambda: object())
    monkeypatch.setattr(
        "app.services.investigation_intent_service.InvestigationIntentService",
        IntentService,
    )

    with pytest.raises(RuntimeError, match="boom"):
        await tasks._run_investigation_flow(
            "event-a",
            include_response_execution=False,
            generate_report=True,
            owner_id="owner-a",
            task_id="task-a",
            redelivered=False,
            lease_acquired=False,
            request_headers=None,
            intent_id="intent-a",
        )

    assert loop_ids["body"] == loop_ids["mark_dead"] == loop_ids["close"]
    assert order == ["body", "mark_dead", "close"]


@pytest.mark.asyncio
async def test_embedding_close_failure_still_clears_loop_bound_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.embedding import factory

    client = AsyncMock()
    client.close.side_effect = RuntimeError("close failed")
    monkeypatch.setattr(factory, "_client", client)
    with pytest.raises(RuntimeError, match="close failed"):
        await factory.close_embedding_client()
    assert factory._client is None


@pytest.mark.asyncio
async def test_task_owned_resource_close_order_is_observable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []

    async def record(name: str) -> None:
        order.append(name)

    monkeypatch.setattr(
        "app.core.embedding.factory.close_embedding_client",
        lambda: record("embedding"),
    )
    monkeypatch.setattr(
        "app.api.v1.deps.close_loop_bound_adapter_resources",
        lambda: record("adapters"),
    )
    monkeypatch.setattr(
        "app.api.v1.deps.close_loop_bound_redis_resources",
        lambda: record("redis"),
    )
    await tasks._close_task_owned_resources()
    assert order == ["embedding", "adapters", "redis"]


def test_cached_investigation_stack_remains_authorized_after_capability_ttl() -> None:
    test_background_resume_after_approval_wait_uses_valid_wm_capabilities()


def test_background_resume_after_approval_wait_uses_valid_wm_capabilities() -> None:
    """Cached investigation-stack writers must survive idle TTL across approval wait."""
    from unittest.mock import AsyncMock, patch

    from app.services.working_memory import WorkingMemory

    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    bound = memory.for_writer("ResponseAgent")
    with patch("app.services.working_memory.time.monotonic", return_value=10_000.0), patch(
        "app.services.working_memory.CAPABILITY_TTL_SECONDS", 5
    ):
        assert memory._resolve_capability(bound._capability) == "ResponseAgent"
