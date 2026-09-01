from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.services.approval_engine import ApprovalEngine
from app.services.state_machine_service import StateMachineService
from app.services.working_memory import WorkingMemory


def test_projection_lock_is_stable_and_collision_only_shares_serialization() -> None:
    service = StateMachineService(AsyncMock(), AsyncMock())  # type: ignore[arg-type]
    event_a = "event-a"
    lock_a = service._projection_lock(event_a)
    assert service._projection_lock(event_a) is lock_a

    event_b = next(
        f"event-{index}"
        for index in range(10_000)
        if f"event-{index}" != event_a
        and service._projection_lock(f"event-{index}") is lock_a
    )
    assert event_b != event_a
    assert service._projection_lock(event_b) is lock_a


@pytest.mark.asyncio
async def test_projection_lock_serializes_same_event_and_hash_collision() -> None:
    service = StateMachineService(AsyncMock(), AsyncMock())  # type: ignore[arg-type]
    lock = service._projection_lock("event-a")
    collision = next(
        f"collision-{index}"
        for index in range(10_000)
        if service._projection_lock(f"collision-{index}") is lock
    )
    active = 0
    peak = 0

    async def enter(event_id: str) -> None:
        nonlocal active, peak
        async with service._projection_lock(event_id):
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0)
            active -= 1

    await asyncio.gather(enter("event-a"), enter("event-a"), enter(collision))
    assert peak == 1


@pytest.mark.asyncio
async def test_working_memory_access_logs_bound_entries_and_event_index() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    with (
        patch("app.services.working_memory.ACCESS_LOG_LIMIT", 2),
        patch("app.services.working_memory.EVENT_CACHE_LIMIT", 2),
    ):
        for index in range(3):
            memory._record_access(
                "event-a",
                agent_name="RiskAgent",
                op="read",
                key=f"key-{index}",
                allowed=True,
            )
        memory._record_access(
            "event-b", agent_name="RiskAgent", op="read", key="key", allowed=True
        )
        memory._record_access(
            "event-c", agent_name="RiskAgent", op="read", key="key", allowed=True
        )

    assert [entry.key for entry in await memory.get_access_log("event-a")] == []
    assert list(memory._access_logs) == ["event-b", "event-c"]


@pytest.mark.asyncio
async def test_working_memory_capabilities_and_degraded_index_are_deterministic() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    with patch("app.services.working_memory.CAPABILITY_LIMIT", 2):
        first = memory.for_writer("RiskAgent")._capability
        second = memory.for_writer("RiskAgent")._capability
        third = memory.for_writer("RiskAgent")._capability
    assert first not in memory._issued_capabilities
    assert list(memory._issued_capabilities) == [second, third]

    degraded = AsyncMock()
    degraded.has_flag.return_value = False
    memory.bind_degraded_flag_service(degraded)
    with patch("app.services.working_memory.EVENT_CACHE_LIMIT", 2):
        for event_id in ("event-a", "event-b", "event-c"):
            await memory._maybe_mark_redis_unavailable(event_id, redis_ok=False)
    assert list(memory._redis_degrade_marked) == ["event-b", "event-c"]


@pytest.mark.asyncio
async def test_approval_publication_uses_durable_cycle_marker_after_cache_eviction() -> None:
    bus = AsyncMock()
    engine = ApprovalEngine(AsyncMock(), event_bus=bus)  # type: ignore[arg-type]
    engine._approval_publish_cache_limit = 2
    engine._remember_approval_publication("tenant-a:event-a:action-old:0")
    engine._remember_approval_publication("tenant-a:event-a:action-other:0")
    engine._remember_approval_publication("tenant-a:event-a:action-third:0")
    assert "tenant-a:event-a:action-old:0" not in engine._approval_required_published

    action = SimpleNamespace(
        event_id="tenant-a:event-a",
        action_id="action-old",
        action_name="contain host",
        reason="approved containment",
        target="host-1",
        impact_assessment=None,
    )
    with patch.object(
        engine,
        "_approval_was_published",
        AsyncMock(side_effect=[True, False]),
    ), patch.object(engine, "_mark_approval_published", AsyncMock()) as mark:
        await engine._publish_approval_required(action, 0)  # type: ignore[arg-type]
        bus.publish_event.assert_not_awaited()

        bus.publish_event.return_value = True
        await engine._publish_approval_required(action, 1)  # type: ignore[arg-type]
        bus.publish_event.assert_awaited_once()
        mark.assert_awaited_once_with("action-old", 1)
