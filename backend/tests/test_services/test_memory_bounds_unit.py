from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.core.errors import GuardrailViolationError
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
        with pytest.raises(GuardrailViolationError):
            memory.for_writer("RiskAgent")
    assert list(memory._issued_capabilities) == [first, second]

    degraded = AsyncMock()
    degraded.has_flag.return_value = False
    memory.bind_degraded_flag_service(degraded)
    with patch("app.services.working_memory.EVENT_CACHE_LIMIT", 2):
        for event_id in ("event-a", "event-b", "event-c"):
            await memory._maybe_mark_redis_unavailable(event_id, redis_ok=False)
    assert list(memory._redis_degrade_marked) == ["event-b", "event-c"]


def test_active_bound_memory_capability_survives_capacity_pressure() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    with patch("app.services.working_memory.CAPABILITY_LIMIT", 1):
        bound = memory.for_writer("RiskAgent")
        with pytest.raises(GuardrailViolationError):
            memory.for_writer("RiskAgent")
    assert memory._resolve_capability(bound._capability) == "RiskAgent"


def test_released_capability_is_removed() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    bound = memory.for_writer("RiskAgent")
    bound.release()
    with pytest.raises(GuardrailViolationError):
        memory._resolve_capability(bound._capability)
    assert not memory._capability_last_used


def test_expired_capability_fails_closed() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    with patch(
        "app.services.working_memory.time.monotonic", side_effect=[0.0, 0.0, 10.0]
    ), patch(
        "app.services.working_memory.CAPABILITY_TTL_SECONDS", 5
    ):
        bound = memory.for_writer("RiskAgent")
        with pytest.raises(GuardrailViolationError):
            memory._resolve_capability(bound._capability)


def test_capability_index_is_bounded_and_deterministic() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    with patch("app.services.working_memory.CAPABILITY_LIMIT", 2):
        first = memory.for_writer("RiskAgent")
        second = memory.for_writer("RiskAgent")
        first.release()
        third = memory.for_writer("RiskAgent")
    assert list(memory._issued_capabilities) == [second._capability, third._capability]
    assert list(memory._capability_last_used) == [second._capability, third._capability]


@pytest.mark.asyncio
async def test_field_ownership_cannot_be_bypassed_after_eviction() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    with patch("app.services.working_memory.CAPABILITY_LIMIT", 1):
        evidence = memory.for_writer("EvidenceAgent")
        with pytest.raises(GuardrailViolationError):
            memory.for_writer("TriageAgent")
    with pytest.raises(GuardrailViolationError) as exc_info:
        await evidence.write("event-a", "triage_result", {"bypass": True})
    assert exc_info.value.error_code == "working_memory_unauthorized_write"


@pytest.mark.asyncio
async def test_redis_degraded_marker_is_cleared_after_recovery() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    degraded = AsyncMock()
    memory.bind_degraded_flag_service(degraded)
    await memory._maybe_mark_redis_unavailable("event-a", redis_ok=False)
    await memory._maybe_mark_redis_unavailable("event-a", redis_ok=True)
    assert "event-a" not in memory._redis_degrade_marked


@pytest.mark.asyncio
async def test_second_redis_outage_creates_new_degraded_marker() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    degraded = AsyncMock()
    memory.bind_degraded_flag_service(degraded)
    await memory._maybe_mark_redis_unavailable("event-a", redis_ok=False)
    await memory._maybe_mark_redis_unavailable("event-a", redis_ok=True)
    await memory._maybe_mark_redis_unavailable("event-a", redis_ok=False)
    assert degraded.set_flag.await_count == 2


@pytest.mark.asyncio
async def test_degraded_marker_concurrent_eviction_has_no_keyerror() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    degraded = AsyncMock()
    memory.bind_degraded_flag_service(degraded)
    with patch("app.services.working_memory.EVENT_CACHE_LIMIT", 2):
        await asyncio.gather(
            *(memory._maybe_mark_redis_unavailable(f"event-{i}", False) for i in range(20))
        )
    assert len(memory._redis_degrade_marked) <= 2


@pytest.mark.asyncio
async def test_degraded_marker_index_is_bounded() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    memory.bind_degraded_flag_service(AsyncMock())
    with patch("app.services.working_memory.EVENT_CACHE_LIMIT", 3):
        for index in range(20):
            await memory._maybe_mark_redis_unavailable(f"event-{index}", False)
    assert list(memory._redis_degrade_marked) == ["event-17", "event-18", "event-19"]


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
    ), patch.object(
        engine,
        "_claim_approval_publication",
        AsyncMock(return_value=True),
    ), patch.object(engine, "_mark_approval_published", AsyncMock()) as mark:
        await engine._publish_approval_required(action, 0)  # type: ignore[arg-type]
        bus.publish_event.assert_not_awaited()

        bus.publish_event.return_value = True
        await engine._publish_approval_required(action, 1)  # type: ignore[arg-type]
        bus.publish_event.assert_awaited_once()
        mark.assert_awaited_once()
        assert mark.await_args.args == ("action-old", 1)
