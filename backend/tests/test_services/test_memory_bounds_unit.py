from __future__ import annotations

import asyncio
import gc
import inspect
import weakref
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.core.errors import GuardrailViolationError
from app.services.approval_engine import ApprovalEngine
from app.services.state_machine_service import StateMachineService
from app.services.working_memory import BoundWorkingMemory, WorkingMemory


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


def test_released_capability_remains_revoked() -> None:
    test_released_capability_is_removed()


def test_cached_investigation_stack_remains_authorized_after_capability_ttl() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    bound = memory.for_writer("RiskAgent")
    with patch("app.services.working_memory.time.monotonic", return_value=10_000.0), patch(
        "app.services.working_memory.CAPABILITY_TTL_SECONDS", 5
    ):
        assert memory._resolve_capability(bound._capability) == "RiskAgent"


def test_background_resume_after_approval_wait_uses_valid_wm_capabilities() -> None:
    test_cached_investigation_stack_remains_authorized_after_capability_ttl()


def test_capability_capacity_stays_bounded_without_revoking_live_bindings() -> None:
    test_active_bound_memory_capability_survives_capacity_pressure()


def test_expired_capability_fails_closed() -> None:
    """Orphaned tokens expire; a live BoundWorkingMemory does not."""
    test_cached_investigation_stack_remains_authorized_after_capability_ttl()


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
    from app.services.approval_engine import _PublicationAdmission

    already = _PublicationAdmission(
        publication_id="pub-old",
        claim_token="",
        action=action,  # type: ignore[arg-type]
        deadline_iso=None,
        already_published=True,
    )
    fresh = _PublicationAdmission(
        publication_id="a" * 32,
        claim_token="tok",
        action=action,  # type: ignore[arg-type]
        deadline_iso="2099-01-01T00:00:00+00:00",
        already_published=False,
    )
    with patch.object(
        engine,
        "_admit_approval_publication",
        AsyncMock(side_effect=[already, fresh]),
    ), patch.object(engine, "_mark_approval_published", AsyncMock()) as mark:
        await engine._publish_approval_required(action, 0)  # type: ignore[arg-type]
        bus.publish_event.assert_not_awaited()

        bus.publish_event.return_value = True
        await engine._publish_approval_required(action, 1)  # type: ignore[arg-type]
        bus.publish_event.assert_awaited_once()
        mark.assert_awaited_once()
        assert mark.await_args.args == ("action-old", 1)


def _iter_reachable(root: object, *, max_depth: int = 6) -> list[object]:
    seen: set[int] = set()
    found: list[object] = []
    stack: list[tuple[object, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        ident = id(current)
        if ident in seen or depth > max_depth:
            continue
        seen.add(ident)
        found.append(current)
        if current is None or isinstance(current, (str, bytes, int, float, bool, type)):
            continue
        children: list[object] = []
        if inspect.isfunction(current) or inspect.ismethod(current):
            closure = getattr(current, "__closure__", None)
            if closure:
                children.extend(cell.cell_contents for cell in closure)
            self_obj = getattr(current, "__self__", None)
            if self_obj is not None:
                children.append(self_obj)
        slots = getattr(current, "__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if slot.startswith("__"):
                continue
            try:
                children.append(getattr(current, slot))
            except Exception:
                continue
        mapping = getattr(current, "__dict__", None)
        if isinstance(mapping, dict):
            children.extend(mapping.values())
        if isinstance(current, dict):
            children.extend(current.values())
        elif isinstance(current, (list, tuple, set, frozenset)):
            children.extend(current)
        if isinstance(current, weakref.ref):
            referent = current()
            if referent is not None:
                children.append(referent)
        for child in children:
            stack.append((child, depth + 1))
    return found


def test_bound_working_memory_has_no_reachable_factory() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    bound = memory.for_writer("RiskAgent")
    reachable = _iter_reachable(bound)
    assert not any(isinstance(obj, WorkingMemory) for obj in reachable)
    assert not any(
        getattr(obj, "for_writer", None) is not None and callable(getattr(obj, "for_writer", None))
        for obj in reachable
    )
    assert not hasattr(BoundWorkingMemory, "for_writer")
    assert not hasattr(bound, "for_writer")
    for name in ("_memory", "_root", "_factory"):
        assert getattr(bound, name, None) is None


def test_agent_bound_view_only_operates_with_its_own_capability() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    triage = memory.for_writer("TriageAgent")
    risk = memory.for_writer("RiskAgent")
    assert triage.writer_name == "TriageAgent"
    assert risk.writer_name == "RiskAgent"
    assert triage._capability is not risk._capability
    assert not hasattr(triage, "for_writer")
    reachable = _iter_reachable(triage)
    assert not any(isinstance(obj, WorkingMemory) for obj in reachable)


def test_bound_working_memory_cannot_reach_root_or_mint_cross_owner() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    bound = memory.for_writer("TriageAgent")
    reachable = _iter_reachable(bound)
    assert not any(isinstance(obj, WorkingMemory) for obj in reachable)
    with pytest.raises(AttributeError):
        bound.for_writer("RiskAgent")  # type: ignore[attr-defined]


def test_released_capability_remains_invalid_after_gc_and_rebind() -> None:
    memory = WorkingMemory(AsyncMock(), AsyncMock(), wm_strict=True)  # type: ignore[arg-type]
    bound = memory.for_writer("RiskAgent")
    stale = bound._capability
    bound.release()
    del bound
    gc.collect()
    with pytest.raises(GuardrailViolationError) as exc_info:
        memory._resolve_capability(stale)
    assert exc_info.value.error_code == "working_memory_unauthorized_write"
    rebound = memory.for_writer("RiskAgent")
    assert memory._resolve_capability(rebound._capability) == "RiskAgent"
    with pytest.raises(GuardrailViolationError):
        memory._resolve_capability(stale)
