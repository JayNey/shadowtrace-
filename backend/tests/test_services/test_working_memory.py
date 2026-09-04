"""WorkingMemory + FIELD_OWNERSHIP tests (ISSUE-014)."""

from __future__ import annotations

import asyncio
import gc
import inspect
import os
import types
import uuid
import weakref
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.schemas import EventSummary
from app.core.errors import GuardrailViolationError
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.models.context import EventContext
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.working_memory import (
    FIELD_OWNERSHIP,
    SCRATCHPAD_LIMIT,
    WRITER_ALIASES,
    BoundWorkingMemory,
    WorkingMemory,
    WriterCapability,
    _MemoryEngine,
)
from app.services.working_memory_bound import OwnerMemoryOps

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(migrated: None) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[RedisClient]:
    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.skip("Redis not reachable; start Compose redis first")
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def store(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> EventContextStore:
    return EventContextStore(redis_client, session_factory)


@pytest_asyncio.fixture
async def wm(
    store: EventContextStore,
    redis_client: RedisClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> WorkingMemory:
    memory = WorkingMemory(store, redis_client, wm_strict=True)
    degraded = DegradedFlagService(store, session_factory)
    memory.bind_degraded_flag_service(degraded)
    return memory


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _summary(event_id: str) -> EventSummary:
    return EventSummary(
        event_id=event_id,
        event_type=EventType.INSIDER_THREAT,
        title="wm-test",
        status=EventStatus.NEW,
        severity=Severity.LOW,
        risk_score=10,
        final_verdict=FinalVerdict.NONE,
        writeback_required=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )


async def _seed_event(session_factory: async_sessionmaker[AsyncSession]) -> str:
    event_id = f"evt-20260713-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="insider_threat",
                    title="wm-test",
                    creation_source_ref={"source_object_id": f"INC-{_sfx()}"},
                )
            )
    return event_id


# --------------------------------------------------------------------------- #
# Ownership table
# --------------------------------------------------------------------------- #


def test_field_ownership_covers_event_context_both_directions() -> None:
    schema = set(EventContext.model_fields.keys())
    owned = set(FIELD_OWNERSHIP.keys())
    assert schema == owned, {
        "missing": sorted(schema - owned),
        "ghost": sorted(owned - schema),
    }
    assert "system" not in FIELD_OWNERSHIP.values()
    assert FIELD_OWNERSHIP["false_positive_match"] == "FalsePositiveMatcher"
    assert WRITER_ALIASES["RuleBasedFalsePositiveHook"] == "FalsePositiveMatcher"
    assert FIELD_OWNERSHIP["degraded_flags"] == "DegradedFlagService"
    assert FIELD_OWNERSHIP["scratchpad"] == "WorkingMemory"


# --------------------------------------------------------------------------- #
# Read / write
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_owner_write_success_and_access_log(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    triage = wm.for_writer("TriageAgent")
    risk = wm.for_writer("RiskAgent")

    await triage.write(
        event_id,
        "triage_result",
        {"severity": "high"},
    )
    value = await risk.read(event_id, "triage_result")
    assert value == {"severity": "high"}

    logs = await wm.get_access_log(event_id)
    write_logs = [e for e in logs if e.op == "write" and e.key == "triage_result"]
    read_logs = [e for e in logs if e.op == "read" and e.key == "triage_result"]
    assert write_logs and write_logs[-1].allowed is True
    assert write_logs[-1].agent_name == "TriageAgent"
    assert read_logs and read_logs[-1].allowed is True


@pytest.mark.asyncio
async def test_non_owner_write_rejected_and_logged(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    triage = wm.for_writer("TriageAgent")
    evidence = wm.for_writer("EvidenceAgent")
    await triage.write(event_id, "triage_result", {"ok": True})

    with pytest.raises(GuardrailViolationError) as exc_info:
        await evidence.write(
            event_id,
            "triage_result",
            {"ok": False},
        )
    assert exc_info.value.error_code == "working_memory_unauthorized_write"
    assert await store.get(event_id, "triage_result") == {"ok": True}

    logs = await wm.get_access_log(event_id)
    denied = [e for e in logs if e.op == "write" and e.allowed is False]
    assert denied
    assert denied[-1].agent_name == "EvidenceAgent"
    assert denied[-1].key == "triage_result"


@pytest.mark.asyncio
async def test_memory_access_log_persists_beyond_projection_capacity(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    reader = wm.for_writer("RiskAgent")
    with patch("app.services.working_memory_bound.ACCESS_LOG_LIMIT", 2):
        for _ in range(5):
            await reader.read(event_id, "triage_result")
    assert len(wm._access_logs[event_id]) == 2
    assert len(await wm.get_access_log(event_id)) == 5


@pytest.mark.asyncio
async def test_denied_write_is_persisted_as_audit_record(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    writer = wm.for_writer("EvidenceAgent")
    with pytest.raises(GuardrailViolationError):
        await writer.write(event_id, "triage_result", {"forbidden": True})
    async with session_factory() as session:
        row = await session.scalar(
            select(orm.MemoryAccessAuditLog).where(
                orm.MemoryAccessAuditLog.event_id == event_id,
                orm.MemoryAccessAuditLog.allowed.is_(False),
            )
        )
    assert row is not None and row.key == "triage_result"


@pytest.mark.asyncio
async def test_access_log_projection_eviction_does_not_delete_audit_history(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    await wm.for_writer("RiskAgent").read(event_id, "triage_result")
    wm._access_logs.clear()
    logs = await wm.get_access_log(event_id)
    assert len(logs) == 1 and logs[0].op == "read"


@pytest.mark.asyncio
async def test_access_log_is_append_only(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    reader = wm.for_writer("RiskAgent")
    await reader.read(event_id, "triage_result")
    await reader.read(event_id, "triage_result")
    async with session_factory() as session:
        count = await session.scalar(
            select(func.count()).select_from(orm.MemoryAccessAuditLog).where(
                orm.MemoryAccessAuditLog.event_id == event_id
            )
        )
    assert count == 2


@pytest.mark.asyncio
async def test_false_positive_hook_alias_allowed(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    hook = wm.for_writer("RuleBasedFalsePositiveHook")
    await hook.write(
        event_id,
        "false_positive_match",
        {"close_as_fp": True},
    )
    assert await store.get(event_id, "false_positive_match") == {"close_as_fp": True}


@pytest.mark.asyncio
async def test_wm_strict_false_still_rejects_non_owner(
    store: EventContextStore,
    redis_client: RedisClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    memory = WorkingMemory(store, redis_client, wm_strict=False)
    memory.bind_degraded_flag_service(DegradedFlagService(store, session_factory))
    evidence = memory.for_writer("EvidenceAgent")

    with pytest.raises(GuardrailViolationError):
        await evidence.write(event_id, "triage_result", {"via": "non-owner"})
    assert await store.get(event_id, "triage_result") is None


@pytest.mark.asyncio
async def test_plain_writer_name_cannot_spoof_capability(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))

    with pytest.raises(GuardrailViolationError):
        await wm.write(
            event_id,
            "triage_result",
            {"spoofed": True},
            writer="TriageAgent",  # type: ignore[arg-type]
        )
    assert await store.get(event_id, "triage_result") is None


@pytest.mark.asyncio
async def test_version_conflict_retries_then_succeeds(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    graph = wm.for_writer("GraphAgent")
    await graph.write(event_id, "graph_output", {"nodes": 1})

    calls = {"n": 0}
    real_cas = store.compare_and_set

    async def flaky_cas(*args: Any, **kwargs: Any) -> bool:
        calls["n"] += 1
        if calls["n"] == 1:
            return False
        return await real_cas(*args, **kwargs)

    with patch.object(store, "compare_and_set", side_effect=flaky_cas):
        await graph.write(event_id, "graph_output", {"nodes": 2})

    assert calls["n"] >= 2
    assert await store.get(event_id, "graph_output") == {"nodes": 2}


@pytest.mark.asyncio
async def test_stale_redis_version_does_not_block_owner_write(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    graph = wm.for_writer("GraphAgent")
    await graph.write(event_id, "graph_output", {"n": 1})

    # Simulate a degraded (Redis-down) write that advanced the authoritative DB
    # version while the Redis {key}__version cache stayed behind.
    async with session_factory() as session:
        async with session.begin():
            await session.execute(
                text(
                    "UPDATE event_context_field_version SET current_version = 5 "
                    "WHERE event_id = :e AND field_name = 'graph_output'"
                ),
                {"e": event_id},
            )

    # Owner write must still succeed: CAS ``expected`` comes from the DB, not the
    # stale Redis cache (else this would raise version_conflict).
    await graph.write(event_id, "graph_output", {"n": 2})
    assert await store.get(event_id, "graph_output") == {"n": 2}
    assert await store.get_field_version(event_id, "graph_output") == 6


# --------------------------------------------------------------------------- #
# Scratchpad
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_scratchpad_append_and_fifo_roll(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    triage = wm.for_writer("TriageAgent")

    for i in range(SCRATCHPAD_LIMIT + 5):
        await triage.append_scratchpad(event_id, f"note-{i}")

    entries = await triage.read_scratchpad(event_id)
    assert len(entries) == SCRATCHPAD_LIMIT
    assert entries[0].note == "note-5"
    assert entries[-1].note == f"note-{SCRATCHPAD_LIMIT + 4}"

    mirrored = await store.get(event_id, "scratchpad")
    assert isinstance(mirrored, list)
    assert len(mirrored) == SCRATCHPAD_LIMIT

    raw = await redis_client.get_client().hget(f"shadowtrace:wm:{event_id}", "scratchpad")
    assert raw is not None
    assert len(RedisClient.loads(raw)) == SCRATCHPAD_LIMIT


@pytest.mark.asyncio
async def test_concurrent_scratchpad_appends_recompute_after_cas_conflict(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    triage = wm.for_writer("TriageAgent")
    evidence = wm.for_writer("EvidenceAgent")
    real_get_versioned = store.get_versioned_field
    reads_ready = asyncio.Event()
    reads = 0

    async def synchronized_get_versioned(
        target_event_id: str,
        key: str,
    ) -> tuple[Any, int]:
        nonlocal reads
        result = await real_get_versioned(target_event_id, key)
        if key == "scratchpad" and reads < 2:
            reads += 1
            if reads == 2:
                reads_ready.set()
            await reads_ready.wait()
        return result

    with patch.object(
        store,
        "get_versioned_field",
        side_effect=synchronized_get_versioned,
    ):
        await asyncio.gather(
            triage.append_scratchpad(event_id, "first"),
            evidence.append_scratchpad(event_id, "second"),
        )

    entries = await triage.read_scratchpad(event_id)
    assert {entry.note for entry in entries} == {"first", "second"}
    assert {entry.agent_name for entry in entries} == {"TriageAgent", "EvidenceAgent"}


@pytest.mark.asyncio
async def test_redis_unavailable_marks_degraded_flag_once(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    risk = wm.for_writer("RiskAgent")

    with patch.object(store._redis, "ping", new_callable=AsyncMock, return_value=False):
        with patch.object(wm._redis, "ping", new_callable=AsyncMock, return_value=False):
            with patch("app.services.context_service.asyncio.sleep", new_callable=AsyncMock):
                await risk.write(
                    event_id,
                    "risk_assessment",
                    {"score": 1},
                )
                await risk.write(
                    event_id,
                    "risk_assessment",
                    {"score": 2},
                )

    async with session_factory() as session:
        se = await session.get(orm.SecurityEvent, event_id)
        assert se is not None
        assert any(
            str(f).startswith("redis_context_unavailable=") for f in (se.degraded_flags or [])
        )

    flags = await store.get(event_id, "degraded_flags")
    assert "redis_context_unavailable=true" in flags


@pytest.mark.asyncio
async def test_bound_working_memory_has_no_cross_owner_binding_api(
    wm: WorkingMemory,
) -> None:
    bound = wm.for_writer("TriageAgent")
    assert not hasattr(BoundWorkingMemory, "for_writer")
    assert not hasattr(bound, "for_writer")


@pytest.mark.asyncio
async def test_bound_working_memory_cannot_mint_cross_owner_capability(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    bound = wm.for_writer("TriageAgent")
    forged = WriterCapability(owner="RiskAgent", _nonce=object())
    with pytest.raises(GuardrailViolationError) as exc_info:
        await wm.write(event_id, "risk_assessment", {"score": 1}, writer=forged)
    assert exc_info.value.error_code == "working_memory_unauthorized_write"
    with pytest.raises(GuardrailViolationError) as bound_exc:
        await bound.write(event_id, "risk_assessment", {"score": 1})
    assert bound_exc.value.error_code == "working_memory_unauthorized_write"


@pytest.mark.asyncio
async def test_released_capability_cannot_write(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    bound = wm.for_writer("TriageAgent")
    bound.release()
    with pytest.raises(GuardrailViolationError) as exc_info:
        await bound.write(event_id, "triage_result", {"ok": True})
    assert exc_info.value.error_code == "working_memory_unauthorized_write"


@pytest.mark.asyncio
async def test_live_binding_survives_idle_ttl_and_capacity_pressure(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    live = wm.for_writer("TriageAgent")
    with (
        patch("app.services.working_memory.CAPABILITY_LIMIT", 1),
        patch("app.services.working_memory.CAPABILITY_TTL_SECONDS", 0),
        patch("app.services.working_memory.time.monotonic", return_value=10_000.0),
    ):
        with pytest.raises(GuardrailViolationError):
            wm.for_writer("RiskAgent")
        await live.write(event_id, "triage_result", {"ok": True})
    assert await store.get(event_id, "triage_result") == {"ok": True}


@pytest.mark.asyncio
async def test_orphan_capability_expires_after_ttl_while_live_binding_survives(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    live = wm.for_writer("TriageAgent")
    with patch("app.services.working_memory.time.monotonic", return_value=100.0):
        orphan_bound = wm.for_writer("RiskAgent")
        orphan = orphan_bound._capability
        del orphan_bound
        gc.collect()
    with (
        patch("app.services.working_memory.time.monotonic", return_value=10_000.0),
        patch("app.services.working_memory.CAPABILITY_TTL_SECONDS", 5),
    ):
        with pytest.raises(GuardrailViolationError) as exc_info:
            await wm.write(event_id, "risk_assessment", {"expired": True}, writer=orphan)
        assert exc_info.value.error_code == "working_memory_unauthorized_write"
        await live.write(event_id, "triage_result", {"ok": True})
    assert await store.get(event_id, "triage_result") == {"ok": True}
    assert await store.get(event_id, "risk_assessment") is None


@pytest.mark.asyncio
async def test_cached_writer_remains_authorized_after_capability_ttl(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    risk = wm.for_writer("RiskAgent")
    from unittest.mock import patch

    with patch("app.services.working_memory.time.monotonic", return_value=10_000.0), patch(
        "app.services.working_memory.CAPABILITY_TTL_SECONDS", 5
    ):
        await risk.write(event_id, "risk_assessment", {"score": 9})
    assert await store.get(event_id, "risk_assessment") == {"score": 9}


def _iter_agent_graph(root: object, *, max_depth: int = 8) -> Iterator[object]:
    """Walk an Agent-facing bound view using the contract-review attack surface.

    Traverses ``__slots__``, ``__dict__``, ``__closure__``, ``__globals__``,
    weakrefs, and method ``__self__``. Engine-private ops must not appear as
    slots, instance attrs, closures, or module-level registries from this view.
    """
    seen: set[int] = set()
    stack: list[tuple[object, int]] = [(root, 0)]
    for _, member in inspect.getmembers(
        root, predicate=lambda obj: inspect.ismethod(obj) or inspect.isfunction(obj)
    ):
        stack.append((member, 1))

    def _push(child: object, depth: int) -> None:
        if child is None:
            return
        stack.append((child, depth))

    while stack:
        current, depth = stack.pop()
        ident = id(current)
        if ident in seen or depth > max_depth:
            continue
        seen.add(ident)
        yield current
        if current is None or isinstance(
            current, (str, bytes, int, float, bool, type, types.ModuleType)
        ):
            continue
        children_depth = depth + 1
        func = current
        if inspect.ismethod(current):
            _push(current.__func__, children_depth)
            _push(getattr(current, "__self__", None), children_depth)
            func = current.__func__
        if inspect.isfunction(func) or inspect.ismethod(func):
            closure = getattr(func, "__closure__", None)
            if closure:
                for cell in closure:
                    try:
                        _push(cell.cell_contents, children_depth)
                    except ValueError:
                        continue
            globals_map = getattr(func, "__globals__", None)
            if isinstance(globals_map, dict):
                _push(globals_map, children_depth)
                for key, value in globals_map.items():
                    if key == "__builtins__":
                        continue
                    _push(value, children_depth)
        slots = getattr(current, "__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if slot in ("__weakref__", "__dict__"):
                continue
            try:
                _push(getattr(current, slot), children_depth)
            except Exception:
                continue
        mapping = getattr(current, "__dict__", None)
        if isinstance(mapping, dict):
            _push(mapping, children_depth)
            for value in mapping.values():
                _push(value, children_depth)
        if isinstance(current, dict):
            for key, value in current.items():
                _push(key, children_depth)
                _push(value, children_depth)
        elif isinstance(current, (list, tuple, set, frozenset)):
            for item in current:
                _push(item, children_depth)
        try:
            referent = current() if isinstance(current, weakref.ref) else None
        except TypeError:
            referent = None
        if referent is not None:
            _push(referent, children_depth)


def _iter_reachable(root: object, *, max_depth: int = 6) -> Iterator[object]:
    yield from _iter_agent_graph(root, max_depth=max_depth)


def _iter_reflection(root: object, *, max_depth: int = 8) -> Iterator[object]:
    yield from _iter_agent_graph(root, max_depth=max_depth)


def _is_store_like(obj: object) -> bool:
    return all(
        callable(getattr(obj, name, None))
        for name in ("compare_and_set", "get", "get_field_version")
    )


def _extract_ops_reference(bound: BoundWorkingMemory) -> OwnerMemoryOps | None:
    """Best-effort capture of a leaked OwnerMemoryOps for resurrection attacks."""
    direct = getattr(bound, "_ops", None)
    if isinstance(direct, OwnerMemoryOps):
        return direct
    port = getattr(bound, "_port", None)
    if port is None:
        return None
    slots = getattr(type(port), "__slots__", ())
    if isinstance(slots, str):
        slots = (slots,)
    for slot in slots:
        fn = getattr(port, slot, None)
        defaults = getattr(fn, "__defaults__", None)
        if not defaults:
            continue
        for item in defaults:
            if isinstance(item, OwnerMemoryOps):
                return item
    return None


_FOREIGN_FIELD = {
    "TriageAgent": "risk_assessment",
    "RiskAgent": "triage_result",
}


async def _assert_store_like_cannot_write_foreign(
    obj: object,
    *,
    event_id: str,
    owner: str,
    store: EventContextStore,
) -> None:
    if not _is_store_like(obj) and not callable(getattr(obj, "compare_and_set", None)):
        return
    foreign_key = _FOREIGN_FIELD[owner]
    before = await store.get(event_id, foreign_key)
    payload = {"stolen": True, "via": type(obj).__name__}
    cas = getattr(obj, "compare_and_set", None)
    if callable(cas):
        expected = 0
        get_version = getattr(obj, "get_field_version", None)
        if callable(get_version):
            try:
                expected = await get_version(event_id, foreign_key) or 0
            except Exception:
                expected = 0
        try:
            result = await cas(event_id, foreign_key, expected, payload)
        except GuardrailViolationError as exc:
            assert exc.error_code == "working_memory_unauthorized_write"
        except Exception:
            result = False
        else:
            assert result is not True
    setter = getattr(obj, "set", None)
    if callable(setter) and _is_store_like(obj):
        try:
            await setter(event_id, foreign_key, payload)
        except GuardrailViolationError as exc:
            assert exc.error_code == "working_memory_unauthorized_write"
        except Exception:
            pass
    assert await store.get(event_id, foreign_key) == before


def _assert_bound_graph_isolated(
    bound: BoundWorkingMemory,
    reachable: list[object],
    *,
    other_owner: str | None = None,
) -> None:
    assert not any(isinstance(obj, WorkingMemory) for obj in reachable)
    assert not any(isinstance(obj, _MemoryEngine) for obj in reachable)
    assert not any(isinstance(obj, EventContextStore) for obj in reachable)
    assert not any(isinstance(obj, OwnerMemoryOps) for obj in reachable)
    assert not any(
        callable(obj) and getattr(obj, "__name__", "") == "for_writer" for obj in reachable
    )
    assert not hasattr(BoundWorkingMemory, "for_writer")
    assert not hasattr(bound, "for_writer")
    stolen_caps = [
        obj
        for obj in reachable
        if isinstance(obj, WriterCapability) and obj.owner != bound.writer_name
    ]
    assert stolen_caps == []
    stolen_bounds = [
        obj
        for obj in reachable
        if isinstance(obj, BoundWorkingMemory) and obj is not bound
    ]
    if other_owner is not None:
        assert not any(
            isinstance(obj, BoundWorkingMemory) and obj.writer_name == other_owner
            for obj in reachable
        )
    assert stolen_bounds == []


@pytest.mark.asyncio
async def test_bound_working_memory_cannot_reach_root_or_mint_cross_owner(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    bound = wm.for_writer("TriageAgent")
    reachable = list(_iter_agent_graph(bound))
    _assert_bound_graph_isolated(bound, reachable, other_owner="RiskAgent")
    for name in ("_memory", "_root", "_factory", "_ops"):
        value = getattr(bound, name, None)
        assert not isinstance(
            value, (WorkingMemory, EventContextStore, OwnerMemoryOps, _MemoryEngine)
        )
    with pytest.raises(AttributeError):
        bound.for_writer("RiskAgent")  # type: ignore[attr-defined]
    with pytest.raises(GuardrailViolationError) as exc_info:
        await bound.write(event_id, "risk_assessment", {"score": 1})
    assert exc_info.value.error_code == "working_memory_unauthorized_write"


@pytest.mark.asyncio
async def test_agent_bound_view_only_operates_with_its_own_capability(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    triage = wm.for_writer("TriageAgent")
    await triage.write(event_id, "triage_result", {"ok": True})
    assert await triage.read(event_id, "triage_result") == {"ok": True}
    with pytest.raises(GuardrailViolationError) as exc_info:
        await triage.write(event_id, "risk_assessment", {"score": 9})
    assert exc_info.value.error_code == "working_memory_unauthorized_write"
    await triage.append_scratchpad(event_id, "note")
    notes = await triage.read_scratchpad(event_id)
    assert notes[-1].note == "note"


@pytest.mark.asyncio
async def test_released_capability_remains_invalid_after_gc_and_rebind(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    bound = wm.for_writer("TriageAgent")
    stale = bound._capability
    bound.release()
    del bound
    gc.collect()
    with pytest.raises(GuardrailViolationError) as stale_exc:
        await wm.write(event_id, "triage_result", {"stale": True}, writer=stale)
    assert stale_exc.value.error_code == "working_memory_unauthorized_write"
    rebound = wm.for_writer("TriageAgent")
    await rebound.write(event_id, "triage_result", {"ok": True})
    with pytest.raises(GuardrailViolationError):
        await wm.write(event_id, "triage_result", {"stale": True}, writer=stale)
    rebound.release()
    with pytest.raises(GuardrailViolationError):
        await rebound.write(event_id, "triage_result", {"after-release": True})


@pytest.mark.asyncio
async def test_bound_working_memory_globals_cannot_steal_other_owner_capability(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    triage = wm.for_writer("TriageAgent")
    risk = wm.for_writer("RiskAgent")
    reachable = list(_iter_reflection(triage))
    _assert_bound_graph_isolated(triage, reachable, other_owner="RiskAgent")
    write_fn = triage.write.__func__
    write_globals = write_fn.__globals__
    assert "_ENGINE_LEASES" not in write_globals
    assert "WorkingMemory" not in write_globals
    assert "_MemoryEngine" not in write_globals
    assert "for_writer" not in write_globals
    issued_maps = [
        obj
        for obj in reachable
        if isinstance(obj, dict)
        and any(isinstance(key, WriterCapability) and key.owner != "TriageAgent" for key in obj)
    ]
    assert issued_maps == []
    with pytest.raises(GuardrailViolationError) as cross_owner:
        await triage.write(event_id, "risk_assessment", {"score": 99})
    assert cross_owner.value.error_code == "working_memory_unauthorized_write"
    assert await store.get(event_id, "risk_assessment") is None
    await risk.write(event_id, "risk_assessment", {"score": 1})
    assert await store.get(event_id, "risk_assessment") == {"score": 1}


@pytest.mark.asyncio
async def test_bound_view_object_graph_cannot_cas_foreign_owner_fields(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    triage = wm.for_writer("TriageAgent")
    risk = wm.for_writer("RiskAgent")
    await triage.write(event_id, "triage_result", {"ok": True})
    await risk.write(event_id, "risk_assessment", {"score": 1})

    for bound in (triage, risk):
        reachable = list(_iter_agent_graph(bound))
        _assert_bound_graph_isolated(
            bound,
            reachable,
            other_owner="RiskAgent" if bound is triage else "TriageAgent",
        )
        for obj in reachable:
            await _assert_store_like_cannot_write_foreign(
                obj,
                event_id=event_id,
                owner=bound.writer_name,
                store=store,
            )

    assert await store.get(event_id, "triage_result") == {"ok": True}
    assert await store.get(event_id, "risk_assessment") == {"score": 1}

    write_globals = triage.write.__func__.__globals__
    store_cls = write_globals.get("EventContextStore")
    before_risk = await store.get(event_id, "risk_assessment")
    if store_cls is EventContextStore:
        try:
            stolen = store_cls(object(), object())
            cas = getattr(stolen, "compare_and_set", None)
            if callable(cas):
                await cas(event_id, "risk_assessment", 0, {"pwn": 1})
        except Exception:
            pass
    assert await store.get(event_id, "risk_assessment") == before_risk


@pytest.mark.asyncio
async def test_bound_private_store_reference_cannot_cas_foreign_field(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    triage = wm.for_writer("TriageAgent")
    risk = wm.for_writer("RiskAgent")
    await triage.write(event_id, "triage_result", {"ok": True})
    await risk.write(event_id, "risk_assessment", {"score": 1})

    for bound, foreign_key, payload in (
        (triage, "risk_assessment", {"stolen": "triage"}),
        (risk, "triage_result", {"stolen": "risk"}),
    ):
        before = await store.get(event_id, foreign_key)
        try:
            leaked = bound._ops._store  # type: ignore[attr-defined]
        except AttributeError:
            leaked = None
        else:
            assert leaked is None or not _is_store_like(leaked)
            if _is_store_like(leaked):
                expected = await leaked.get_field_version(event_id, foreign_key) or 0
                try:
                    result = await leaked.compare_and_set(
                        event_id, foreign_key, expected, payload
                    )
                except GuardrailViolationError as exc:
                    assert exc.error_code == "working_memory_unauthorized_write"
                    result = False
                assert result is not True
        for name in dir(bound):
            if name.startswith("__"):
                continue
            try:
                attr = getattr(bound, name)
            except Exception:
                continue
            await _assert_store_like_cannot_write_foreign(
                attr,
                event_id=event_id,
                owner=bound.writer_name,
                store=store,
            )
        assert await store.get(event_id, foreign_key) == before


@pytest.mark.asyncio
async def test_release_is_permanent_against_alive_flip_and_stale_ops(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    bound = wm.for_writer("TriageAgent")
    stale_cap = bound._capability
    captured_ops = _extract_ops_reference(bound)
    captured_port = getattr(bound, "_port", None)
    captured_write = bound.write
    captured_read = bound.read
    captured_append = bound.append_scratchpad

    bound.release()

    with pytest.raises(GuardrailViolationError) as exc_info:
        await bound.write(event_id, "triage_result", {"after": True})
    assert exc_info.value.error_code == "working_memory_unauthorized_write"
    with pytest.raises(GuardrailViolationError) as exc_info:
        await bound.read(event_id, "triage_result")
    assert exc_info.value.error_code == "working_memory_unauthorized_write"
    with pytest.raises(GuardrailViolationError) as exc_info:
        await bound.append_scratchpad(event_id, "after")
    assert exc_info.value.error_code == "working_memory_unauthorized_write"
    with pytest.raises(GuardrailViolationError) as exc_info:
        await captured_write(event_id, "triage_result", {"captured": True})
    assert exc_info.value.error_code == "working_memory_unauthorized_write"
    with pytest.raises(GuardrailViolationError) as exc_info:
        await captured_read(event_id, "triage_result")
    assert exc_info.value.error_code == "working_memory_unauthorized_write"
    with pytest.raises(GuardrailViolationError) as exc_info:
        await captured_append(event_id, "captured")
    assert exc_info.value.error_code == "working_memory_unauthorized_write"

    ops = getattr(bound, "_ops", None)
    alive = getattr(ops, "_alive", None) if ops is not None else None
    if isinstance(alive, list) and alive:
        alive[0] = True
    if captured_ops is not None:
        captured_alive = getattr(captured_ops, "_alive", None)
        if isinstance(captured_alive, list) and captured_alive:
            captured_alive[0] = True
        with pytest.raises(GuardrailViolationError) as ops_exc:
            await captured_ops.write(event_id, "triage_result", {"resurrected": True})
        assert ops_exc.value.error_code == "working_memory_unauthorized_write"
        leaked_store = getattr(captured_ops, "_store", None)
        if leaked_store is not None and callable(getattr(leaked_store, "compare_and_set", None)):
            before = await store.get(event_id, "risk_assessment")
            expected = 0
            get_version = getattr(leaked_store, "get_field_version", None)
            if callable(get_version):
                expected = await get_version(event_id, "risk_assessment") or 0
            try:
                result = await leaked_store.compare_and_set(
                    event_id, "risk_assessment", expected, {"stolen": True}
                )
            except GuardrailViolationError as exc:
                assert exc.error_code == "working_memory_unauthorized_write"
                result = False
            assert result is not True
            assert await store.get(event_id, "risk_assessment") == before

    try:
        object.__setattr__(bound, "_ops", captured_ops)
    except Exception:
        pass
    try:
        object.__setattr__(bound, "_port", captured_port)
    except Exception:
        pass
    with pytest.raises(GuardrailViolationError) as stuffed:
        await bound.write(event_id, "triage_result", {"stuffed": True})
    assert stuffed.value.error_code == "working_memory_unauthorized_write"

    with pytest.raises(GuardrailViolationError) as stale_exc:
        await wm.write(event_id, "triage_result", {"stale": True}, writer=stale_cap)
    assert stale_exc.value.error_code == "working_memory_unauthorized_write"
    assert await store.get(event_id, "triage_result") is None

    async with session_factory() as session:
        denied = await session.scalar(
            select(orm.MemoryAccessAuditLog).where(
                orm.MemoryAccessAuditLog.event_id == event_id,
                orm.MemoryAccessAuditLog.allowed.is_(False),
            )
        )
    assert denied is not None

    del bound
    gc.collect()
    rebound = wm.for_writer("TriageAgent")
    await rebound.write(event_id, "triage_result", {"ok": True})
    assert await store.get(event_id, "triage_result") == {"ok": True}
    with pytest.raises(GuardrailViolationError):
        await wm.write(event_id, "triage_result", {"stale": True}, writer=stale_cap)


@pytest.mark.asyncio
async def test_revoke_is_release_alias_and_cannot_be_revived(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    bound = wm.for_writer("RiskAgent")
    bound.revoke()
    with pytest.raises(GuardrailViolationError) as exc_info:
        await bound.write(event_id, "risk_assessment", {"revoked": True})
    assert exc_info.value.error_code == "working_memory_unauthorized_write"
    assert bound.release is bound.revoke or bound.revoke.__func__ is bound.release.__func__


@pytest.mark.asyncio
async def test_legal_owner_write_and_scratchpad_survive_isolation_fix(
    wm: WorkingMemory,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_event(session_factory)
    await store.init_context(event_id, _summary(event_id))
    triage = wm.for_writer("TriageAgent")
    risk = wm.for_writer("RiskAgent")
    evidence = wm.for_writer("EvidenceAgent")

    await triage.write(event_id, "triage_result", {"ok": True})
    assert await store.get(event_id, "triage_result") == {"ok": True}
    await risk.append_scratchpad(event_id, "from-risk")
    await evidence.append_scratchpad(event_id, "from-evidence")
    notes = {entry.note for entry in await triage.read_scratchpad(event_id)}
    assert notes == {"from-risk", "from-evidence"}

    with pytest.raises(GuardrailViolationError) as exc_info:
        await risk.write(event_id, "triage_result", {"nope": True})
    assert exc_info.value.error_code == "working_memory_unauthorized_write"
    assert await store.get(event_id, "triage_result") == {"ok": True}

    async with session_factory() as session:
        denied = await session.scalar(
            select(orm.MemoryAccessAuditLog).where(
                orm.MemoryAccessAuditLog.event_id == event_id,
                orm.MemoryAccessAuditLog.allowed.is_(False),
                orm.MemoryAccessAuditLog.key == "triage_result",
            )
        )
    assert denied is not None
    assert denied.agent_name == "RiskAgent"
