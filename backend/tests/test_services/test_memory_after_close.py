"""Memory consolidation after graph-owned CLOSED transitions."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from app.models.context import EventContext
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.models.security_event import EventSummary
from app.services.memory_after_close import (
    consolidate_memory_after_close,
    spawn_memory_after_close,
)


class _RecordingMemory:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    async def execute(self, payload: Any) -> Any:
        self.calls.append(payload)
        return SimpleNamespace()


class _RaisingMemory:
    async def execute(self, payload: Any) -> Any:
        del payload
        raise RuntimeError("memory boom")


class _Store:
    def __init__(self, context: EventContext) -> None:
        self.context = context

    async def get_full_context(self, event_id: str) -> EventContext:
        del event_id
        return self.context


class _RefreshStore(_Store):
    def __init__(self, context: EventContext, *, fail_refresh: bool = False) -> None:
        super().__init__(context)
        self.fail_refresh = fail_refresh
        self.refresh_count = 0

    async def refresh_closed_snapshot(self, event_id: str) -> EventContext:
        del event_id
        self.refresh_count += 1
        if self.fail_refresh:
            raise RuntimeError("snapshot refresh unavailable")
        return self.context


def _context(event_id: str, status: EventStatus) -> EventContext:
    return EventContext(
        event=EventSummary(
            event_id=event_id,
            event_type=EventType.INSIDER_THREAT,
            title="insider",
            status=status,
            severity=Severity.HIGH,
            risk_score=83,
            final_verdict=FinalVerdict.CONFIRMED_THREAT,
            writeback_required=True,
            writeback_readiness=WritebackReadiness.READY,
            disposition_policy=DispositionPolicy.REQUIRED,
        )
    )


def _closed_context(event_id: str) -> EventContext:
    return _context(event_id, EventStatus.CLOSED)


@pytest.mark.asyncio
async def test_consolidate_memory_after_close_executes_agent() -> None:
    memory = _RecordingMemory()
    await consolidate_memory_after_close(
        "evt-memory-1",
        memory_agent=memory,
        context_store=_Store(_closed_context("evt-memory-1")),
    )
    assert len(memory.calls) == 1
    assert memory.calls[0].event_id == "evt-memory-1"
    assert memory.calls[0].investigation_result.final_status is EventStatus.CLOSED


@pytest.mark.asyncio
async def test_consolidate_skips_when_memory_agent_missing() -> None:
    memory = _RecordingMemory()
    await consolidate_memory_after_close(
        "evt-memory-none",
        memory_agent=None,
        context_store=_Store(_closed_context("evt-memory-none")),
    )
    await consolidate_memory_after_close(
        "evt-memory-none",
        memory_agent=memory,
        context_store=None,
    )
    assert memory.calls == []


@pytest.mark.asyncio
async def test_consolidate_skips_when_snapshot_not_closed() -> None:
    memory = _RecordingMemory()
    await consolidate_memory_after_close(
        "evt-memory-reporting",
        memory_agent=memory,
        context_store=_RefreshStore(_context("evt-memory-reporting", EventStatus.REPORTING)),
    )
    assert memory.calls == []


@pytest.mark.asyncio
async def test_consolidate_skips_when_refresh_fails_and_fallback_not_closed() -> None:
    memory = _RecordingMemory()
    await consolidate_memory_after_close(
        "evt-memory-stale",
        memory_agent=memory,
        context_store=_RefreshStore(
            _context("evt-memory-stale", EventStatus.REPORTING),
            fail_refresh=True,
        ),
    )
    assert memory.calls == []


@pytest.mark.asyncio
async def test_consolidate_swallows_agent_errors() -> None:
    await consolidate_memory_after_close(
        "evt-memory-raise",
        memory_agent=_RaisingMemory(),
        context_store=_Store(_closed_context("evt-memory-raise")),
    )


@pytest.mark.asyncio
async def test_spawn_memory_after_close_runs_in_background() -> None:
    memory = _RecordingMemory()
    task = spawn_memory_after_close(
        "evt-memory-1",
        memory_agent=memory,
        context_store=_Store(_closed_context("evt-memory-1")),
    )
    assert task is not None
    await task
    assert len(memory.calls) == 1


@pytest.mark.asyncio
async def test_spawn_returns_none_without_agent() -> None:
    assert (
        spawn_memory_after_close(
            "evt-memory-none",
            memory_agent=None,
            context_store=_Store(_closed_context("evt-memory-none")),
        )
        is None
    )


@pytest.mark.asyncio
async def test_http_close_helper_spawns_when_closed_and_synced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.v1 import events as events_mod

    spawned: list[str] = []

    def _spawn(event_id: str, **_kwargs: Any) -> None:
        spawned.append(event_id)

    monkeypatch.setattr(
        "app.services.memory_after_close.spawn_memory_after_close",
        _spawn,
    )
    monkeypatch.setattr(
        "app.api.v1.deps._get_investigation_stack",
        AsyncMock(
            return_value={
                "memory": object(),
                "context_store": object(),
                "degraded_flags": None,
            }
        ),
    )
    event = SimpleNamespace(
        event_id="evt-http-1",
        status=EventStatus.CLOSED,
        external_unsynced=False,
    )
    await events_mod._spawn_memory_after_http_close(event)
    assert spawned == ["evt-http-1"]


@pytest.mark.asyncio
async def test_http_close_helper_skips_force_close_unsynced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.v1 import events as events_mod

    spawned: list[str] = []
    monkeypatch.setattr(
        "app.services.memory_after_close.spawn_memory_after_close",
        lambda event_id, **_kwargs: spawned.append(event_id),
    )
    event = SimpleNamespace(
        event_id="evt-http-force",
        status=EventStatus.CLOSED,
        external_unsynced=True,
    )
    await events_mod._spawn_memory_after_http_close(event)
    assert spawned == []
