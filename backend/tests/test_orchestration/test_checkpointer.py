"""Checkpoint memory fallback observability tests (ISSUE-175 / #701)."""

from __future__ import annotations

from typing import Any

import pytest

from app.core.metrics import checkpoint_health_snapshot, reset_checkpoint_metrics_for_tests
from app.orchestration.checkpointer import (
    RedisCheckpointer,
    checkpoint_key_for_event,
    get_checkpoint_health,
    reset_checkpoint_health_state_for_tests,
)


class FakeRedisStore:
    def __init__(self, *, fail_set: bool = False) -> None:
        self.values: dict[str, bytes] = {}
        self.fail_set = fail_set

    async def get(self, key: str) -> bytes | None:
        return self.values.get(key)

    async def set(self, key: str, value: bytes, *, ex: int | None = None) -> None:
        if self.fail_set:
            raise ConnectionError("redis set failed")
        self.values[key] = value

    async def delete(self, key: str) -> None:
        self.values.pop(key, None)


class FakeRedisClient:
    def __init__(self, *, available: bool = True, fail_set: bool = False) -> None:
        self.available = available
        self.store = FakeRedisStore(fail_set=fail_set)

    async def ping(self) -> bool:
        return self.available

    def get_client(self) -> FakeRedisStore:
        return self.store


def _config(thread_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread_id}}


@pytest.fixture(autouse=True)
def _reset_checkpoint_observability() -> None:
    reset_checkpoint_health_state_for_tests()
    yield
    reset_checkpoint_health_state_for_tests()


@pytest.mark.asyncio
async def test_redis_client_none_records_fallback_trigger() -> None:
    saver = await RedisCheckpointer.create(None)  # type: ignore[arg-type]
    assert saver.memory_fallback is True
    health = get_checkpoint_health()
    assert health["fallback_triggers"] == 1
    assert health["memory_fallback"] is True


@pytest.mark.asyncio
async def test_hydrate_failure_pins_thread_and_fallback() -> None:
    redis = FakeRedisClient()

    class FailingGetStore(FakeRedisStore):
        async def get(self, key: str) -> bytes | None:
            raise ConnectionError("redis get failed")

    redis.store = FailingGetStore()  # type: ignore[assignment]
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    assert saver.memory_fallback is False

    await saver._hydrate("evt-load-fail")
    assert saver.memory_fallback is True
    assert saver._memory_pinned_threads == {"evt-load-fail"}
    health = get_checkpoint_health()
    assert health["memory_pinned_thread_count"] == 1


@pytest.mark.asyncio
async def test_recovery_health_shows_pinned_threads_while_redis_resumed() -> None:
    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(
        redis,  # type: ignore[arg-type]
        attempt_redis_recovery=True,
        recovery_interval_seconds=0.0,
    )
    redis.store.fail_set = True
    saver._memory.storage["evt-pinned"] = {}
    await saver._persist("evt-pinned")

    redis.store.fail_set = False
    await saver._maybe_attempt_redis_recovery()
    health = get_checkpoint_health()
    assert health["memory_fallback"] is False
    assert health["memory_pinned_thread_count"] == 1


@pytest.mark.asyncio
async def test_any_live_checkpointer_fallback_marks_health_degraded() -> None:
    await RedisCheckpointer.create(FakeRedisClient())  # type: ignore[arg-type]
    await RedisCheckpointer.create(FakeRedisClient(available=False))  # type: ignore[arg-type]

    health = get_checkpoint_health()
    assert health["status"] == "degraded"
    assert health["memory_fallback"] is True


@pytest.mark.asyncio
async def test_fallback_sets_health_and_metrics() -> None:
    redis = FakeRedisClient(available=False)
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]

    assert saver.memory_fallback is True
    assert saver.recoverable is False

    health = get_checkpoint_health()
    assert health["status"] == "degraded"
    assert health["memory_fallback"] is True
    assert health["recoverable"] is False
    assert health["fallback_triggers"] == 1
    assert health["redis_recovery_enabled"] is False
    assert health["memory_pinned_thread_count"] == 0

    snapshot = checkpoint_health_snapshot()
    assert snapshot["memory_fallback"] is True
    assert snapshot["fallback_triggers"] == 1


@pytest.mark.asyncio
async def test_default_memory_fallback_without_recovery_flag() -> None:
    redis = FakeRedisClient()
    redis.store.fail_set = True
    saver = await RedisCheckpointer.create(
        redis,  # type: ignore[arg-type]
        attempt_redis_recovery=False,
    )
    assert saver.memory_fallback is False

    saver._memory.storage["evt-fallback-default"] = {}
    await saver._persist("evt-fallback-default")
    assert saver.memory_fallback is True
    assert saver._memory_pinned_threads == {"evt-fallback-default"}
    assert redis.store.values == {}

    saver._memory.storage["evt-fallback-default-2"] = {}
    await saver._persist("evt-fallback-default-2")
    assert redis.store.values == {}


@pytest.mark.asyncio
async def test_recovery_restores_redis_only_for_new_threads() -> None:
    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(
        redis,  # type: ignore[arg-type]
        attempt_redis_recovery=True,
        recovery_interval_seconds=0.0,
    )
    redis.store.fail_set = True

    saver._memory.storage["evt-pinned"] = {}
    await saver._persist("evt-pinned")
    assert saver.memory_fallback is True
    assert saver._memory_pinned_threads == {"evt-pinned"}

    redis.store.fail_set = False
    await saver._maybe_attempt_redis_recovery()
    saver._memory.storage["evt-redis-resumed"] = {}
    await saver._persist("evt-redis-resumed")

    assert saver.memory_fallback is False
    assert saver.recoverable is True
    assert checkpoint_key_for_event("evt-redis-resumed") in redis.store.values
    assert checkpoint_key_for_event("evt-pinned") not in redis.store.values

    await saver._persist("evt-pinned")
    assert checkpoint_key_for_event("evt-pinned") not in redis.store.values


@pytest.mark.asyncio
async def test_sync_api_still_downgrades_recoverability_once() -> None:
    saver = await RedisCheckpointer.create(FakeRedisClient())  # type: ignore[arg-type]
    assert saver.recoverable is True

    assert saver.get_tuple(_config("evt-sync")) is None
    assert saver.recoverable is False
    assert checkpoint_health_snapshot()["fallback_triggers"] == 1


def test_reset_checkpoint_metrics_for_tests_clears_counters() -> None:
    reset_checkpoint_metrics_for_tests()
    assert checkpoint_health_snapshot()["fallback_triggers"] == 0
