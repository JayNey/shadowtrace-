from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from app.core.redis_client import RedisClient
from app.models.context import EventContext
from app.services.context_service import EventContextStore, ctx_key, version_field


def _store() -> tuple[EventContextStore, AsyncMock]:
    client = AsyncMock()
    redis = MagicMock()
    redis.get_client.return_value = client
    return EventContextStore(redis, AsyncMock()), client  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_single_field_hit_uses_two_hgets_and_no_ping() -> None:
    store, client = _store()
    client.hget.side_effect = [RedisClient.dumps({"score": 80}), RedisClient.dumps(7)]
    store.get_field_version = AsyncMock(return_value=7)  # type: ignore[method-assign]

    assert await store.get("event-a", "risk_assessment") == {"score": 80}
    assert client.hget.await_count == 2
    client.hget.assert_any_await(ctx_key("event-a"), "risk_assessment")
    client.hget.assert_any_await(ctx_key("event-a"), version_field("risk_assessment"))
    assert store._redis.ping.call_count == 0


@pytest.mark.asyncio
async def test_full_context_hit_uses_one_hgetall_and_no_ping() -> None:
    store, client = _store()
    client.hgetall.return_value = {
        b"risk_assessment": RedisClient.dumps({"score": 80}),
        b"risk_assessment__version": RedisClient.dumps(7),
    }
    store._load_current_field_versions = AsyncMock(  # type: ignore[method-assign]
        return_value={"risk_assessment": 7}
    )

    context = await store.get_full_context("event-a")
    assert context.risk_assessment == {"score": 80}
    client.hgetall.assert_awaited_once_with(ctx_key("event-a"))
    assert store._redis.ping.call_count == 0


@pytest.mark.asyncio
async def test_redis_write_command_counts_with_and_without_log_and_expiry() -> None:
    store, client = _store()
    assert await store._redis_set_fields(
        "event-a", {"risk_assessment": {"score": 80}}, log_entry={"op": "set"}
    )
    client.hset.assert_awaited_once()
    client.rpush.assert_awaited_once()
    client.expire.assert_not_awaited()

    client.reset_mock()
    assert await store._redis_set_fields(
        "event-a", {"risk_assessment": {"score": 81}}, log_entry=None, expire=True
    )
    client.hset.assert_awaited_once()
    client.rpush.assert_not_awaited()
    client.expire.assert_awaited_once()
    assert store._redis.ping.call_count == 0


@pytest.mark.asyncio
async def test_redis_write_retry_count_is_bounded_and_predictable() -> None:
    store, client = _store()
    client.hset.side_effect = [ConnectionError("one"), ConnectionError("two"), None]
    with patch("app.services.context_service.asyncio.sleep", new_callable=AsyncMock) as sleep:
        assert await store._redis_set_fields("event-a", {"x": 1}, log_entry=None)
    assert client.hset.await_count == 3
    assert sleep.await_count == 2

    client.reset_mock()
    client.hset.side_effect = ConnectionError("down")
    with patch("app.services.context_service.asyncio.sleep", new_callable=AsyncMock) as sleep:
        assert not await store._redis_set_fields("event-a", {"x": 1}, log_entry=None)
    assert client.hset.await_count == 4
    assert sleep.await_count == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [SQLAlchemyError("db"), KeyError("missing")])
async def test_database_errors_are_not_misclassified_as_redis_failures(error: Exception) -> None:
    store, client = _store()
    client.hget.return_value = None
    store.rebuild_context = AsyncMock(side_effect=error)  # type: ignore[method-assign]
    with pytest.raises(type(error)):
        await store.get("event-a", "risk_assessment")
    assert not store._degraded_cache


@pytest.mark.asyncio
async def test_context_validation_error_propagates_after_valid_redis_read() -> None:
    store, client = _store()
    client.hgetall.return_value = {
        b"risk_assessment": RedisClient.dumps("not-a-dict"),
        b"risk_assessment__version": RedisClient.dumps(1),
    }
    store._load_current_field_versions = AsyncMock(  # type: ignore[method-assign]
        return_value={"risk_assessment": 1}
    )
    with pytest.raises(ValidationError):
        await store.get_full_context("event-a")
    assert not store._degraded_cache


def test_concurrent_degraded_cache_update_and_eviction_has_no_keyerror() -> None:
    store, _ = _store()
    with patch("app.services.context_service.DEGRADED_CACHE_MAX_ENTRIES", 4):
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(store._cache_degraded, f"event-{index}", EventContext())
                for index in range(100)
            ]
            for future in futures:
                future.result()
    assert len(store._degraded_cache) <= 4


def test_degraded_cache_and_timestamp_index_remain_consistent() -> None:
    store, _ = _store()
    with patch("app.services.context_service.DEGRADED_CACHE_MAX_ENTRIES", 2):
        for index in range(20):
            store._cache_degraded(f"event-{index}", EventContext())
            store._get_degraded_if_fresh(f"event-{index}")
    assert list(store._degraded_cache) == list(store._degraded_cache_ts)


def test_degraded_cache_expires_after_30_seconds() -> None:
    store, _ = _store()
    with patch("app.services.context_service.time.monotonic", side_effect=[0.0, 31.0]):
        store._cache_degraded("event-a", EventContext())
        assert store._get_degraded_if_fresh("event-a") is None
    assert not store._degraded_cache
    assert not store._degraded_cache_ts


@pytest.mark.asyncio
async def test_postgres_error_is_not_converted_to_degraded_cache() -> None:
    store, client = _store()
    client.hget.return_value = None
    store.rebuild_context = AsyncMock(side_effect=SQLAlchemyError("db"))  # type: ignore[method-assign]
    with pytest.raises(SQLAlchemyError):
        await store.get("event-a", "risk_assessment")
    assert not store._degraded_cache


@pytest.mark.asyncio
async def test_validation_error_is_not_converted_to_degraded_cache() -> None:
    store, client = _store()
    client.hgetall.return_value = {
        b"risk_assessment": RedisClient.dumps("not-a-dict"),
        b"risk_assessment__version": RedisClient.dumps(1),
    }
    store._load_current_field_versions = AsyncMock(  # type: ignore[method-assign]
        return_value={"risk_assessment": 1}
    )
    with pytest.raises(ValidationError):
        await store.get_full_context("event-a")
    assert not store._degraded_cache
