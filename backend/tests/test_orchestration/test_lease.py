"""Unit tests for EventLease renewal failure handling (ISSUE-226)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

import pytest

from app.core.errors import DependencyUnavailableError, ValidationError
from app.orchestration.lease import EventLease

_OWNER = "worker-test"


class _FakeRedis:
    """Minimal fake that lets us control ``renew()`` behaviour per-test."""

    def __init__(
        self,
        *,
        owner_id: str = _OWNER,
        renew_side_effect: object = None,
    ) -> None:
        self._owner_id = owner_id
        self._renew_side_effect = renew_side_effect
        self.get_calls: list[str] = []
        self.expire_calls: list[tuple[str, int]] = []

    async def get(self, key: str) -> bytes | None:
        self.get_calls.append(key)
        return self._owner_id.encode("utf-8")

    async def expire(self, key: str, ttl: int) -> bool:
        self.expire_calls.append((key, ttl))
        if callable(self._renew_side_effect):
            return self._renew_side_effect(key)
        if isinstance(self._renew_side_effect, Exception):
            raise self._renew_side_effect
        return True

    async def set(self, *args: object, **kwargs: object) -> bool:
        return True

    def register_script(self, script: str) -> object:
        from app.orchestration.lease import classify_lease_lua_script

        kind = classify_lease_lua_script(script)

        async def _run(*, keys: list[str], args: list[str]) -> int:
            key = keys[0]
            owner_id = args[0]
            if kind == "renew":
                current = await self.get(key)
                if current is None:
                    return -1
                decoded = current.decode("utf-8") if isinstance(current, bytes) else current
                if decoded != owner_id:
                    return 0
                ttl = int(args[1]) if len(args) > 1 else 600
                await self.expire(key, ttl)
                return 1
            return 1

        return _run


class _FakeRedisClient:
    """RedisClient-shaped wrapper so EventLease can call ``get_client()``."""

    def __init__(self, raw: _FakeRedis) -> None:
        self._raw = raw

    def get_client(self) -> _FakeRedis:
        return self._raw


def _lease_with_fake(fake_redis: _FakeRedis) -> EventLease:
    return EventLease(_FakeRedisClient(fake_redis))  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_acquire_and_renew_reject_non_positive_ttl() -> None:
    lease = _lease_with_fake(_FakeRedis())
    with pytest.raises(ValidationError):
        await lease.acquire("evt-ttl", _OWNER, ttl_s=0)
    with pytest.raises(ValidationError):
        await lease.renew("evt-ttl", _OWNER, ttl_s=-1)


_real_asyncio_sleep = asyncio.sleep


async def _instant_sleep(_seconds: float) -> None:
    """Fast-forward renew interval while yielding to the event loop."""
    del _seconds
    await _real_asyncio_sleep(0)


@asynccontextmanager
async def _fast_renew_loop() -> AsyncIterator[None]:
    """Keep asyncio.sleep patched for the full renew-loop lifetime."""
    with patch("app.orchestration.lease.asyncio.sleep", _instant_sleep):
        yield


async def _wait_until(condition: Callable[[], bool], *, timeout: float = 2.0) -> None:
    """Poll until *condition* returns True."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition():
        if loop.time() >= deadline:
            raise TimeoutError("condition not met before timeout")
        await asyncio.sleep(0)


async def _cancel_renew_task(task: asyncio.Task[None]) -> None:
    """Cancel a renew loop task, tolerating normal completion."""
    if not task.done():
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await task


@pytest.mark.asyncio
async def test_renew_exception_triggers_on_renewal_failed_after_threshold() -> None:
    """After max_renew_failures+1 consecutive exceptions, on_renewal_failed is set."""
    fake_redis = _FakeRedis(renew_side_effect=ConnectionError("redis down"))
    lease = _lease_with_fake(fake_redis)

    renewal_failed = asyncio.Event()
    async with _fast_renew_loop():
        task = await lease.start_renewal(
            "evt-test",
            _OWNER,
            on_renewal_failed=renewal_failed,
            max_renew_failures=2,
        )
        try:
            await asyncio.wait_for(renewal_failed.wait(), timeout=2.0)
            assert renewal_failed.is_set()
        finally:
            await _cancel_renew_task(task)


@pytest.mark.asyncio
async def test_renew_exception_resets_after_successful_renew() -> None:
    """A single exception followed by a success resets the counter."""
    call_count = 0

    async def _flaky_renew(_key: str, _ttl: int) -> bool:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("transient blip")
        return True

    fake_redis = _FakeRedis()
    fake_redis.expire = _flaky_renew  # type: ignore[method-assign]

    lease = _lease_with_fake(fake_redis)

    renewal_failed = asyncio.Event()
    async with _fast_renew_loop():
        task = await lease.start_renewal(
            "evt-test",
            _OWNER,
            on_renewal_failed=renewal_failed,
            max_renew_failures=2,
        )
        try:
            await _wait_until(lambda: call_count >= 2)
            assert not renewal_failed.is_set(), (
                "renewal_failed was set even though the exception count reset"
            )
        finally:
            await _cancel_renew_task(task)


@pytest.mark.asyncio
async def test_renew_owner_mismatch_still_triggers_immediately() -> None:
    """Stolen lease (renew returns False) still sets on_renewal_failed instantly."""
    fake_redis = _FakeRedis()
    fake_redis.get = AsyncMock(return_value=b"worker-thief")  # type: ignore[method-assign]

    lease = _lease_with_fake(fake_redis)

    renewal_failed = asyncio.Event()
    async with _fast_renew_loop():
        task = await lease.start_renewal(
            "evt-test",
            _OWNER,
            on_renewal_failed=renewal_failed,
        )
        try:
            await asyncio.wait_for(renewal_failed.wait(), timeout=2.0)
            assert renewal_failed.is_set()
        finally:
            await _cancel_renew_task(task)


@pytest.mark.asyncio
async def test_renew_single_exception_below_threshold_does_not_trigger() -> None:
    """Two errors then success must NOT set on_renewal_failed when threshold is 2."""
    error_count = 0

    async def _error_then_succeed(_key: str, _ttl: int) -> bool:
        nonlocal error_count
        error_count += 1
        if error_count <= 2:
            raise ConnectionError("transient")
        return True

    fake_redis = _FakeRedis()
    fake_redis.expire = _error_then_succeed  # type: ignore[method-assign]

    lease = _lease_with_fake(fake_redis)

    renewal_failed = asyncio.Event()
    async with _fast_renew_loop():
        task = await lease.start_renewal(
            "evt-test",
            _OWNER,
            on_renewal_failed=renewal_failed,
            max_renew_failures=2,
        )
        try:
            await _wait_until(lambda: error_count >= 3)
            assert not renewal_failed.is_set(), (
                "renewal_failed was set even though errors were below threshold"
            )
        finally:
            await _cancel_renew_task(task)


@pytest.mark.asyncio
async def test_renew_exception_default_threshold() -> None:
    """Default max_renew_failures=3 triggers on the 4th consecutive error."""
    call_count = 0

    async def _always_error(_key: str, _ttl: int) -> bool:
        nonlocal call_count
        call_count += 1
        raise ConnectionError(f"error {call_count}")

    fake_redis = _FakeRedis()
    fake_redis.expire = _always_error  # type: ignore[method-assign]

    lease = _lease_with_fake(fake_redis)

    renewal_failed = asyncio.Event()
    async with _fast_renew_loop():
        task = await lease.start_renewal(
            "evt-test",
            _OWNER,
            on_renewal_failed=renewal_failed,
        )
        try:
            await asyncio.wait_for(renewal_failed.wait(), timeout=2.0)
            assert renewal_failed.is_set()
            assert call_count == 4
        finally:
            await _cancel_renew_task(task)


@pytest.mark.asyncio
async def test_renew_loop_exits_on_first_exception_with_threshold_zero() -> None:
    """max_renew_failures=0 means the first exception triggers failure."""
    fake_redis = _FakeRedis(renew_side_effect=ConnectionError("boom"))
    lease = _lease_with_fake(fake_redis)

    renewal_failed = asyncio.Event()
    async with _fast_renew_loop():
        task = await lease.start_renewal(
            "evt-test",
            _OWNER,
            on_renewal_failed=renewal_failed,
            max_renew_failures=0,
        )
        try:
            await asyncio.wait_for(renewal_failed.wait(), timeout=2.0)
            assert renewal_failed.is_set()
        finally:
            await _cancel_renew_task(task)


@pytest.mark.asyncio
async def test_renew_redis_unavailable_raises_dependency_error() -> None:
    """Redis unavailable during renew must not return False (lease theft signal)."""
    lease = EventLease(None)
    with pytest.raises(DependencyUnavailableError):
        await lease.renew("evt-test", _OWNER)


@pytest.mark.asyncio
async def test_renew_redis_unavailable_single_attempt_below_threshold() -> None:
    """First Redis-unavailable renew must not set on_renewal_failed (ISSUE-355)."""
    lease = EventLease(None)

    renewal_failed = asyncio.Event()
    async with _fast_renew_loop():
        task = await lease.start_renewal(
            "evt-test",
            _OWNER,
            on_renewal_failed=renewal_failed,
            max_renew_failures=2,
        )
        try:
            await asyncio.sleep(0.01)
            assert not renewal_failed.is_set(), (
                "renewal_failed set on first Redis-unavailable renew"
            )
            assert not task.done()
        finally:
            await _cancel_renew_task(task)


@pytest.mark.asyncio
async def test_renew_redis_unavailable_triggers_after_threshold() -> None:
    """ISSUE-355: Redis-unavailable still fail-closes after consecutive threshold."""
    lease = EventLease(None)
    renewal_failed = asyncio.Event()
    async with _fast_renew_loop():
        task = await lease.start_renewal(
            "evt-test",
            _OWNER,
            on_renewal_failed=renewal_failed,
            max_renew_failures=2,
        )
        try:
            await asyncio.wait_for(renewal_failed.wait(), timeout=2.0)
            assert renewal_failed.is_set()
        finally:
            await _cancel_renew_task(task)


@pytest.mark.asyncio
async def test_renew_success_does_not_trigger() -> None:
    """Normal successful renewal never sets on_renewal_failed."""
    fake_redis = _FakeRedis()
    lease = _lease_with_fake(fake_redis)

    renewal_failed = asyncio.Event()
    async with _fast_renew_loop():
        task = await lease.start_renewal(
            "evt-test",
            _OWNER,
            on_renewal_failed=renewal_failed,
        )
        try:
            await _wait_until(lambda: len(fake_redis.expire_calls) >= 1)
            assert not renewal_failed.is_set()
        finally:
            await _cancel_renew_task(task)
