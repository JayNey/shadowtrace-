"""In-memory Redis stand-in with SET NX EX, TTL, and lease release semantics."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from app.core.redis_client import RedisClient


@dataclass
class _RedisEntry:
    value: str
    expires_at: float | None = None


class InMemoryFakeRedis:
    """Minimal async Redis fake for lease and metadata tests."""

    def __init__(self, *, clock: Callable[[], float] | None = None) -> None:
        self._entries: dict[str, _RedisEntry] = {}
        self._clock = clock or time.monotonic

    def _purge_expired(self, key: str) -> None:
        entry = self._entries.get(key)
        if entry is None or entry.expires_at is None:
            return
        if self._clock() >= entry.expires_at:
            del self._entries[key]

    async def set(
        self,
        key: str,
        value: str,
        *,
        nx: bool = False,
        ex: int | None = None,
        **kwargs: object,
    ) -> bool:
        if kwargs:
            unsupported = ", ".join(sorted(kwargs))
            raise TypeError(f"unsupported fake Redis SET options: {unsupported}")
        self._purge_expired(key)
        if nx and key in self._entries:
            return False
        expires_at = self._clock() + ex if ex is not None else None
        self._entries[key] = _RedisEntry(value=value, expires_at=expires_at)
        return True

    async def get(self, key: str) -> bytes | None:
        self._purge_expired(key)
        entry = self._entries.get(key)
        if entry is None:
            return None
        return entry.value.encode("utf-8")

    async def delete(self, key: str) -> int:
        self._purge_expired(key)
        existed = key in self._entries
        self._entries.pop(key, None)
        return 1 if existed else 0

    async def expire(self, key: str, ttl: int) -> bool:
        self._purge_expired(key)
        entry = self._entries.get(key)
        if entry is None:
            return False
        entry.expires_at = self._clock() + ttl
        return True

    def register_script(self, script: str) -> Any:
        from app.orchestration.lease import classify_lease_lua_script

        kind = classify_lease_lua_script(script)

        async def _release(*, keys: list[str], args: list[str]) -> int:
            key = keys[0]
            owner_id = args[0]
            self._purge_expired(key)
            entry = self._entries.get(key)
            if entry is None:
                if len(keys) > 1:
                    self._entries.pop(keys[1], None)
                return -1
            if entry.value != owner_id:
                return 0
            del self._entries[key]
            if len(keys) > 1:
                self._entries.pop(keys[1], None)
            return 1

        async def _renew(*, keys: list[str], args: list[str]) -> int:
            key = keys[0]
            owner_id = args[0]
            ttl = int(args[1]) if len(args) > 1 else 0
            if ttl <= 0:
                return 0
            self._purge_expired(key)
            entry = self._entries.get(key)
            if entry is None:
                return -1
            if entry.value != owner_id:
                return 0
            entry.expires_at = self._clock() + ttl
            if len(keys) > 1:
                await self.set(keys[1], str(ttl), ex=ttl)
            return 1

        return _renew if kind == "renew" else _release


class InMemoryFakeRedisClient:
    """RedisClient-shaped wrapper for :class:`InMemoryFakeRedis`."""

    def __init__(self, raw: InMemoryFakeRedis | None = None) -> None:
        self.client = raw or InMemoryFakeRedis()

    def get_client(self) -> InMemoryFakeRedis:
        return self.client


def patch_redis_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    raw: InMemoryFakeRedis | None = None,
) -> InMemoryFakeRedis:
    """Patch :class:`RedisClient` to use an in-memory fake for the test."""
    fake = raw or InMemoryFakeRedis()
    wrapper = InMemoryFakeRedisClient(fake)

    async def _ping(self: RedisClient) -> bool:
        return True

    def _get_client(self: RedisClient) -> InMemoryFakeRedis:
        return wrapper.get_client()

    async def _aclose(self: RedisClient) -> None:
        return None

    monkeypatch.setattr(RedisClient, "ping", _ping)
    monkeypatch.setattr(RedisClient, "get_client", _get_client)
    monkeypatch.setattr(RedisClient, "aclose", _aclose)
    return fake
