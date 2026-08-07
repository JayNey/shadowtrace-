"""Async Redis client with orjson serialization (ISSUE-013).

Celery workers run each task via ``asyncio.run``, which creates and closes a
fresh event loop. ``redis.asyncio`` clients/pools are loop-bound, so this
wrapper rebinds to the current loop when the previous one is closed or differs
(ISSUE-252 / Strategy B).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import date, datetime
from enum import Enum
from typing import Any
from uuid import UUID

import orjson
from pydantic import BaseModel
from redis.asyncio import ConnectionPool, Redis

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_DEFAULT_MAX_CONNECTIONS = 20


def _json_default(obj: Any) -> Any:
    """Fallback encoder for types orjson does not handle natively."""
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def is_event_loop_error(exc: BaseException) -> bool:
    """Return True when ``exc`` indicates a closed or cross-loop asyncio Future."""
    if isinstance(exc, RuntimeError):
        lowered = str(exc).lower()
        return (
            "event loop is closed" in lowered
            or "different event loop" in lowered
            or "bound to a different event loop" in lowered
            or "attached to a different loop" in lowered
            or "no running event loop" in lowered
        )
    lowered = str(exc).lower()
    return "different loop" in lowered or "event loop is closed" in lowered


class RedisClient:
    """Thin async Redis wrapper: connection pool + orjson helpers + ping.

    The underlying ``redis.asyncio`` client is rebound when the active event
    loop changes (Celery ``asyncio.run`` / worker post-fork).
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        max_connections: int = _DEFAULT_MAX_CONNECTIONS,
    ) -> None:
        self._url = url if url is not None else get_settings().redis_url
        self._max_connections = max_connections
        self._pool: ConnectionPool | None = None
        self._client: Redis | None = None
        self._bound_loop: asyncio.AbstractEventLoop | None = None
        self._rebuild()

    def _rebuild(self) -> None:
        self._pool = ConnectionPool.from_url(
            self._url,
            max_connections=self._max_connections,
            decode_responses=False,
        )
        self._client = Redis(connection_pool=self._pool)
        self._bound_loop = None

    @staticmethod
    def _running_loop() -> asyncio.AbstractEventLoop | None:
        try:
            return asyncio.get_running_loop()
        except RuntimeError:
            return None

    def _needs_rebind(self, loop: asyncio.AbstractEventLoop | None) -> bool:
        if self._client is None or self._pool is None:
            return True
        bound = self._bound_loop
        if bound is None:
            return False
        if bound.is_closed():
            return True
        return loop is not None and bound is not loop

    def _drop_resources_sync(self) -> None:
        """Drop loop-bound resources without awaiting (loop may already be closed)."""
        self._client = None
        self._pool = None
        self._bound_loop = None

    async def _retire_resources(self) -> None:
        client, pool = self._client, self._pool
        self._client = None
        self._pool = None
        self._bound_loop = None
        if client is not None:
            try:
                await client.aclose()
            except Exception:
                logger.debug("redis client aclose during rebind failed", exc_info=True)
        if pool is not None:
            try:
                await pool.disconnect()
            except Exception:
                logger.debug("redis pool disconnect during rebind failed", exc_info=True)

    def _ensure_client(self) -> Redis:
        loop = self._running_loop()
        if self._needs_rebind(loop):
            logger.info(
                "RedisClient rebinding asyncio client to current event loop "
                "(closed_or_cross_loop=true)"
            )
            self._drop_resources_sync()
            self._rebuild()
        if self._client is None:
            self._rebuild()
        if loop is not None and self._bound_loop is None:
            self._bound_loop = loop
        assert self._client is not None
        return self._client

    def get_client(self) -> Redis:
        """Return the async Redis client, rebound to the current loop if needed."""
        return self._ensure_client()

    async def rebind_to_current_loop(self) -> None:
        """Force-retire the current client and bind a fresh one to this loop."""
        loop = self._running_loop()
        if not self._needs_rebind(loop) and self._client is not None:
            if loop is not None and self._bound_loop is None:
                self._bound_loop = loop
            return
        logger.info("RedisClient explicit rebind_to_current_loop")
        await self._retire_resources()
        self._rebuild()
        if loop is not None:
            self._bound_loop = loop

    async def ping(self) -> bool:
        """Return True when Redis answers PING; False on any failure."""
        try:
            client = self._ensure_client()
            return bool(await client.ping())
        except Exception as exc:  # noqa: BLE001 — health/degrade path must not raise
            if is_event_loop_error(exc):
                try:
                    await self.rebind_to_current_loop()
                    client = self._ensure_client()
                    return bool(await client.ping())
                except Exception:  # noqa: BLE001
                    return False
            return False

    async def aclose(self) -> None:
        """Close the client and disconnect the pool."""
        await self._retire_resources()

    @staticmethod
    def dumps(value: Any) -> bytes:
        """Serialize ``value`` to UTF-8 JSON bytes via orjson."""
        return orjson.dumps(value, default=_json_default)

    @staticmethod
    def loads(data: bytes | str | memoryview) -> Any:
        """Deserialize orjson / UTF-8 JSON bytes or str."""
        if isinstance(data, memoryview):
            data = data.tobytes()
        if isinstance(data, str):
            data = data.encode("utf-8")
        return orjson.loads(data)


__all__ = [
    "RedisClient",
    "is_event_loop_error",
]
