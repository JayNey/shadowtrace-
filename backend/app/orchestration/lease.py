"""Redis-based distributed event lease for SuperAgent (ISSUE-054).

Guarantees at-most-one investigation per event via ``SET NX EX`` on key
``shadowtrace:lease:event:{event_id}``. The lease auto-expires after *ttl_s*
seconds; a background renew task extends it at 60 s intervals while the
investigation graph is running.
"""

from __future__ import annotations

import logging
import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = logging.getLogger(__name__)

LEASE_KEY_PREFIX = "shadowtrace:lease:event:"
DEFAULT_LEASE_TTL_SECONDS = 600
RENEW_INTERVAL_SECONDS = 60

# Lua script: release only if the stored owner matches.
_RELEASE_SCRIPT = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
"""

# Lua script: renew TTL only if the stored owner matches.
_RENEW_SCRIPT = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("EXPIRE", KEYS[1], ARGV[2])
else
    return 0
end
"""


def _generate_owner_id() -> str:
    """Return a unique worker identity for lease ownership checks."""
    return f"worker-{secrets.token_hex(4)}"


def _lease_key(event_id: str) -> str:
    return f"{LEASE_KEY_PREFIX}{event_id}"


class EventLease:
    """Distributed lease for an investigation event.

    Usage::

        lease = EventLease(redis_client.get_client())
        if not await lease.acquire(event_id):
            raise HTTPException(409, "investigation already in progress")
        try:
            await run_investigation(event_id)
        finally:
            await lease.release(event_id)
    """

    def __init__(
        self,
        redis: Redis,
        *,
        ttl_s: int = DEFAULT_LEASE_TTL_SECONDS,
    ) -> None:
        self._redis = redis
        self._ttl_s = ttl_s
        self._owner_id = _generate_owner_id()

    @property
    def owner_id(self) -> str:
        return self._owner_id

    async def acquire(self, event_id: str, *, ttl_s: int | None = None) -> bool:
        """Try to acquire the lease. Returns ``True`` on success, ``False`` if
        another worker already holds it.
        """
        ttl = ttl_s if ttl_s is not None else self._ttl_s
        key = _lease_key(event_id)
        acquired = await self._redis.set(key, self._owner_id, nx=True, ex=ttl)
        if acquired:
            logger.debug("lease acquired event=%s owner=%s ttl=%ds", event_id, self._owner_id, ttl)
        else:
            logger.info("lease denied event=%s (held by another worker)", event_id)
        return bool(acquired)

    async def renew(self, event_id: str) -> bool:
        """Extend the lease TTL. Returns ``True`` if the renewal succeeded."""
        key = _lease_key(event_id)
        result = await self._redis.eval(
            _RENEW_SCRIPT,
            1,
            key,
            self._owner_id,
            str(self._ttl_s),
        )
        ok = result == 1
        if not ok:
            logger.warning(
                "lease renewal failed event=%s owner=%s (lease may have expired or been stolen)",
                event_id,
                self._owner_id,
            )
        return ok

    async def release(self, event_id: str) -> bool:
        """Release the lease. Returns ``True`` if the lease was successfully
        deleted, ``False`` if the owner didn't match (already expired/released).
        """
        key = _lease_key(event_id)
        result = await self._redis.eval(_RELEASE_SCRIPT, 1, key, self._owner_id)
        ok = result == 1
        if ok:
            logger.debug("lease released event=%s owner=%s", event_id, self._owner_id)
        return ok

    def lease_key_for(self, event_id: str) -> str:
        """Return the Redis key used for this event's lease."""
        return _lease_key(event_id)


__all__ = [
    "DEFAULT_LEASE_TTL_SECONDS",
    "EventLease",
    "LEASE_KEY_PREFIX",
    "RENEW_INTERVAL_SECONDS",
]
