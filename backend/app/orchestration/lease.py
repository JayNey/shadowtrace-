"""EventLease — Redis-based distributed lease to prevent duplicate orchestration (ISSUE-054).

Acquire uses ``SET NX EX`` for atomicity; renew and release use Lua scripts to
check owner identity before EXPIRE/DEL. When Redis is unavailable ``acquire`` raises
``DependencyUnavailableError`` (HTTP 503); duplicate triggers return ``False``
(HTTP 409).

Lease key: ``shadowtrace:lease:event:{event_id}``
Owner id:    ``worker-{8 hex chars}``
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any

from app.core.errors import DependencyUnavailableError, ValidationError
from app.core.redis_client import RedisClient

logger = logging.getLogger(__name__)

LEASE_KEY_PREFIX = "shadowtrace:lease:event:"
DEFAULT_LEASE_TTL_S = 600
RENEW_INTERVAL_S = 60

# Lua script: atomically delete the key only when the value matches owner_id.
# Returns: 1 = deleted, 0 = owner mismatch, -1 = key absent.
_RELEASE_SCRIPT = """
-- shadowtrace-lease-release
local val = redis.call("GET", KEYS[1])
if val == false then
    return -1
end
if val == ARGV[1] then
    return redis.call("DEL", KEYS[1])
end
return 0
"""

# Lua script: atomically extend TTL only when the value matches owner_id.
# Returns: 1 = renewed, 0 = owner mismatch, -1 = key absent.
_RENEW_SCRIPT = """
-- shadowtrace-lease-renew
local val = redis.call("GET", KEYS[1])
if val == false then
    return -1
end
if val == ARGV[1] then
    redis.call("EXPIRE", KEYS[1], tonumber(ARGV[2]))
    return 1
end
return 0
"""


def classify_lease_lua_script(source: str) -> str:
    """Return ``renew`` or ``release`` for a registered EventLease Lua script.

    Prefer identity against the module constants so comment edits cannot
    silently swap branches in fake Redis. Fall back to EXPIRE vs DEL.
    """
    if source is _RENEW_SCRIPT or source == _RENEW_SCRIPT:
        return "renew"
    if source is _RELEASE_SCRIPT or source == _RELEASE_SCRIPT:
        return "release"
    has_expire = 'redis.call("EXPIRE"' in source or "redis.call('EXPIRE'" in source
    has_del = 'redis.call("DEL"' in source or "redis.call('DEL'" in source
    if has_expire and not has_del:
        return "renew"
    if has_del and not has_expire:
        return "release"
    raise ValueError("unknown lease lua script")


def _require_positive_ttl(ttl_s: int) -> int:
    if ttl_s <= 0:
        raise ValidationError(
            "lease ttl_s must be a positive integer",
            details={"ttl_s": ttl_s},
        )
    return ttl_s


def _lease_key(event_id: str) -> str:
    return f"{LEASE_KEY_PREFIX}{event_id}"


def generate_owner_id() -> str:
    """Return a unique worker identity: ``worker-{8 hex chars}``."""
    return f"worker-{secrets.token_hex(4)}"


class EventLease:
    """Distributed lease backed by Redis.

    When Redis is unavailable, ``acquire`` raises
    :class:`~app.core.errors.DependencyUnavailableError` (HTTP 503).  Other
    methods return falsy values when Redis is down.

    Holds :class:`RedisClient` (not a raw ``redis.asyncio`` handle) so Celery
    Strategy B / loop rebind can refresh the underlying client (ISSUE-252).
    """

    def __init__(self, redis_client: RedisClient | None) -> None:
        self._redis_client = redis_client
        self._lua_scripts: dict[str, Any] = {}
        self._lua_client_id: int | None = None
        self._acquired_ttl: dict[str, int] = {}

    def _raw_redis(self) -> Any | None:
        if self._redis_client is None:
            return None
        return self._redis_client.get_client()

    def _script_for(self, redis: Any, source: str) -> Any:
        client_id = id(redis)
        if self._lua_client_id != client_id:
            self._lua_scripts.clear()
            self._lua_client_id = client_id
        script = self._lua_scripts.get(source)
        if script is None:
            script = redis.register_script(source)
            self._lua_scripts[source] = script
        return script

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def acquire(
        self,
        event_id: str,
        owner_id: str,
        ttl_s: int = DEFAULT_LEASE_TTL_S,
    ) -> bool:
        """Atomically acquire the lease.  Returns ``True`` on success.

        Uses ``SET key owner_id NX EX ttl_s`` so only the first caller for
        a given *event_id* wins.  Returns ``False`` when another owner holds
        the lease.  Raises :class:`~app.core.errors.DependencyUnavailableError`
        when Redis is unavailable.
        """
        redis = self._raw_redis()
        if redis is None:
            logger.warning(
                "EventLease.acquire: Redis unavailable, refusing lease for event=%s",
                event_id,
            )
            raise DependencyUnavailableError(
                message="event lease store unavailable",
                error_code="dependency_unavailable",
                details={"event_id": event_id, "dependency": "redis"},
            )
        ttl_s = _require_positive_ttl(ttl_s)
        key = _lease_key(event_id)
        acquired = await redis.set(key, owner_id, nx=True, ex=ttl_s)
        if acquired:
            self._acquired_ttl[event_id] = ttl_s
            logger.info(
                "EventLease: acquired lease for event=%s owner=%s ttl=%ds",
                event_id,
                owner_id,
                ttl_s,
            )
        else:
            logger.info(
                "EventLease: lease already held for event=%s (attempt by %s)",
                event_id,
                owner_id,
            )
        return bool(acquired)

    async def renew(
        self,
        event_id: str,
        owner_id: str,
        ttl_s: int = DEFAULT_LEASE_TTL_S,
    ) -> bool:
        """Extend the lease TTL — only when *owner_id* still matches.

        Uses a Lua compare-and-expire so a TOCTOU window cannot extend another
        worker's lease after expiry. Returns ``True`` when renewed. Returns
        ``False`` when the key is absent or the owner no longer matches.

        Raises :class:`~app.core.errors.DependencyUnavailableError` when Redis
        is unavailable so :meth:`start_renewal` can count consecutive errors
        instead of treating a blip as lease theft (ISSUE-355).
        """
        redis = self._raw_redis()
        if redis is None:
            logger.warning(
                "EventLease.renew: Redis unavailable for event=%s owner=%s",
                event_id,
                owner_id,
            )
            raise DependencyUnavailableError(
                message="event lease store unavailable",
                error_code="dependency_unavailable",
                details={"event_id": event_id, "dependency": "redis", "operation": "renew"},
            )
        ttl_s = _require_positive_ttl(ttl_s)
        key = _lease_key(event_id)
        script = self._script_for(redis, _RENEW_SCRIPT)
        result: Any = await script(keys=[key], args=[owner_id, str(ttl_s)])
        code = int(result) if result is not None else -1
        if code == 1:
            logger.debug(
                "EventLease: renewed lease for event=%s owner=%s ttl=%ds",
                event_id,
                owner_id,
                ttl_s,
            )
            return True
        if code == -1:
            logger.warning(
                "EventLease.renew: lease key absent for event=%s — "
                "lease may have expired or been released by another worker",
                event_id,
            )
            return False
        logger.warning(
            "EventLease.renew: owner mismatch for event=%s (caller=%s)",
            event_id,
            owner_id,
        )
        return False

    async def release(self, event_id: str, owner_id: str) -> bool:
        """Release the lease when *owner_id* matches.

        Uses a Lua script so the check-and-delete is atomic.  Returns
        ``True`` when the key was deleted or was already absent (idempotent).
        Returns ``False`` when the key exists but is owned by a different
        party — the caller must NOT proceed as if the lease is released.
        """
        redis = self._raw_redis()
        if redis is None:
            return False
        key = _lease_key(event_id)
        script = self._script_for(redis, _RELEASE_SCRIPT)
        result: Any = await script(keys=[key], args=[owner_id])
        code = int(result) if result is not None else -1
        if code == 1:
            logger.info(
                "EventLease: released lease for event=%s owner=%s",
                event_id,
                owner_id,
            )
            self._acquired_ttl.pop(event_id, None)
            return True
        if code == -1:
            logger.debug(
                "EventLease.release: key already absent for event=%s (idempotent)",
                event_id,
            )
            return True
        # code == 0: owner mismatch — lease held by another worker.
        logger.warning(
            "EventLease.release: owner mismatch for event=%s "
            "(caller=%s) — lease held by another worker, NOT released",
            event_id,
            owner_id,
        )
        return False

    async def get_owner(self, event_id: str) -> str | None:
        """Inspect the current lease owner (for diagnostics only)."""
        redis = self._raw_redis()
        if redis is None:
            return None
        key = _lease_key(event_id)
        value = await redis.get(key)
        if value is None:
            return None
        return value.decode("utf-8") if isinstance(value, bytes) else value

    # ------------------------------------------------------------------ #
    # Background renewal helpers
    # ------------------------------------------------------------------ #

    async def start_renewal(
        self,
        event_id: str,
        owner_id: str,
        *,
        on_renewal_failed: asyncio.Event | None = None,
        max_renew_failures: int = 3,
        ttl_s: int | None = None,
    ) -> asyncio.Task[None]:
        """Launch a background task that renews the lease every 60 s.

        When *ttl_s* is omitted, reuse the TTL from :meth:`acquire` for this
        event (custom acquire TTLs must not be silently reset to 600s).
        """
        if ttl_s is None:
            renew_ttl = self._acquired_ttl.get(event_id, DEFAULT_LEASE_TTL_S)
        else:
            renew_ttl = ttl_s
        renew_ttl = _require_positive_ttl(renew_ttl)

        async def _renew_loop() -> None:
            consecutive_errors = 0
            while True:
                await asyncio.sleep(RENEW_INTERVAL_S)
                try:
                    ok = await self.renew(event_id, owner_id, ttl_s=renew_ttl)
                    if not ok:
                        # False only means key absent or owner mismatch — real loss.
                        logger.error(
                            "EventLease: renewal failed for event=%s owner=%s "
                            "- lease lost (key absent or owner mismatch)",
                            event_id,
                            owner_id,
                        )
                        if on_renewal_failed is not None:
                            on_renewal_failed.set()
                        break
                    # Successful renewal resets the consecutive error counter.
                    consecutive_errors = 0
                except Exception:
                    consecutive_errors += 1
                    if consecutive_errors > max_renew_failures:
                        logger.error(
                            "EventLease: %d consecutive renewal errors for "
                            "event=%s (threshold=%d) — treating as fatal "
                            "and signaling caller",
                            consecutive_errors,
                            event_id,
                            max_renew_failures,
                        )
                        if on_renewal_failed is not None:
                            on_renewal_failed.set()
                        break
                    logger.warning(
                        "EventLease: renewal error %d/%d for event=%s",
                        consecutive_errors,
                        max_renew_failures + 1,
                        event_id,
                        exc_info=True,
                    )

        task = asyncio.create_task(_renew_loop())
        return task


__all__ = [
    "DEFAULT_LEASE_TTL_S",
    "EventLease",
    "RENEW_INTERVAL_S",
    "classify_lease_lua_script",
    "generate_owner_id",
]
