"""Atomic grant attempt reservation with shadow namespace isolation (ISSUE-134)."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from app.core.metrics import (
    record_budget_redis_fallback,
    record_budget_redis_recovery,
    set_budget_redis_degraded,
)
from app.models.tool_call_grant import ToolCallMode

logger = logging.getLogger(__name__)

PRODUCTION_BUDGET_KEY_PREFIX = "shadowtrace:tool_grant_budget:production:"
SHADOW_BUDGET_KEY_PREFIX = "shadowtrace:tool_grant_budget:shadow:"
RESERVATION_RECOVERY_PROBE_KEY = "shadowtrace:tool_grant_budget:recovery_probe"
DEFAULT_RESERVATION_REDIS_RECOVERY_INTERVAL_SECONDS = 5.0


def budget_reservation_key(
    mode: ToolCallMode,
    *,
    namespace_key: str,
    grant_id: str,
) -> str:
    if mode is ToolCallMode.SHADOW:
        return f"{SHADOW_BUDGET_KEY_PREFIX}{namespace_key}:{grant_id}"
    if mode is ToolCallMode.PRODUCTION:
        return f"{PRODUCTION_BUDGET_KEY_PREFIX}{namespace_key}:{grant_id}"
    return f"shadowtrace:tool_grant_budget:compat:{namespace_key}:{grant_id}"


@dataclass
class _GrantBudgetCounter:
    reserved: int = 0
    consumed: int = 0


@dataclass
class ToolCallBudgetReservationStore:
    """In-process fallback counters keyed by reservation key."""

    counters: dict[str, _GrantBudgetCounter] = field(default_factory=dict)


class ToolCallBudgetReservationService:
    """Reserve/consume per-grant call budget without touching production ledgers in shadow mode."""

    def __init__(
        self,
        redis: object | None = None,
        *,
        memory_store: ToolCallBudgetReservationStore | None = None,
        attempt_redis_recovery: bool = True,
        recovery_interval_seconds: float = DEFAULT_RESERVATION_REDIS_RECOVERY_INTERVAL_SECONDS,
    ) -> None:
        self._redis = redis
        self._memory = memory_store or ToolCallBudgetReservationStore()
        self._redis_degraded = False
        self._memory_pinned_keys: set[str] = set()
        self._last_recovery_probe_at = 0.0
        self._attempt_redis_recovery = attempt_redis_recovery
        self._recovery_interval_seconds = recovery_interval_seconds

    async def reserve(
        self,
        *,
        mode: ToolCallMode,
        namespace_key: str,
        grant_id: str,
        max_calls: int,
    ) -> int:
        """Atomically reserve one attempt slot; returns 1-based seq or raises ValueError."""

        if max_calls < 1:
            raise ValueError("max_calls must be >= 1")
        key = budget_reservation_key(mode, namespace_key=namespace_key, grant_id=grant_id)
        client = await self._redis_client()
        if client is None or not self._uses_redis_for_key(key):
            self._ensure_key_pinned_for_degraded_fallback(key)
            counter = self._memory.counters.setdefault(key, _GrantBudgetCounter())
            if counter.reserved >= max_calls:
                raise ValueError("grant max_calls exhausted")
            counter.reserved += 1
            return counter.reserved

        script = """
        local current = tonumber(redis.call('GET', KEYS[1]) or '0')
        local limit = tonumber(ARGV[1])
        if current >= limit then
            return -1
        end
        return redis.call('INCR', KEYS[1])
        """
        try:
            seq = await client.eval(script, 1, key, str(max_calls))
            seq_int = int(seq)
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("reserve", grant_id, reservation_key=key)
            counter = self._memory.counters.setdefault(key, _GrantBudgetCounter())
            if counter.reserved >= max_calls:
                raise ValueError("grant max_calls exhausted") from None
            counter.reserved += 1
            return counter.reserved
        if seq_int < 0:
            raise ValueError("grant max_calls exhausted")
        return seq_int

    async def release(
        self,
        *,
        mode: ToolCallMode,
        namespace_key: str,
        grant_id: str,
        count: int = 1,
    ) -> None:
        """Release reserved attempt slots (e.g. when PG authoritative reserve fails)."""

        if count < 1:
            return
        key = budget_reservation_key(mode, namespace_key=namespace_key, grant_id=grant_id)
        client = await self._redis_client()
        if client is None or not self._uses_redis_for_key(key):
            self._ensure_key_pinned_for_degraded_fallback(key)
            counter = self._memory.counters.setdefault(key, _GrantBudgetCounter())
            counter.reserved = max(0, counter.reserved - count)
            return

        script = """
        local current = tonumber(redis.call('GET', KEYS[1]) or '0')
        local dec = tonumber(ARGV[1])
        if current <= 0 then
            return 0
        end
        local actual = dec
        if current < dec then
            actual = current
        end
        return redis.call('DECRBY', KEYS[1], actual)
        """
        try:
            await client.eval(script, 1, key, str(count))
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("release", grant_id, reservation_key=key)
            counter = self._memory.counters.setdefault(key, _GrantBudgetCounter())
            counter.reserved = max(0, counter.reserved - count)

    async def get_reserved_count(
        self,
        *,
        mode: ToolCallMode,
        namespace_key: str,
        grant_id: str,
    ) -> int:
        key = budget_reservation_key(mode, namespace_key=namespace_key, grant_id=grant_id)
        if not self._uses_redis_for_key(key):
            return self._memory.counters.get(key, _GrantBudgetCounter()).reserved
        client = await self._redis_client()
        if client is None:
            return self._memory.counters.get(key, _GrantBudgetCounter()).reserved
        try:
            raw = await client.get(key)
            return int(raw or 0)
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("get_reserved_count", grant_id, reservation_key=key)
            return self._memory.counters.get(key, _GrantBudgetCounter()).reserved

    def _uses_redis_for_key(self, key: str) -> bool:
        return key not in self._memory_pinned_keys

    def _pin_key_to_memory(self, reservation_key: str | None) -> None:
        if reservation_key:
            self._memory_pinned_keys.add(reservation_key)

    def _ensure_key_pinned_for_degraded_fallback(self, reservation_key: str) -> None:
        if self._redis_degraded:
            self._pin_key_to_memory(reservation_key)

    async def _maybe_attempt_redis_recovery(self) -> None:
        if not self._attempt_redis_recovery or not self._redis_degraded or self._redis is None:
            return
        now = time.monotonic()
        if now - self._last_recovery_probe_at < self._recovery_interval_seconds:
            return
        self._last_recovery_probe_at = now
        try:
            ping = getattr(self._redis, "ping", None)
            if callable(ping) and not await ping():
                return
            get_client = getattr(self._redis, "get_client", None)
            client = get_client() if callable(get_client) else self._redis
            get = getattr(client, "get", None)
            if callable(get):
                await get(RESERVATION_RECOVERY_PROBE_KEY)
            self._clear_redis_degraded()
        except Exception:
            return

    def _clear_redis_degraded(self) -> None:
        if not self._redis_degraded:
            return
        self._redis_degraded = False
        set_budget_redis_degraded(service="reservation", active=False)
        record_budget_redis_recovery(service="reservation")
        logger.info(
            "tool grant budget Redis recovered; new grants resume Redis counters "
            "(%s grant(s) remain memory-pinned until completion)",
            len(self._memory_pinned_keys),
        )

    async def _redis_client(self) -> object | None:
        if self._redis is None:
            return None
        try:
            ping = getattr(self._redis, "ping", None)
            if callable(ping):
                if not await ping():
                    self._mark_redis_degraded("ping")
                    return None
            if self._redis_degraded:
                await self._maybe_attempt_redis_recovery()
                if self._redis_degraded:
                    return None
            get_client = getattr(self._redis, "get_client", None)
            if callable(get_client):
                return get_client()
            return self._redis
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("ping")
            return None

    def _mark_redis_degraded(
        self,
        op: str,
        grant_id: str | None = None,
        *,
        reservation_key: str | None = None,
    ) -> None:
        if not self._redis_degraded:
            logger.warning(
                "tool grant budget Redis unavailable; using in-process counters op=%s grant_id=%s",
                op,
                grant_id,
            )
            set_budget_redis_degraded(service="reservation", active=True)
            record_budget_redis_fallback(service="reservation", op=op)
        self._redis_degraded = True
        self._pin_key_to_memory(reservation_key)


__all__ = [
    "PRODUCTION_BUDGET_KEY_PREFIX",
    "SHADOW_BUDGET_KEY_PREFIX",
    "ToolCallBudgetReservationService",
    "ToolCallBudgetReservationStore",
    "budget_reservation_key",
]
