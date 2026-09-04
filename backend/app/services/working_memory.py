"""WorkingMemory + FIELD_OWNERSHIP (ISSUE-014 / intro §4.11)."""

from __future__ import annotations

import logging
import time
import weakref
from collections import OrderedDict
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from sqlalchemy import select

from app.core.config import get_settings
from app.core.errors import GuardrailViolationError
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.models.working_memory import MemoryAccessLog
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.working_memory_bound import (
    ACCESS_LOG_LIMIT,
    EVENT_CACHE_LIMIT,
    FIELD_OWNERSHIP,
    SCRATCHPAD_LIMIT,
    WRITER_ALIASES,
    BoundWorkingMemory,
    OwnerMemoryOps,
    WriterCapability,
    normalize_writer,
    wm_key,
)

logger = logging.getLogger(__name__)

CAPABILITY_LIMIT = 8192
CAPABILITY_TTL_SECONDS = 30 * 60


class _MemoryEngine:
    """Owner-gated EventContext access with scratchpad + access audit."""

    def __init__(
        self,
        store: EventContextStore,
        redis: RedisClient,
        *,
        degraded_flags: DegradedFlagService | None = None,
        wm_strict: bool | None = None,
    ) -> None:
        self._store = store
        self._redis = redis
        self._degraded_flags = degraded_flags
        self._wm_strict = get_settings().wm_strict if wm_strict is None else wm_strict
        # Durable history lives in memory_access_audit_log. This bounded map is
        # only a process-local diagnostic projection.
        self._access_logs: OrderedDict[str, list[MemoryAccessLog]] = OrderedDict()
        self._redis_degrade_marked: OrderedDict[str, None] = OrderedDict()
        self._redis_degrade_lock = RLock()
        self._issued_capabilities: OrderedDict[WriterCapability, str] = OrderedDict()
        self._capability_last_used: OrderedDict[WriterCapability, float] = OrderedDict()
        self._capability_alive: dict[WriterCapability, list[bool]] = {}
        self._ops_by_capability: dict[WriterCapability, OwnerMemoryOps] = {}
        self._degraded_holder: list[DegradedFlagService | None] = [degraded_flags]
        self._live_bindings: dict[WriterCapability, weakref.ReferenceType[BoundWorkingMemory]] = {}
        self._capability_lock = RLock()

    def bind_degraded_flag_service(self, service: DegradedFlagService) -> None:
        """Wire DegradedFlagService after construction (breaks init cycles)."""
        self._degraded_flags = service
        self._degraded_holder[0] = service

    async def _maybe_mark_redis_unavailable(self, event_id: str, redis_ok: bool) -> None:
        """Composition-root redis degrade marker. Agent views use OwnerMemoryOps."""
        if redis_ok:
            with self._redis_degrade_lock:
                self._redis_degrade_marked.pop(event_id, None)
            return
        degraded_flags = self._degraded_holder[0]
        if degraded_flags is None:
            logger.warning(
                "redis_ok=false but DegradedFlagService not bound event_id=%s",
                event_id,
            )
            return
        with self._redis_degrade_lock:
            if event_id in self._redis_degrade_marked:
                self._redis_degrade_marked.move_to_end(event_id)
                return
            if len(self._redis_degrade_marked) >= EVENT_CACHE_LIMIT:
                self._redis_degrade_marked.popitem(last=False)
            self._redis_degrade_marked[event_id] = None
        try:
            await degraded_flags.set_flag(
                event_id,
                "redis_context_unavailable",
                True,
                writer="WorkingMemory",
            )
        except Exception:
            with self._redis_degrade_lock:
                self._redis_degrade_marked.pop(event_id, None)
            raise

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def release(self, capability: WriterCapability) -> None:
        """Revoke a capability; subsequent access fails closed."""
        with self._capability_lock:
            self._drop_capability_locked(capability)

    revoke = release

    async def read(
        self,
        event_id: str,
        key: str,
        reader: WriterCapability,
    ) -> Any:
        try:
            self._resolve_capability(reader)
        except GuardrailViolationError:
            await self._record_access_durable(
                event_id,
                agent_name=self._capability_label(reader),
                op="read",
                key=key,
                allowed=False,
            )
            raise
        return await self._ops_by_capability[reader].read(event_id, key)

    async def write(
        self,
        event_id: str,
        key: str,
        value: Any,
        writer: WriterCapability,
    ) -> None:
        writer_name = self._capability_label(writer)
        try:
            self._resolve_capability(writer)
        except GuardrailViolationError:
            await self._record_access_durable(
                event_id,
                agent_name=writer_name,
                op="write",
                key=key,
                allowed=False,
            )
            raise
        await self._ops_by_capability[writer].write(event_id, key, value)

    async def append_scratchpad(
        self,
        event_id: str,
        note: str,
        *,
        writer: WriterCapability,
    ) -> None:
        try:
            self._resolve_capability(writer)
        except GuardrailViolationError:
            await self._record_access_durable(
                event_id,
                agent_name=self._capability_label(writer),
                op="write",
                key="scratchpad",
                allowed=False,
            )
            raise
        await self._ops_by_capability[writer].append_scratchpad(event_id, note)

    async def read_scratchpad(
        self,
        event_id: str,
        *,
        reader: WriterCapability,
    ) -> list[Any]:
        return await self._ops_by_capability[reader].read_scratchpad(event_id)

    async def get_access_log(self, event_id: str) -> list[MemoryAccessLog]:
        factory = getattr(self._store, "_session_factory", None)
        if isinstance(self._store, EventContextStore) and factory is not None:
            async with factory() as session:
                rows = (
                    await session.scalars(
                        select(orm.MemoryAccessAuditLog)
                        .where(orm.MemoryAccessAuditLog.event_id == event_id)
                        .order_by(orm.MemoryAccessAuditLog.id)
                    )
                ).all()
            if rows:
                return [
                    MemoryAccessLog(
                        timestamp=row.timestamp,
                        agent_name=row.agent_name,
                        op=row.op,
                        key=row.key,
                        allowed=row.allowed,
                    )
                    for row in rows
                ]
        return list(self._access_logs.get(event_id, []))

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _resolve_capability(self, capability: WriterCapability) -> str:
        try:
            with self._capability_lock:
                self._reclaim_unbound_capabilities()
                alive = self._capability_alive.get(capability)
                if not alive or not alive[0]:
                    raise KeyError(capability)
                owner = self._issued_capabilities[capability]
                self._capability_last_used[capability] = time.monotonic()
                self._capability_last_used.move_to_end(capability)
                self._issued_capabilities.move_to_end(capability)
                return owner
        except (KeyError, TypeError) as exc:
            raise GuardrailViolationError(
                "unrecognized working-memory writer capability",
                error_code="working_memory_unauthorized_write",
                details={"writer": self._capability_label(capability)},
            ) from exc

    @staticmethod
    def _capability_label(capability: object) -> str:
        if isinstance(capability, WriterCapability):
            return capability.owner
        return f"<invalid:{type(capability).__name__}>"

    def _record_access(
        self,
        event_id: str,
        *,
        agent_name: str,
        op: str,
        key: str,
        allowed: bool,
    ) -> None:
        log = MemoryAccessLog(
            timestamp=datetime.now(UTC),
            agent_name=agent_name,
            op=op,  # type: ignore[arg-type]
            key=key,
            allowed=allowed,
        )
        if event_id not in self._access_logs and len(self._access_logs) >= EVENT_CACHE_LIMIT:
            self._access_logs.popitem(last=False)
        entries = self._access_logs.setdefault(event_id, [])
        self._access_logs.move_to_end(event_id)
        entries.append(log)
        if len(entries) > ACCESS_LOG_LIMIT:
            del entries[: len(entries) - ACCESS_LOG_LIMIT]

    async def _record_access_durable(self, event_id: str, **kwargs: Any) -> None:
        self._record_access(event_id, **kwargs)
        factory = getattr(self._store, "_session_factory", None)
        if not isinstance(self._store, EventContextStore) or factory is None:
            return
        log = self._access_logs[event_id][-1]
        async with factory() as session:
            async with session.begin():
                session.add(
                    orm.MemoryAccessAuditLog(
                        event_id=event_id,
                        timestamp=log.timestamp,
                        agent_name=log.agent_name,
                        op=log.op,
                        key=log.key,
                        allowed=log.allowed,
                    )
                )

    def _binding_is_live(self, capability: WriterCapability) -> bool:
        ref = self._live_bindings.get(capability)
        return ref is not None and ref() is not None

    def _drop_capability_locked(self, capability: WriterCapability) -> None:
        alive = self._capability_alive.pop(capability, None)
        if alive is not None:
            alive[0] = False
        self._ops_by_capability.pop(capability, None)
        self._issued_capabilities.pop(capability, None)
        self._capability_last_used.pop(capability, None)
        self._live_bindings.pop(capability, None)

    def _reclaim_unbound_capabilities(self) -> None:
        """Drop capabilities whose BoundWorkingMemory is gone; never revoke live ones.

        Idle TTL only applies to orphaned tokens that have no live binding.
        Capacity stays bounded by reclaiming dead bindings first, then refusing
        new issues rather than evicting a still-held capability.
        """
        cutoff = time.monotonic() - CAPABILITY_TTL_SECONDS
        for capability, last_used in list(self._capability_last_used.items()):
            alive = self._capability_alive.get(capability)
            if alive is not None and not alive[0]:
                self._drop_capability_locked(capability)
                continue
            if self._binding_is_live(capability):
                continue
            if last_used <= cutoff or capability not in self._live_bindings:
                self._drop_capability_locked(capability)


class WorkingMemory:
    """Composition-root factory. Agent-facing views never hold this object."""

    def __init__(
        self,
        store: EventContextStore,
        redis: RedisClient,
        *,
        degraded_flags: DegradedFlagService | None = None,
        wm_strict: bool | None = None,
    ) -> None:
        self._engine = _MemoryEngine(
            store,
            redis,
            degraded_flags=degraded_flags,
            wm_strict=wm_strict,
        )

    def for_writer(self, writer: str) -> BoundWorkingMemory:
        """Bind a trusted composition-root identity to an agent-safe memory view."""
        engine = self._engine
        canonical = normalize_writer(writer)
        if canonical not in set(FIELD_OWNERSHIP.values()):
            raise GuardrailViolationError(
                f"unknown working-memory writer identity: {writer!r}",
                error_code="working_memory_unauthorized_write",
                details={"writer": writer},
            )
        capability = WriterCapability(owner=canonical, _nonce=object())
        alive = [True]
        with engine._capability_lock:
            engine._reclaim_unbound_capabilities()
            if len(engine._issued_capabilities) >= CAPABILITY_LIMIT:
                raise GuardrailViolationError(
                    "working-memory capability capacity exhausted; release an active capability",
                    error_code="working_memory_capability_capacity_exhausted",
                    details={"limit": CAPABILITY_LIMIT},
                )
            ops = OwnerMemoryOps(
                owner=canonical,
                alive=alive,
                store=engine._store,
                redis=engine._redis,
                degraded_holder=engine._degraded_holder,
                access_logs=engine._access_logs,
                redis_degrade_marked=engine._redis_degrade_marked,
                redis_degrade_lock=engine._redis_degrade_lock,
            )
            engine._issued_capabilities[capability] = canonical
            engine._capability_last_used[capability] = time.monotonic()
            engine._capability_alive[capability] = alive
            engine._ops_by_capability[capability] = ops
            bound = BoundWorkingMemory(_capability=capability, _ops=ops)
            engine._live_bindings[capability] = weakref.ref(bound)
            return bound

    def __getattr__(self, name: str) -> Any:
        return getattr(self._engine, name)
