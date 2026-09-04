"""Agent-facing WorkingMemory types.

This module must not import the composition-root ``WorkingMemory`` /
``_MemoryEngine`` or hold a process-wide capability lease map. Bound views
hold an opaque token plus a store-free port; EventContextStore lives only
on engine-private ``OwnerMemoryOps``.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from types import FunctionType
from typing import TYPE_CHECKING, Any, Protocol

from app.core.errors import GuardrailViolationError
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.models.context import EventContext
from app.models.working_memory import MemoryAccessLog, ScratchpadEntry
from app.services.degraded_flag_service import DegradedFlagService

if TYPE_CHECKING:
    from app.services.context_service import EventContextStore

logger = logging.getLogger(__name__)

SCRATCHPAD_LIMIT = 200
ACCESS_LOG_LIMIT = 512
EVENT_CACHE_LIMIT = 2048
WRITE_CAS_MAX_ATTEMPTS = 3
WM_KEY_PREFIX = "shadowtrace:wm:"

FIELD_OWNERSHIP: dict[str, str] = {
    "analysis_only_complete": "AnalysisOnlyPipeline",
    "event": "EventService",
    "source_snapshot": "EventService",
    "source_sync_state": "SourceIngester",
    "detection_context_snapshot": "DetectionContextProjector",
    "triage_result": "TriageAgent",
    "false_positive_match": "FalsePositiveMatcher",
    "fp_adjudication": "PostEvidenceFpAdjudicator",
    "evidence_output": "EvidenceAgent",
    "storyline": "StorylineService",
    "graph_output": "GraphAgent",
    "rag_output": "RAGAgent",
    "risk_assessment": "RiskAgent",
    "execution_plan": "PlannerAgent",
    "response_plan": "ResponseAgent",
    "approval_records": "ApprovalEngine",
    "disposition_only_intent": "WorkflowRuntimeService",
    "execution_substate": "WorkflowRuntimeService",
    "manual_hold": "ManualResolutionService",
    "execution_summary": "ActionExecutionService",
    "execution_jobs": "ActionExecutionService",
    "verification_result": "VerifyAgent",
    "rollback_results": "RollbackService",
    "impact_assessments": "ImpactAssessmentService",
    "report": "ReportAgent",
    "report_generated": "WorkflowRuntimeService",
    "memory_output": "MemoryAgent",
    "memory_output_early": "MemoryAgent",
    "disposition_commands": "DispositionSyncService",
    "disposition_receipts": "DispositionSyncService",
    "writeback_summary": "DispositionSyncService",
    "state_history": "StateMachineService",
    "replan_count": "StateMachineService",
    "budget_usage": "BudgetService",
    "guard_violations": "OutputGuard",
    "convergence_state": "ConvergenceGuard",
    "quality_scores": "OutputQualityEvaluator",
    "scratchpad": "WorkingMemory",
    "degraded_flags": "DegradedFlagService",
    "triage_degraded": "TriageAgent",
    "graph_degraded": "GraphAgent",
    "storyline_degraded": "StorylineService",
    "classification_override": "EventService",
}

WRITER_ALIASES: dict[str, str] = {
    "RuleBasedFalsePositiveHook": "FalsePositiveMatcher",
}


def _validate_field_ownership() -> None:
    schema_fields = set(EventContext.model_fields.keys())
    owned_fields = set(FIELD_OWNERSHIP.keys())
    missing = schema_fields - owned_fields
    ghost = owned_fields - schema_fields
    if missing or ghost:
        raise RuntimeError(
            "FIELD_OWNERSHIP must exactly cover EventContext fields: "
            f"missing={sorted(missing)} ghost={sorted(ghost)}"
        )


_validate_field_ownership()


def wm_key(event_id: str) -> str:
    return f"{WM_KEY_PREFIX}{event_id}"


def normalize_writer(writer: str) -> str:
    return WRITER_ALIASES.get(writer, writer)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class WriterCapability:
    """Opaque writer identity issued and tracked by one WorkingMemory instance."""

    owner: str
    _nonce: object


class BoundMemoryOps(Protocol):
    writer_name: str

    async def read(self, event_id: str, key: str) -> Any: ...

    async def write(self, event_id: str, key: str, value: Any) -> None: ...

    async def append_scratchpad(self, event_id: str, note: str) -> None: ...

    async def read_scratchpad(self, event_id: str) -> list[ScratchpadEntry]: ...

    def release(self) -> None: ...


def _store_is_durable(store: object) -> bool:
    from app.services.context_service import EventContextStore

    return isinstance(store, EventContextStore)


def _unauthorized(writer: str) -> GuardrailViolationError:
    return GuardrailViolationError(
        "unrecognized working-memory writer capability",
        error_code="working_memory_unauthorized_write",
        details={"writer": writer},
    )


def _self_is_live(alive: list[bool], holder: list[object]) -> bool:
    return bool(alive and alive[0] and holder and holder[0] is not None)


def _bind_callable(template: Callable[..., Any], defaults: tuple[Any, ...]) -> Callable[..., Any]:
    """Bind engine-private state via defaults, never via closure cells or fields."""
    return FunctionType(
        template.__code__,
        {"__builtins__": __builtins__},
        template.__name__,
        defaults,
        None,
    )


def _drop_capability(capability: WriterCapability, engine: Any) -> None:
    with engine._capability_lock:
        engine._drop_capability_locked(capability)


async def _port_read(event_id: str, key: str, ops: OwnerMemoryOps) -> Any:
    return await ops.read(event_id, key)


async def _port_write(event_id: str, key: str, value: Any, ops: OwnerMemoryOps) -> None:
    await ops.write(event_id, key, value)


async def _port_append(event_id: str, note: str, ops: OwnerMemoryOps) -> None:
    await ops.append_scratchpad(event_id, note)


async def _port_read_scratchpad(event_id: str, ops: OwnerMemoryOps) -> list[ScratchpadEntry]:
    return await ops.read_scratchpad(event_id)


async def _emit_denied(
    event_id: str,
    *,
    agent_name: str,
    op: str,
    key: str,
    session_factory: Any,
    access_logs: OrderedDict[str, list[MemoryAccessLog]],
    durable: bool,
) -> None:
    log = MemoryAccessLog(
        timestamp=datetime.now(UTC),
        agent_name=agent_name,
        op=op,  # type: ignore[arg-type]
        key=key,
        allowed=False,
    )
    if event_id not in access_logs and len(access_logs) >= EVENT_CACHE_LIMIT:
        access_logs.popitem(last=False)
    entries = access_logs.setdefault(event_id, [])
    access_logs.move_to_end(event_id)
    entries.append(log)
    if len(entries) > ACCESS_LOG_LIMIT:
        del entries[: len(entries) - ACCESS_LOG_LIMIT]
    if not durable or session_factory is None:
        return
    async with session_factory() as session:
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


def _dead_globals() -> dict[str, Any]:
    return {
        "__builtins__": __builtins__,
        "GuardrailViolationError": GuardrailViolationError,
        "_emit_denied": _emit_denied,
        "_unauthorized": _unauthorized,
    }


async def _dead_read(
    event_id: str,
    key: str,
    owner: str,
    session_factory: Any,
    access_logs: OrderedDict[str, list[MemoryAccessLog]],
    durable: bool,
) -> Any:
    await _emit_denied(
        event_id,
        agent_name=owner,
        op="read",
        key=key,
        session_factory=session_factory,
        access_logs=access_logs,
        durable=durable,
    )
    raise _unauthorized(owner)


async def _dead_write(
    event_id: str,
    key: str,
    value: Any,
    owner: str,
    session_factory: Any,
    access_logs: OrderedDict[str, list[MemoryAccessLog]],
    durable: bool,
) -> None:
    await _emit_denied(
        event_id,
        agent_name=owner,
        op="write",
        key=key,
        session_factory=session_factory,
        access_logs=access_logs,
        durable=durable,
    )
    raise _unauthorized(owner)


async def _dead_append(
    event_id: str,
    note: str,
    owner: str,
    session_factory: Any,
    access_logs: OrderedDict[str, list[MemoryAccessLog]],
    durable: bool,
) -> None:
    await _emit_denied(
        event_id,
        agent_name=owner,
        op="write",
        key="scratchpad",
        session_factory=session_factory,
        access_logs=access_logs,
        durable=durable,
    )
    raise _unauthorized(owner)


async def _dead_read_scratchpad(
    event_id: str,
    owner: str,
    session_factory: Any,
    access_logs: OrderedDict[str, list[MemoryAccessLog]],
    durable: bool,
) -> list[ScratchpadEntry]:
    await _emit_denied(
        event_id,
        agent_name=owner,
        op="read",
        key="scratchpad",
        session_factory=session_factory,
        access_logs=access_logs,
        durable=durable,
    )
    raise _unauthorized(owner)


def _bind_dead(template: Callable[..., Any], defaults: tuple[Any, ...]) -> Callable[..., Any]:
    return FunctionType(
        template.__code__,
        _dead_globals(),
        template.__name__,
        defaults,
        None,
    )


class OwnerMemoryOps:
    """Engine-private per-owner EventContext I/O. Never a BoundWorkingMemory field."""

    __slots__ = (
        "_owner",
        "_alive",
        "_store",
        "_redis",
        "_degraded_holder",
        "_access_logs",
        "_redis_degrade_marked",
        "_redis_degrade_lock",
        "_session_factory",
        "_durable",
        "_live_check",
    )

    def __init__(
        self,
        *,
        owner: str,
        alive: list[bool],
        store: EventContextStore,
        redis: RedisClient,
        degraded_holder: list[DegradedFlagService | None],
        access_logs: OrderedDict[str, list[MemoryAccessLog]],
        redis_degrade_marked: OrderedDict[str, None],
        redis_degrade_lock: RLock,
    ) -> None:
        self._owner = owner
        self._alive = alive
        self._store = store
        self._redis = redis
        self._degraded_holder = degraded_holder
        self._access_logs = access_logs
        self._redis_degrade_marked = redis_degrade_marked
        self._redis_degrade_lock = redis_degrade_lock
        self._durable = _store_is_durable(store)
        self._session_factory = getattr(store, "_session_factory", None) if self._durable else None
        self._live_check: Callable[[], bool] = lambda: False

    def bind_liveness(self, alive: list[bool], holder: list[object]) -> None:
        self._live_check = _bind_callable(_self_is_live, (alive, holder))  # type: ignore[assignment]

    @property
    def writer_name(self) -> str:
        return self._owner

    def disconnect(self) -> None:
        """Permanently disable this ops object; restoring flags cannot revive I/O."""
        self._alive[0] = False
        self._store = None
        self._redis = None
        self._session_factory = None
        self._durable = False
        self._live_check = lambda: False

    def release(self) -> None:
        self.disconnect()

    def _require_alive(self) -> None:
        live_check = self._live_check
        if (
            self._store is None
            or not self._alive[0]
            or not callable(live_check)
            or not live_check()
        ):
            raise _unauthorized(self._owner)

    async def read(self, event_id: str, key: str) -> Any:
        try:
            self._require_alive()
        except GuardrailViolationError:
            await self._record_access_durable(
                event_id,
                agent_name=self._owner,
                op="read",
                key=key,
                allowed=False,
            )
            raise
        if key not in FIELD_OWNERSHIP:
            await self._record_access_durable(
                event_id,
                agent_name=self._owner,
                op="read",
                key=key,
                allowed=False,
            )
            raise GuardrailViolationError(
                f"unregistered EventContext field: {key!r}",
                error_code="working_memory_unauthorized_write",
                details={"event_id": event_id, "key": key, "reader": self._owner},
            )
        await self._record_access_durable(
            event_id,
            agent_name=self._owner,
            op="read",
            key=key,
            allowed=True,
        )
        store = self._store
        if store is None:
            raise _unauthorized(self._owner)
        return await store.get(event_id, key)

    async def write(self, event_id: str, key: str, value: Any) -> None:
        if key not in FIELD_OWNERSHIP:
            await self._record_access_durable(
                event_id,
                agent_name=self._owner,
                op="write",
                key=key,
                allowed=False,
            )
            raise GuardrailViolationError(
                f"unregistered EventContext field: {key!r}",
                error_code="working_memory_unauthorized_write",
                details={"event_id": event_id, "key": key, "writer": self._owner},
            )
        try:
            self._require_alive()
        except GuardrailViolationError:
            await self._record_access_durable(
                event_id,
                agent_name=self._owner,
                op="write",
                key=key,
                allowed=False,
            )
            raise
        owner = FIELD_OWNERSHIP[key]
        if self._owner != owner:
            await self._record_access_durable(
                event_id,
                agent_name=self._owner,
                op="write",
                key=key,
                allowed=False,
            )
            raise GuardrailViolationError(
                f"writer {self._owner!r} is not owner of {key!r} (owner={owner!r})",
                error_code="working_memory_unauthorized_write",
                details={
                    "event_id": event_id,
                    "key": key,
                    "writer": self._owner,
                    "owner": owner,
                },
            )
        await self._record_access_durable(
            event_id, agent_name=self._owner, op="write", key=key, allowed=True
        )
        await self._write_with_version_retry(event_id, key, value)

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        try:
            self._require_alive()
        except GuardrailViolationError:
            await self._record_access_durable(
                event_id,
                agent_name=self._owner,
                op="write",
                key="scratchpad",
                allowed=False,
            )
            raise
        entry = ScratchpadEntry(
            agent_name=self._owner,
            timestamp=datetime.now(UTC),
            note=note,
        )
        serialized = entry.model_dump(mode="json")

        def append_to(current: Any) -> list[Any]:
            entries = list(current) if isinstance(current, list) else []
            entries.append(serialized)
            return entries[-SCRATCHPAD_LIMIT:]

        await self._record_access_durable(
            event_id,
            agent_name=self._owner,
            op="write",
            key="scratchpad",
            allowed=True,
        )
        entries = await self._write_with_version_retry(
            event_id,
            "scratchpad",
            transform=append_to,
        )
        await self._mirror_wm_scratchpad(event_id, entries)

    async def read_scratchpad(self, event_id: str) -> list[ScratchpadEntry]:
        raw = await self.read(event_id, "scratchpad")
        if not raw:
            return []
        if not isinstance(raw, list):
            return []
        return [ScratchpadEntry.model_validate(item) for item in raw]

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
        factory = self._session_factory
        if not self._durable or factory is None:
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

    async def _write_with_version_retry(
        self,
        event_id: str,
        key: str,
        value: Any = None,
        *,
        transform: Callable[[Any], Any] | None = None,
    ) -> Any:
        store = self._store
        redis = self._redis
        if store is None or redis is None:
            raise _unauthorized(self._owner)
        last_conflict = False
        for attempt in range(WRITE_CAS_MAX_ATTEMPTS):
            if transform is None:
                expected = await store.get_field_version(event_id, key)
            else:
                current, expected = await store.get_versioned_field(event_id, key)
                value = transform(current)
            ok = await store.compare_and_set(
                event_id,
                key,
                expected or 0,
                value,
            )
            if ok:
                redis_ok = await redis.ping()
                await self._maybe_mark_redis_unavailable(event_id, redis_ok)
                return value
            last_conflict = True
            logger.info(
                "WorkingMemory CAS conflict event_id=%s key=%s attempt=%s",
                event_id,
                key,
                attempt + 1,
            )

        if last_conflict:
            raise GuardrailViolationError(
                f"version conflict writing {key!r} after {WRITE_CAS_MAX_ATTEMPTS} attempts",
                error_code="version_conflict",
                details={"event_id": event_id, "key": key},
            )

    async def _maybe_mark_redis_unavailable(self, event_id: str, redis_ok: bool) -> None:
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

    async def _mirror_wm_scratchpad(self, event_id: str, entries: list[Any]) -> None:
        redis = self._redis
        if redis is None or not await redis.ping():
            return
        try:
            client = redis.get_client()
            await client.hset(
                wm_key(event_id),
                "scratchpad",
                RedisClient.dumps(entries),
            )
        except Exception:  # noqa: BLE001 — draft mirror must not fail the write
            logger.warning(
                "failed to mirror scratchpad to wm key event_id=%s",
                event_id,
                exc_info=True,
            )


class _AgentMemoryPort:
    """Store-free proxy. Engine-private ops are bound via function defaults, not fields."""

    __slots__ = (
        "_owner",
        "_read_fn",
        "_write_fn",
        "_append_fn",
        "_read_scratch_fn",
        "_release_fn",
        "_sealed",
    )

    def __init__(
        self,
        *,
        owner: str,
        ops: OwnerMemoryOps,
        engine: Any,
        capability: WriterCapability,
    ) -> None:
        self._owner = owner
        self._read_fn = _bind_callable(_port_read, (ops,))
        self._write_fn = _bind_callable(_port_write, (ops,))
        self._append_fn = _bind_callable(_port_append, (ops,))
        self._read_scratch_fn = _bind_callable(_port_read_scratchpad, (ops,))
        self._release_fn = _bind_callable(_drop_capability, (capability, engine))
        self._sealed = False

    async def read(self, event_id: str, key: str) -> Any:
        return await self._read_fn(event_id, key)

    async def write(self, event_id: str, key: str, value: Any) -> None:
        await self._write_fn(event_id, key, value)

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        await self._append_fn(event_id, note)

    async def read_scratchpad(self, event_id: str) -> list[ScratchpadEntry]:
        return await self._read_scratch_fn(event_id)

    def release(self) -> None:
        if self._sealed:
            return
        self._sealed = True
        ops = None
        defaults = getattr(self._write_fn, "__defaults__", None) or ()
        for item in defaults:
            if isinstance(item, OwnerMemoryOps):
                ops = item
                break
        factory = getattr(ops, "_session_factory", None) if ops is not None else None
        logs = getattr(ops, "_access_logs", None) if ops is not None else None
        if logs is None:
            logs = OrderedDict()
        durable = bool(getattr(ops, "_durable", False)) if ops is not None else False
        try:
            self._release_fn()
        finally:
            self._seal(factory, logs, durable)

    def _seal(
        self,
        factory: Any,
        logs: OrderedDict[str, list[MemoryAccessLog]],
        durable: bool,
    ) -> None:
        owner = self._owner
        dead = (owner, factory, logs, durable)
        self._read_fn = _bind_dead(_dead_read, dead)
        self._write_fn = _bind_dead(_dead_write, (owner, factory, logs, durable))
        self._append_fn = _bind_dead(_dead_append, dead)
        self._read_scratch_fn = _bind_dead(_dead_read_scratchpad, dead)
        self._release_fn = lambda: None


@dataclass(frozen=True, slots=True, weakref_slot=True)
class BoundWorkingMemory:
    """Agent-facing memory view bound to one non-self-reported writer identity."""

    _capability: WriterCapability
    _port: _AgentMemoryPort

    @property
    def writer_name(self) -> str:
        return self._capability.owner

    async def read(self, event_id: str, key: str) -> Any:
        return await self._port.read(event_id, key)

    async def write(self, event_id: str, key: str, value: Any) -> None:
        await self._port.write(event_id, key, value)

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        await self._port.append_scratchpad(event_id, note)

    async def read_scratchpad(self, event_id: str) -> list[ScratchpadEntry]:
        return await self._port.read_scratchpad(event_id)

    def release(self) -> None:
        self._port.release()

    revoke = release


def bind_working_memory(
    *,
    capability: WriterCapability,
    ops: OwnerMemoryOps,
    engine: Any,
) -> BoundWorkingMemory:
    """Composition-root constructor. Agents never call this."""
    return BoundWorkingMemory(
        _capability=capability,
        _port=_AgentMemoryPort(
            owner=capability.owner,
            ops=ops,
            engine=engine,
            capability=capability,
        ),
    )
