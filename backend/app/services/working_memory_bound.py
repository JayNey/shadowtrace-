"""Agent-facing WorkingMemory types.

This module must not import the composition-root ``WorkingMemory`` /
``_MemoryEngine`` or hold a process-wide capability lease map. Bound views
only receive a per-owner ops object issued by the composition root.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any, Protocol

from sqlalchemy import select

from app.core.errors import GuardrailViolationError
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.models.context import EventContext
from app.models.working_memory import MemoryAccessLog, ScratchpadEntry
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService

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


class OwnerMemoryOps:
    """Per-owner EventContext I/O. Holds no sibling capabilities or factory."""

    __slots__ = (
        "_owner",
        "_alive",
        "_store",
        "_redis",
        "_degraded_holder",
        "_access_logs",
        "_redis_degrade_marked",
        "_redis_degrade_lock",
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

    @property
    def writer_name(self) -> str:
        return self._owner

    def release(self) -> None:
        self._alive[0] = False

    def _require_alive(self) -> None:
        if not self._alive[0]:
            raise GuardrailViolationError(
                "unrecognized working-memory writer capability",
                error_code="working_memory_unauthorized_write",
                details={"writer": self._owner},
            )

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
        return await self._store.get(event_id, key)

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

    async def _write_with_version_retry(
        self,
        event_id: str,
        key: str,
        value: Any = None,
        *,
        transform: Callable[[Any], Any] | None = None,
    ) -> Any:
        last_conflict = False
        for attempt in range(WRITE_CAS_MAX_ATTEMPTS):
            if transform is None:
                expected = await self._store.get_field_version(event_id, key)
            else:
                current, expected = await self._store.get_versioned_field(event_id, key)
                value = transform(current)
            ok = await self._store.compare_and_set(
                event_id,
                key,
                expected or 0,
                value,
            )
            if ok:
                redis_ok = await self._redis.ping()
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
        if not await self._redis.ping():
            return
        try:
            client = self._redis.get_client()
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


@dataclass(frozen=True, slots=True, weakref_slot=True)
class BoundWorkingMemory:
    """Agent-facing memory view bound to one non-self-reported writer identity."""

    _capability: WriterCapability
    _ops: BoundMemoryOps

    @property
    def writer_name(self) -> str:
        return self._capability.owner

    async def read(self, event_id: str, key: str) -> Any:
        return await self._ops.read(event_id, key)

    async def write(self, event_id: str, key: str, value: Any) -> None:
        await self._ops.write(event_id, key, value)

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        await self._ops.append_scratchpad(event_id, note)

    async def read_scratchpad(self, event_id: str) -> list[ScratchpadEntry]:
        return await self._ops.read_scratchpad(event_id)

    def release(self) -> None:
        self._ops.release()

    revoke = release
