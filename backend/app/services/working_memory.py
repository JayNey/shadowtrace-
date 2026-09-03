"""WorkingMemory + FIELD_OWNERSHIP (ISSUE-014 / intro §4.11)."""

from __future__ import annotations

import logging
import time
import weakref
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from sqlalchemy import select

from app.core.config import get_settings
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
CAPABILITY_LIMIT = 8192
CAPABILITY_TTL_SECONDS = 30 * 60
WM_KEY_PREFIX = "shadowtrace:wm:"
WRITE_CAS_MAX_ATTEMPTS = 3

# --------------------------------------------------------------------------- #
# FIELD_OWNERSHIP — exact EventContext field → trusted writer identity
# --------------------------------------------------------------------------- #

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
    # Written via EventContextStore by report_node / AnalysisOnlyPipeline skip paths
    # (ISSUE-204); WorkingMemory ownership label kept for journal identity.
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
    # ISSUE-233: populated by OutputQualityEvaluator at investigation completion
    # (SuperAgent / AnalysisOnlyPipeline); rule-based by default, optional LLM judge.
    "quality_scores": "OutputQualityEvaluator",
    "scratchpad": "WorkingMemory",
    "degraded_flags": "DegradedFlagService",
    "triage_degraded": "TriageAgent",
    "graph_degraded": "GraphAgent",
    "storyline_degraded": "StorylineService",
    # ISSUE-209 — analyst classification override (API via EventService)
    "classification_override": "EventService",
}

# Legacy writer alias kept for journal entries written before ISSUE-114 hook removal.
WRITER_ALIASES: dict[str, str] = {
    "RuleBasedFalsePositiveHook": "FalsePositiveMatcher",
}


def _validate_field_ownership() -> None:
    """Fail fast if ownership drifts from the EventContext schema (both directions)."""
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
    """Map known aliases onto the canonical FIELD_OWNERSHIP identity."""
    return WRITER_ALIASES.get(writer, writer)


@dataclass(frozen=True, slots=True)
class WriterCapability:
    """Opaque writer identity issued and tracked by one WorkingMemory instance."""

    owner: str
    _nonce: object


@dataclass(frozen=True, slots=True, weakref_slot=True)
class BoundWorkingMemory:
    """Agent-facing memory view bound to one non-self-reported writer identity."""

    _memory: WorkingMemory
    _capability: WriterCapability

    @property
    def writer_name(self) -> str:
        return self._capability.owner

    async def read(self, event_id: str, key: str) -> Any:
        return await self._memory.read(event_id, key, reader=self._capability)

    async def write(self, event_id: str, key: str, value: Any) -> None:
        await self._memory.write(event_id, key, value, writer=self._capability)

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        await self._memory.append_scratchpad(event_id, note, writer=self._capability)

    async def read_scratchpad(self, event_id: str) -> list[ScratchpadEntry]:
        return await self._memory.read_scratchpad(event_id, reader=self._capability)

    def for_writer(self, writer: str) -> BoundWorkingMemory:
        """Mint a new ``BoundWorkingMemory`` for *writer* from the same backing
        ``WorkingMemory``, preserving the single-instance invariants.
        """
        return self._memory.for_writer(writer)

    def release(self) -> None:
        self._memory.release(self._capability)

    revoke = release


class WorkingMemory:
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
        self._live_bindings: dict[WriterCapability, weakref.ReferenceType[BoundWorkingMemory]] = {}
        self._capability_lock = RLock()

    def bind_degraded_flag_service(self, service: DegradedFlagService) -> None:
        """Wire DegradedFlagService after construction (breaks init cycles)."""
        self._degraded_flags = service

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def for_writer(self, writer: str) -> BoundWorkingMemory:
        """Bind a trusted composition-root identity to an agent-safe memory view."""
        canonical = normalize_writer(writer)
        if canonical not in set(FIELD_OWNERSHIP.values()):
            raise GuardrailViolationError(
                f"unknown working-memory writer identity: {writer!r}",
                error_code="working_memory_unauthorized_write",
                details={"writer": writer},
            )
        capability = WriterCapability(owner=canonical, _nonce=object())
        with self._capability_lock:
            self._reclaim_unbound_capabilities()
            if len(self._issued_capabilities) >= CAPABILITY_LIMIT:
                raise GuardrailViolationError(
                    "working-memory capability capacity exhausted; release an active capability",
                    error_code="working_memory_capability_capacity_exhausted",
                    details={"limit": CAPABILITY_LIMIT},
                )
            self._issued_capabilities[capability] = canonical
            self._capability_last_used[capability] = time.monotonic()
            bound = BoundWorkingMemory(self, capability)
            self._live_bindings[capability] = weakref.ref(bound)
            return bound

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
            reader_name = self._resolve_capability(reader)
        except GuardrailViolationError:
            await self._record_access_durable(
                event_id,
                agent_name=self._capability_label(reader),
                op="read",
                key=key,
                allowed=False,
            )
            raise
        if key not in FIELD_OWNERSHIP:
            await self._record_access_durable(
                event_id,
                agent_name=reader_name,
                op="read",
                key=key,
                allowed=False,
            )
            raise GuardrailViolationError(
                f"unregistered EventContext field: {key!r}",
                error_code="working_memory_unauthorized_write",
                details={"event_id": event_id, "key": key, "reader": reader_name},
            )
        await self._record_access_durable(
            event_id,
            agent_name=reader_name,
            op="read",
            key=key,
            allowed=True,
        )
        value = await self._store.get(event_id, key)
        return value

    async def write(
        self,
        event_id: str,
        key: str,
        value: Any,
        writer: WriterCapability,
    ) -> None:
        writer_name = self._capability_label(writer)
        if key not in FIELD_OWNERSHIP:
            await self._record_access_durable(
                event_id,
                agent_name=writer_name,
                op="write",
                key=key,
                allowed=False,
            )
            raise GuardrailViolationError(
                f"unregistered EventContext field: {key!r}",
                error_code="working_memory_unauthorized_write",
                details={"event_id": event_id, "key": key, "writer": writer_name},
            )

        owner = FIELD_OWNERSHIP[key]
        try:
            canonical = self._resolve_capability(writer)
        except GuardrailViolationError:
            await self._record_access_durable(
                event_id,
                agent_name=writer_name,
                op="write",
                key=key,
                allowed=False,
            )
            raise
        if canonical != owner:
            await self._record_access_durable(
                event_id,
                agent_name=canonical,
                op="write",
                key=key,
                allowed=False,
            )
            raise GuardrailViolationError(
                f"writer {canonical!r} is not owner of {key!r} (owner={owner!r})",
                error_code="working_memory_unauthorized_write",
                details={
                    "event_id": event_id,
                    "key": key,
                    "writer": canonical,
                    "owner": owner,
                },
            )

        await self._record_access_durable(
            event_id, agent_name=canonical, op="write", key=key, allowed=True
        )
        await self._write_with_version_retry(event_id, key, value)

    async def append_scratchpad(
        self,
        event_id: str,
        note: str,
        *,
        writer: WriterCapability,
    ) -> None:
        try:
            agent_name = self._resolve_capability(writer)
        except GuardrailViolationError:
            await self._record_access_durable(
                event_id,
                agent_name=self._capability_label(writer),
                op="write",
                key="scratchpad",
                allowed=False,
            )
            raise
        entry = ScratchpadEntry(
            agent_name=agent_name,
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
            agent_name=agent_name,
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

    async def read_scratchpad(
        self,
        event_id: str,
        *,
        reader: WriterCapability,
    ) -> list[ScratchpadEntry]:
        raw = await self.read(event_id, "scratchpad", reader=reader)
        if not raw:
            return []
        if not isinstance(raw, list):
            return []
        return [ScratchpadEntry.model_validate(item) for item in raw]

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
            if self._binding_is_live(capability):
                continue
            if last_used <= cutoff or capability not in self._live_bindings:
                self._drop_capability_locked(capability)

    async def _write_with_version_retry(
        self,
        event_id: str,
        key: str,
        value: Any = None,
        *,
        transform: Callable[[Any], Any] | None = None,
    ) -> Any:
        """CAS a value, recomputing mutations from the latest DB value on conflict."""
        last_conflict = False
        for attempt in range(WRITE_CAS_MAX_ATTEMPTS):
            if transform is None:
                expected = await self._read_field_version(event_id, key)
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
                # compare_and_set does not return redis_ok; probe after success.
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

    async def _read_field_version(self, event_id: str, key: str) -> int | None:
        """Authoritative current version from the DB, not the Redis cache.

        The Redis ``{key}__version`` companion is only a cache and can lag the
        ``event_context_field_version`` table after a degraded (Redis-down) write;
        using it as CAS ``expected`` would spuriously fail a legitimate owner write.
        """
        return await self._store.get_field_version(event_id, key)

    async def _maybe_mark_redis_unavailable(self, event_id: str, redis_ok: bool) -> None:
        if redis_ok:
            with self._redis_degrade_lock:
                self._redis_degrade_marked.pop(event_id, None)
            return
        if self._degraded_flags is None:
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
            await self._degraded_flags.set_flag(
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
        """Best-effort mirror into ``shadowtrace:wm:{event_id}`` Hash."""
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
