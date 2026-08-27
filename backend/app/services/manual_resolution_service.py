"""Durable manual-resolution hold + graph resume intent (ISSUE-277 / #873)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import IdempotencyKeyReuseError, ValidationError
from app.core.metrics import record_dispatch_schedule
from app.db import models as orm
from app.models.enums import EventStatus, ExecutionSubstate, GraphResumeIntentStatus
from app.models.graph_resume_intent import (
    ACTIVE_GRAPH_RESUME_STATUSES,
    INTENT_KIND_MANUAL_RESOLUTION_RESUME,
    INTENT_KIND_NESTED_GRAPH_WAKEUP,
    INTENT_VERSION_ISSUE277_V1,
    MANUAL_HOLD_JOURNAL_FIELD,
    NESTED_WAKEUP_HOLD_GENERATION,
    RESOLUTION_SOURCE_ACTION_UNKNOWN,
    RESOLUTION_SOURCE_NESTED_WAKEUP,
    RESOLUTION_SOURCE_WRITEBACK_AUTO,
    RESOLUTION_SOURCE_WRITEBACK_MANUAL,
    SUBJECT_KIND_ACTION,
    SUBJECT_KIND_EVENT,
    SUBJECT_KIND_WRITEBACK,
    TERMINAL_GRAPH_RESUME_STATUSES,
    GraphResumeIntentRecord,
    ManualHoldSnapshot,
    parse_manual_hold_snapshot,
    validate_graph_resume_transition,
)
from app.services.context_service import (
    append_context_journal_in_session,
    unwrap_journal_value,
)
from app.services.degraded_flag_service import DegradedFlagService

logger = logging.getLogger(__name__)

_OPERATION_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_CLAIM_LEASE_S = 120
_DISPATCH_WORKER_ID = "graph-resume-dispatcher-1"
_STARTED_STALE_MIN_S = 660
_MAX_ATTEMPTS = 5
_NESTED_WAKEUP_RETRY_BACKOFF_S = 15
_NESTED_WAKEUP_STILL_WAITING = frozenset(
    {
        ExecutionSubstate.WAITING_WRITEBACK,
        ExecutionSubstate.WAITING_EXECUTION,
        ExecutionSubstate.WAITING_APPROVAL,
        ExecutionSubstate.MANUAL_RESOLUTION,
    }
)


def new_graph_resume_intent_id() -> str:
    return f"gri-{secrets.token_hex(8)}"


def resolution_payload_sha256(
    *,
    event_id: str,
    hold_generation: int,
    resolution_source: str,
    subject_kind: str,
    subject_id: str,
    resolution: str | None,
) -> str:
    payload = {
        "event_id": event_id,
        "hold_generation": hold_generation,
        "resolution_source": resolution_source,
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "resolution": resolution,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ManualResolutionService:
    """Enter durable manual holds and enqueue fenced graph resume intents."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        workflow_runtime: Any | None = None,
        resume_runner: Any | None = None,
        degraded_flags: DegradedFlagService | None = None,
        claim_lease_s: int = _CLAIM_LEASE_S,
        max_attempts: int = _MAX_ATTEMPTS,
        nested_retry_backoff_s: int = _NESTED_WAKEUP_RETRY_BACKOFF_S,
    ) -> None:
        self._session_factory = session_factory
        self._runtime = workflow_runtime
        self._resume_runner = resume_runner
        self._degraded = degraded_flags
        self._claim_lease_s = claim_lease_s
        self._max_attempts = max_attempts
        self._nested_retry_backoff_s = max(0, int(nested_retry_backoff_s))
        self._dispatch_scheduled = False
        self._pending_in_process: list[tuple[str | None, str | None, str, tuple[str, ...]]] = []

    def bind_runtime(self, workflow_runtime: Any) -> None:
        self._runtime = workflow_runtime

    def bind_resume_runner(self, resume_runner: Any) -> None:
        self._resume_runner = resume_runner

    async def enter_manual_hold(
        self,
        event_id: str,
        *,
        reason: str,
        pending_ids: list[str] | None = None,
        checkpoint_id: str | None = None,
        event_status: EventStatus | None = None,
    ) -> ManualHoldSnapshot:
        """Persist MANUAL_RESOLUTION + bump hold generation under a row lock.

        Hold metadata and execution_substate are written in one transaction so a
        crash cannot leave MANUAL_RESOLUTION without a fenced generation.
        """
        from app.models.workflow import validate_execution_substate

        authoritative: EventStatus
        async with self._session_factory() as session:
            async with session.begin():
                event = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
                if event is None:
                    raise ValidationError(
                        "event not found for manual hold",
                        details={"event_id": event_id},
                    )
                authoritative = EventStatus(event.status)
                if event_status is not None and event_status is not authoritative:
                    raise ValidationError(
                        "caller EventStatus does not match authoritative state",
                        details={
                            "event_id": event_id,
                            "caller_status": event_status.value,
                            "authoritative_status": authoritative.value,
                        },
                    )
                current = await self._read_manual_hold(session, event_id)
                generation = int(current.generation if current else 0) + 1
                snapshot = ManualHoldSnapshot(
                    generation=generation,
                    reason=reason,
                    pending_ids=tuple(pending_ids or []),
                    checkpoint_id=checkpoint_id or event_id,
                )
                await append_context_journal_in_session(
                    session,
                    event_id,
                    MANUAL_HOLD_JOURNAL_FIELD,
                    {
                        "generation": snapshot.generation,
                        "reason": snapshot.reason,
                        "pending_ids": list(snapshot.pending_ids),
                        "checkpoint_id": snapshot.checkpoint_id,
                    },
                )
                current_substate = await self._read_execution_substate(session, event_id)
                if current_substate is not ExecutionSubstate.MANUAL_RESOLUTION:
                    validate_execution_substate(
                        authoritative,
                        current_substate,
                        ExecutionSubstate.MANUAL_RESOLUTION,
                    )
                    await append_context_journal_in_session(
                        session,
                        event_id,
                        "execution_substate",
                        ExecutionSubstate.MANUAL_RESOLUTION.value,
                    )
        # Journal already holds authoritative MANUAL_RESOLUTION. Runtime sync is
        # best-effort for WM observers and must not fail the durable hold commit.
        if self._runtime is not None:
            try:
                await self._runtime.set_execution_substate(
                    event_id,
                    ExecutionSubstate.MANUAL_RESOLUTION,
                    event_status=authoritative,
                )
            except Exception:
                logger.warning(
                    "post-commit runtime MANUAL_RESOLUTION sync failed event=%s",
                    event_id,
                    exc_info=True,
                )
        return snapshot

    async def create_or_replay_resume_intent(
        self,
        event_id: str,
        *,
        resolution_source: str,
        subject_kind: str,
        subject_id: str,
        resolution: str | None = None,
        principal: str | None = None,
        comment: str | None = None,
        evidence_ref: str | None = None,
        operation_id: str | None = None,
        hold_generation: int | None = None,
        checkpoint_id: str | None = None,
    ) -> GraphResumeIntentRecord:
        if operation_id is not None and not _OPERATION_ID_RE.fullmatch(operation_id):
            raise ValidationError(
                "operation_id must be 1-128 chars of [A-Za-z0-9._:-]",
                details={"operation_id": operation_id},
            )
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    return await self.create_or_replay_resume_intent_in_session(
                        session,
                        event_id,
                        resolution_source=resolution_source,
                        subject_kind=subject_kind,
                        subject_id=subject_id,
                        resolution=resolution,
                        principal=principal,
                        comment=comment,
                        evidence_ref=evidence_ref,
                        operation_id=operation_id,
                        hold_generation=hold_generation,
                        checkpoint_id=checkpoint_id,
                    )
        except IntegrityError:
            logger.info(
                "graph resume intent insert raced event=%s operation_id=%s",
                event_id,
                operation_id,
            )
            return await self._lookup_resume_intent_after_race(
                event_id,
                operation_id=operation_id,
                hold_generation=hold_generation,
            )

    async def enqueue_nested_wakeup(
        self,
        event_id: str,
        *,
        reason: str = "nested_wakeup",
    ) -> GraphResumeIntentRecord | None:
        """Durable wakeup that does not require a MANUAL_RESOLUTION hold.

        Uses hold_generation=0 so it cannot collide with real manual holds
        (those start at 1). One active nested wakeup per event is enough.
        """
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    event = await session.get(
                        orm.SecurityEvent,
                        event_id,
                        with_for_update=True,
                    )
                    if event is None:
                        logger.error(
                            "nested wakeup skipped: event missing event=%s",
                            event_id,
                        )
                        return None
                    payload_hash = resolution_payload_sha256(
                        event_id=event_id,
                        hold_generation=NESTED_WAKEUP_HOLD_GENERATION,
                        resolution_source=RESOLUTION_SOURCE_NESTED_WAKEUP,
                        subject_kind=SUBJECT_KIND_EVENT,
                        subject_id=event_id,
                        resolution=reason,
                    )
                    active = await session.scalar(
                        select(orm.GraphResumeIntent)
                        .where(
                            orm.GraphResumeIntent.event_id == event_id,
                            orm.GraphResumeIntent.hold_generation
                            == NESTED_WAKEUP_HOLD_GENERATION,
                            orm.GraphResumeIntent.status.in_(
                                [status.value for status in ACTIVE_GRAPH_RESUME_STATUSES]
                            ),
                        )
                        .with_for_update()
                    )
                    if active is not None:
                        record = self._record_from_row(active)
                    else:
                        row = orm.GraphResumeIntent(
                            intent_id=new_graph_resume_intent_id(),
                            event_id=event_id,
                            intent_kind=INTENT_KIND_NESTED_GRAPH_WAKEUP,
                            intent_version=INTENT_VERSION_ISSUE277_V1,
                            status=GraphResumeIntentStatus.PENDING.value,
                            revision=1,
                            attempt=0,
                            hold_generation=NESTED_WAKEUP_HOLD_GENERATION,
                            checkpoint_id=event_id,
                            operation_id=None,
                            resolution_source=RESOLUTION_SOURCE_NESTED_WAKEUP,
                            subject_kind=SUBJECT_KIND_EVENT,
                            subject_id=event_id,
                            resolution=reason,
                            principal="NestedGraphResume",
                            comment=reason,
                            evidence_ref=None,
                            payload_sha256=payload_hash,
                        )
                        session.add(row)
                        await session.flush()
                        record = self._record_from_row(row)
            await self._dispatch_nested_wakeup_if_unbound(record)
            return record
        except IntegrityError:
            logger.info(
                "nested graph wakeup insert raced event=%s",
                event_id,
            )
            try:
                record = await self._lookup_resume_intent_after_race(
                    event_id,
                    operation_id=None,
                    hold_generation=NESTED_WAKEUP_HOLD_GENERATION,
                )
                await self._dispatch_nested_wakeup_if_unbound(record)
                return record
            except ValidationError:
                logger.exception(
                    "nested graph wakeup race lookup failed event=%s",
                    event_id,
                )
                raise
        except Exception:
            logger.exception("failed to enqueue nested graph wakeup event=%s", event_id)
            raise

    async def _dispatch_nested_wakeup_if_unbound(
        self,
        record: GraphResumeIntentRecord,
        *,
        ignore_lease: bool = False,
    ) -> None:
        """Dispatch only after the investigation graph has unbound this event.

        ContextVar is process-local; Redis EventLease on the parent SuperAgent
        outlives bind exit, so skip dispatch while that lock is still held.
        After a successful lease release, callers pass ``ignore_lease=True``:
        resume still fences via ``EventLease.acquire``.
        """
        from app.orchestration.graph_invocation import (
            investigation_lease_is_held,
            is_in_investigation_graph,
        )

        if is_in_investigation_graph(event_id=record.event_id):
            logger.info(
                "nested wakeup persisted without dispatch; graph still bound event=%s",
                record.event_id,
            )
            return
        if not ignore_lease and await investigation_lease_is_held(record.event_id):
            logger.info(
                "nested wakeup persisted without dispatch; event lease held event=%s",
                record.event_id,
            )
            return
        if record.status not in {
            GraphResumeIntentStatus.PENDING,
            GraphResumeIntentStatus.RETRY,
        }:
            return
        self.schedule_dispatch(
            event_id=record.event_id,
            intent_id=record.intent_id,
            trigger="nested_wakeup",
        )

    async def kick_nested_wakeup_dispatch(self, event_id: str) -> None:
        """Re-enqueue a PENDING/RETRY nested wakeup after EventLease release.

        Does not insert a new intent — a second insert would resume every
        investigation that happens to have no active nested row.
        """
        async with self._session_factory() as session:
            row = await session.scalar(
                select(orm.GraphResumeIntent)
                .where(
                    orm.GraphResumeIntent.event_id == event_id,
                    orm.GraphResumeIntent.hold_generation == NESTED_WAKEUP_HOLD_GENERATION,
                    orm.GraphResumeIntent.intent_kind == INTENT_KIND_NESTED_GRAPH_WAKEUP,
                    orm.GraphResumeIntent.status.in_(
                        [
                            GraphResumeIntentStatus.PENDING.value,
                            GraphResumeIntentStatus.RETRY.value,
                        ]
                    ),
                )
                .order_by(orm.GraphResumeIntent.updated_at.desc())
            )
            if row is None:
                return
            record = self._record_from_row(row)
        await self._dispatch_nested_wakeup_if_unbound(record, ignore_lease=True)

    def _nested_retry_ready(self, row: orm.GraphResumeIntent, now: datetime) -> bool:
        if str(row.intent_kind) != INTENT_KIND_NESTED_GRAPH_WAKEUP:
            return True
        if GraphResumeIntentStatus(row.status) is not GraphResumeIntentStatus.RETRY:
            return True
        if self._nested_retry_backoff_s <= 0:
            return True
        updated = row.updated_at
        if updated is None:
            return True
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=UTC)
        return updated <= now - timedelta(seconds=self._nested_retry_backoff_s)

    async def _nested_wakeup_still_waiting(self, event_id: str) -> bool:
        async with self._session_factory() as session:
            event = await session.get(orm.SecurityEvent, event_id)
            if event is not None and str(event.status) == EventStatus.WAITING_APPROVAL.value:
                return True
            substate = await self._read_execution_substate(session, event_id)
            return substate in _NESTED_WAKEUP_STILL_WAITING

    async def _nested_wakeup_blocked_by_manual_hold(self, event_id: str) -> bool:
        """True when a durable manual hold already owns the event.

        Nested ainvoke would re-run Verify → manual_hold_node and bump
        hold generation, invalidating the operator's resume intent.
        """
        async with self._session_factory() as session:
            substate = await self._read_execution_substate(session, event_id)
            if substate is not ExecutionSubstate.MANUAL_RESOLUTION:
                return False
            return await self._read_manual_hold(session, event_id) is not None

    async def create_or_replay_resume_intent_in_session(
        self,
        session: AsyncSession,
        event_id: str,
        *,
        resolution_source: str,
        subject_kind: str,
        subject_id: str,
        resolution: str | None = None,
        principal: str | None = None,
        comment: str | None = None,
        evidence_ref: str | None = None,
        operation_id: str | None = None,
        hold_generation: int | None = None,
        checkpoint_id: str | None = None,
    ) -> GraphResumeIntentRecord:
        """Create/replay resume intent inside the caller's adjudication transaction.

        Insert races use a SAVEPOINT so subject status CAS is not rolled back when
        another concurrent resolution already created the active hold intent.
        """
        if operation_id is not None and not _OPERATION_ID_RE.fullmatch(operation_id):
            raise ValidationError(
                "operation_id must be 1-128 chars of [A-Za-z0-9._:-]",
                details={"operation_id": operation_id},
            )
        event = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
        if event is None:
            raise ValidationError(
                "event not found for graph resume intent",
                details={"event_id": event_id},
            )
        substate = await self._read_execution_substate(session, event_id)
        if substate is not ExecutionSubstate.MANUAL_RESOLUTION:
            raise ValidationError(
                "graph resume intent requires MANUAL_RESOLUTION hold",
                details={
                    "event_id": event_id,
                    "execution_substate": substate.value,
                },
            )
        hold = await self._read_manual_hold(session, event_id)
        if hold is None:
            raise ValidationError(
                "manual hold metadata missing",
                details={"event_id": event_id},
            )
        generation = hold.generation if hold_generation is None else hold_generation
        if generation != hold.generation:
            raise IdempotencyKeyReuseError(
                "hold generation mismatch for resume intent",
                details={
                    "event_id": event_id,
                    "expected_generation": hold.generation,
                    "provided_generation": generation,
                },
            )
        payload_hash = resolution_payload_sha256(
            event_id=event_id,
            hold_generation=generation,
            resolution_source=resolution_source,
            subject_kind=subject_kind,
            subject_id=subject_id,
            resolution=resolution,
        )
        if operation_id is not None:
            existing = await session.scalar(
                select(orm.GraphResumeIntent).where(
                    orm.GraphResumeIntent.operation_id == operation_id
                )
            )
            if existing is not None:
                if existing.event_id != event_id or existing.payload_sha256 != payload_hash:
                    raise IdempotencyKeyReuseError(
                        "operation_id was already used with a different resolution",
                        details={
                            "operation_id": operation_id,
                            "intent_id": existing.intent_id,
                            "event_id": event_id,
                        },
                    )
                return self._record_from_row(existing)

        active = await session.scalar(
            select(orm.GraphResumeIntent)
            .where(
                orm.GraphResumeIntent.event_id == event_id,
                orm.GraphResumeIntent.hold_generation == generation,
                orm.GraphResumeIntent.status.in_(
                    [status.value for status in ACTIVE_GRAPH_RESUME_STATUSES]
                ),
            )
            .with_for_update()
        )
        if active is not None:
            return self._record_from_row(active)

        row = orm.GraphResumeIntent(
            intent_id=new_graph_resume_intent_id(),
            event_id=event_id,
            intent_kind=INTENT_KIND_MANUAL_RESOLUTION_RESUME,
            intent_version=INTENT_VERSION_ISSUE277_V1,
            status=GraphResumeIntentStatus.PENDING.value,
            revision=1,
            attempt=0,
            hold_generation=generation,
            checkpoint_id=checkpoint_id or hold.checkpoint_id or event_id,
            operation_id=operation_id,
            resolution_source=resolution_source,
            subject_kind=subject_kind,
            subject_id=subject_id,
            resolution=resolution,
            principal=principal,
            comment=comment,
            evidence_ref=evidence_ref,
            payload_sha256=payload_hash,
        )
        try:
            async with session.begin_nested():
                session.add(row)
                session.add(
                    orm.EventAuditLog(
                        event_id=event_id,
                        from_status=ExecutionSubstate.MANUAL_RESOLUTION.value,
                        to_status=GraphResumeIntentStatus.PENDING.value,
                        operator=principal or "ManualResolutionService",
                        reason=(
                            f"graph_resume_intent:create:{resolution_source}:"
                            f"{subject_kind}:{subject_id}"
                        ),
                    )
                )
                await session.flush()
        except IntegrityError:
            logger.info(
                "graph resume intent nested insert raced event=%s generation=%s",
                event_id,
                generation,
            )
            if operation_id is not None:
                by_op = await session.scalar(
                    select(orm.GraphResumeIntent).where(
                        orm.GraphResumeIntent.operation_id == operation_id
                    )
                )
                if by_op is not None:
                    if by_op.event_id != event_id or by_op.payload_sha256 != payload_hash:
                        raise IdempotencyKeyReuseError(
                            "operation_id was already used with a different resolution",
                            details={
                                "operation_id": operation_id,
                                "intent_id": by_op.intent_id,
                                "event_id": event_id,
                            },
                        ) from None
                    return self._record_from_row(by_op)
            raced = await session.scalar(
                select(orm.GraphResumeIntent).where(
                    orm.GraphResumeIntent.event_id == event_id,
                    orm.GraphResumeIntent.hold_generation == generation,
                    orm.GraphResumeIntent.status.in_(
                        [status.value for status in ACTIVE_GRAPH_RESUME_STATUSES]
                    ),
                )
            )
            if raced is None:
                raise ValidationError(
                    "failed to locate graph resume intent after nested race",
                    details={"event_id": event_id, "hold_generation": generation},
                ) from None
            return self._record_from_row(raced)
        return self._record_from_row(row)

    async def _lookup_resume_intent_after_race(
        self,
        event_id: str,
        *,
        operation_id: str | None,
        hold_generation: int | None,
    ) -> GraphResumeIntentRecord:
        async with self._session_factory() as session:
            if operation_id is not None:
                by_op = await session.scalar(
                    select(orm.GraphResumeIntent).where(
                        orm.GraphResumeIntent.operation_id == operation_id
                    )
                )
                if by_op is not None:
                    return self._record_from_row(by_op)
            hold = await self._read_manual_hold(session, event_id)
            generation = (
                hold_generation
                if hold_generation is not None
                else (hold.generation if hold else None)
            )
            if generation is None:
                raise ValidationError(
                    "failed to locate graph resume intent after race",
                    details={"event_id": event_id},
                )
            active = await session.scalar(
                select(orm.GraphResumeIntent).where(
                    orm.GraphResumeIntent.event_id == event_id,
                    orm.GraphResumeIntent.hold_generation == generation,
                    orm.GraphResumeIntent.status.in_(
                        [status.value for status in ACTIVE_GRAPH_RESUME_STATUSES]
                    ),
                )
            )
            if active is None:
                raise ValidationError(
                    "failed to locate graph resume intent after race",
                    details={"event_id": event_id, "hold_generation": generation},
                )
            return self._record_from_row(active)

    def schedule_dispatch(
        self,
        *,
        event_id: str | None = None,
        intent_id: str | None = None,
        trigger: str = "unspecified",
        event_ids: list[str] | None = None,
        countdown_s: int = 0,
    ) -> None:
        """Best-effort durable dispatch; never raises.

        Prefer Celery (survives process kill via beat reclaim). Fall back to an
        in-process task when Celery is unavailable so local/background mode still
        progresses. When no running event loop exists, emit structured signals
        instead of silently returning (ISSUE-324).

        *countdown_s* delays the enqueue so nested RETRY respects
        ``nested_retry_backoff_s`` instead of no-op claiming during backoff.
        """
        flagged_event_ids: list[str] = []
        if event_id:
            flagged_event_ids.append(event_id)
        if event_ids:
            for eid in event_ids:
                if eid and eid not in flagged_event_ids:
                    flagged_event_ids.append(eid)

        delay = max(0, int(countdown_s or 0))

        try:
            from app.core.config import TaskMode, get_settings

            if get_settings().task_mode is TaskMode.CELERY:
                from app.tasks.graph_resume_intent_tasks import (
                    dispatch_pending_graph_resume_intents,
                )

                if delay > 0:
                    dispatch_pending_graph_resume_intents.apply_async(countdown=delay)
                else:
                    dispatch_pending_graph_resume_intents.delay()
                record_dispatch_schedule(domain="graph_resume", outcome="resume_scheduled")
                logger.debug(
                    "graph resume dispatch enqueued trigger=%s event_id=%s intent_id=%s delay=%ss",
                    trigger,
                    event_id or "-",
                    intent_id or "-",
                    delay,
                )
                return
        except Exception as exc:
            record_dispatch_schedule(domain="graph_resume", outcome="resume_enqueue_failed")
            logger.warning(
                "graph resume dispatch enqueue failed trigger=%s event_id=%s intent_id=%s error=%s",
                trigger,
                event_id or "-",
                intent_id or "-",
                type(exc).__name__,
            )

        if delay > 0:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None:

                def _dispatch_later() -> None:
                    self.schedule_dispatch(
                        event_id=event_id,
                        intent_id=intent_id,
                        trigger=trigger,
                        event_ids=event_ids,
                        countdown_s=0,
                    )

                loop.call_later(delay, _dispatch_later)
                record_dispatch_schedule(domain="graph_resume", outcome="resume_scheduled")
                logger.debug(
                    "graph resume dispatch delayed trigger=%s event_id=%s intent_id=%s delay=%ss",
                    trigger,
                    event_id or "-",
                    intent_id or "-",
                    delay,
                )
                return

        job = (intent_id, event_id, trigger, tuple(flagged_event_ids))
        if self._dispatch_scheduled:
            self._pending_in_process.append(job)
            record_dispatch_schedule(
                domain="graph_resume",
                outcome="resume_schedule_coalesced",
            )
            logger.info(
                "graph resume in-process dispatch coalesced trigger=%s event_id=%s intent_id=%s",
                trigger,
                event_id or "-",
                intent_id or "-",
            )
            return
        self._dispatch_scheduled = True

        async def _execute_one(
            current_intent_id: str | None,
            current_event_id: str | None,
            current_trigger: str,
            current_flags: tuple[str, ...],
        ) -> None:
            try:
                if current_intent_id is not None:
                    ran = int(await self.claim_and_run_intent(current_intent_id))
                else:
                    ran = await self.claim_and_run_batch(limit=20)
                if ran > 0:
                    record_dispatch_schedule(domain="graph_resume", outcome="resume_scheduled")
                else:
                    record_dispatch_schedule(
                        domain="graph_resume",
                        outcome="resume_in_process_empty",
                    )
                logger.info(
                    "graph resume in-process dispatch trigger=%s event_id=%s intent_id=%s ran=%s",
                    current_trigger,
                    current_event_id or "-",
                    current_intent_id or "-",
                    ran,
                )
            except Exception:
                logger.exception(
                    "graph resume in-process dispatch failed trigger=%s event_id=%s intent_id=%s",
                    current_trigger,
                    current_event_id or "-",
                    current_intent_id or "-",
                )
                for eid in current_flags:
                    await self._set_resume_dispatch_degraded_flag(eid, trigger=current_trigger)

        async def _run() -> None:
            pending = [job]
            try:
                while pending:
                    (
                        current_intent_id,
                        current_event_id,
                        current_trigger,
                        current_flags,
                    ) = pending.pop(0)
                    await _execute_one(
                        current_intent_id,
                        current_event_id,
                        current_trigger,
                        current_flags,
                    )
                    pending.extend(self._pending_in_process)
                    self._pending_in_process.clear()
            finally:
                leftover = list(self._pending_in_process)
                self._pending_in_process.clear()
                self._dispatch_scheduled = False
                for (
                    leftover_intent_id,
                    leftover_event_id,
                    leftover_trigger,
                    leftover_flags,
                ) in leftover:
                    self.schedule_dispatch(
                        event_id=leftover_event_id,
                        intent_id=leftover_intent_id,
                        trigger=leftover_trigger,
                        event_ids=list(leftover_flags),
                    )

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._dispatch_scheduled = False
            record_dispatch_schedule(
                domain="graph_resume",
                outcome="resume_schedule_skipped_no_loop",
            )
            logger.warning(
                "graph resume dispatch skipped: no running event loop trigger=%s "
                "event_id=%s intent_id=%s",
                trigger,
                event_id or "-",
                intent_id or "-",
            )
            for eid in flagged_event_ids:
                self._schedule_resume_dispatch_degraded_flag(eid, trigger=trigger)
            return
        loop.create_task(_run())

    async def _set_resume_dispatch_degraded_flag(self, event_id: str, *, trigger: str) -> None:
        """Persist graph_resume_dispatch_unavailable for a failed/unavailable resume dispatch."""
        degraded = self._degraded
        if degraded is None:
            return
        try:
            await degraded.set_flag(
                event_id,
                "graph_resume_dispatch_unavailable",
                trigger,
                writer="ManualResolutionService",
            )
        except Exception:
            logger.warning(
                "failed to set graph_resume_dispatch_unavailable event=%s trigger=%s",
                event_id,
                trigger,
                exc_info=True,
            )

    def _schedule_resume_dispatch_degraded_flag(self, event_id: str, *, trigger: str) -> None:
        """Persist graph_resume_dispatch_unavailable even when called without a loop."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # This helper is primarily invoked from the no-loop schedule path.
            try:
                asyncio.run(self._set_resume_dispatch_degraded_flag(event_id, trigger=trigger))
            except Exception:
                logger.warning(
                    "failed to set graph_resume_dispatch_unavailable event=%s trigger=%s",
                    event_id,
                    trigger,
                    exc_info=True,
                )
            return
        loop.create_task(self._set_resume_dispatch_degraded_flag(event_id, trigger=trigger))

    async def has_schedulable_intent(self, event_id: str) -> bool:
        """True when event has PENDING/RETRY/CLAIMED/STARTED resume intent."""
        async with self._session_factory() as session:
            row = await session.scalar(
                select(orm.GraphResumeIntent.intent_id)
                .where(
                    orm.GraphResumeIntent.event_id == event_id,
                    orm.GraphResumeIntent.status.in_(
                        [status.value for status in ACTIVE_GRAPH_RESUME_STATUSES]
                    ),
                )
                .limit(1)
            )
            return row is not None

    async def claim_and_run_batch(self, *, limit: int = 20) -> int:
        claimed = await self._claim_batch(limit=limit)
        ran = 0
        for claimed_id in claimed:
            if await self._run_claimed_intent(claimed_id):
                ran += 1
        return ran

    async def claim_and_run_intent(self, intent_id: str) -> bool:
        """Claim and run one specific resume intent (ISSUE-324 in-process fallback)."""
        claimed = await self._claim_intent(intent_id)
        if claimed is None:
            return False
        return await self._run_claimed_intent(claimed)

    async def reconcile_stale(self, *, limit: int = 100) -> int:
        now = datetime.now(UTC)
        stale_cutoff = now - timedelta(seconds=_STARTED_STALE_MIN_S)
        changed = 0
        changed_event_ids: list[str] = []
        async with self._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.scalars(
                        select(orm.GraphResumeIntent)
                        .where(
                            orm.GraphResumeIntent.status.in_(
                                [
                                    GraphResumeIntentStatus.CLAIMED.value,
                                    GraphResumeIntentStatus.STARTED.value,
                                    GraphResumeIntentStatus.PENDING.value,
                                ]
                            )
                        )
                        .order_by(orm.GraphResumeIntent.updated_at.asc())
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                for row in rows:
                    status = GraphResumeIntentStatus(row.status)
                    # PENDING rows are drained by claim_and_run_batch (dispatch /
                    # reconcile wrappers). This loop only fences expired claims.
                    if status is GraphResumeIntentStatus.PENDING:
                        continue
                    expired_claim = row.claim_expires_at is not None and row.claim_expires_at <= now
                    stale_started = (
                        status is GraphResumeIntentStatus.STARTED
                        and row.updated_at.replace(tzinfo=UTC) <= stale_cutoff
                    )
                    if not (expired_claim or stale_started):
                        continue
                    if int(row.attempt or 0) + 1 >= self._max_attempts:
                        validate_graph_resume_transition(status, GraphResumeIntentStatus.DEAD)
                        row.status = GraphResumeIntentStatus.DEAD.value
                        row.last_error = "reconcile_exhausted"
                    else:
                        validate_graph_resume_transition(status, GraphResumeIntentStatus.RETRY)
                        row.status = GraphResumeIntentStatus.RETRY.value
                        row.attempt = int(row.attempt or 0) + 1
                        row.revision = int(row.revision or 1) + 1
                        row.last_error = "reconcile_stale"
                    row.claim_owner = None
                    row.claim_expires_at = None
                    row.updated_at = now
                    changed += 1
                    if row.event_id not in changed_event_ids:
                        changed_event_ids.append(row.event_id)
        if changed:
            self.schedule_dispatch(
                event_ids=changed_event_ids,
                trigger="reconcile_stale",
            )
        return changed

    async def _claim_batch(self, *, limit: int) -> list[str]:
        now = datetime.now(UTC)
        lease_until = now + timedelta(seconds=self._claim_lease_s)
        claimed: list[str] = []
        async with self._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.scalars(
                        select(orm.GraphResumeIntent)
                        .where(
                            or_(
                                orm.GraphResumeIntent.status
                                == GraphResumeIntentStatus.PENDING.value,
                                and_(
                                    orm.GraphResumeIntent.status
                                    == GraphResumeIntentStatus.RETRY.value,
                                    or_(
                                        orm.GraphResumeIntent.intent_kind
                                        != INTENT_KIND_NESTED_GRAPH_WAKEUP,
                                        orm.GraphResumeIntent.updated_at
                                        <= now
                                        - timedelta(seconds=self._nested_retry_backoff_s),
                                    ),
                                ),
                            )
                        )
                        .order_by(orm.GraphResumeIntent.updated_at.asc())
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                for row in rows:
                    current = GraphResumeIntentStatus(row.status)
                    validate_graph_resume_transition(current, GraphResumeIntentStatus.CLAIMED)
                    row.status = GraphResumeIntentStatus.CLAIMED.value
                    row.claim_owner = _DISPATCH_WORKER_ID
                    row.claim_expires_at = lease_until
                    row.updated_at = now
                    claimed.append(row.intent_id)
        return claimed

    async def _claim_intent(self, intent_id: str) -> str | None:
        """Claim a single PENDING/RETRY resume intent by id."""
        now = datetime.now(UTC)
        lease_until = now + timedelta(seconds=self._claim_lease_s)
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.GraphResumeIntent,
                    intent_id,
                    with_for_update=True,
                )
                if row is None:
                    return None
                current = GraphResumeIntentStatus(row.status)
                if current not in {
                    GraphResumeIntentStatus.PENDING,
                    GraphResumeIntentStatus.RETRY,
                }:
                    return None
                if not self._nested_retry_ready(row, now):
                    return None
                validate_graph_resume_transition(current, GraphResumeIntentStatus.CLAIMED)
                row.status = GraphResumeIntentStatus.CLAIMED.value
                row.claim_owner = _DISPATCH_WORKER_ID
                row.claim_expires_at = lease_until
                row.updated_at = now
                return row.intent_id

    async def _run_claimed_intent(self, intent_id: str) -> bool:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.GraphResumeIntent,
                    intent_id,
                    with_for_update=True,
                )
                if row is None:
                    return False
                if GraphResumeIntentStatus(row.status) is not GraphResumeIntentStatus.CLAIMED:
                    return False
                kind = str(row.intent_kind)
                if kind == INTENT_KIND_NESTED_GRAPH_WAKEUP:
                    validate_graph_resume_transition(
                        GraphResumeIntentStatus.CLAIMED,
                        GraphResumeIntentStatus.STARTED,
                    )
                    row.status = GraphResumeIntentStatus.STARTED.value
                    row.updated_at = datetime.now(UTC)
                    event_id = row.event_id
                else:
                    hold = await self._read_manual_hold(session, row.event_id)
                    if hold is None or hold.generation != int(row.hold_generation):
                        validate_graph_resume_transition(
                            GraphResumeIntentStatus.CLAIMED,
                            GraphResumeIntentStatus.SKIPPED,
                        )
                        row.status = GraphResumeIntentStatus.SKIPPED.value
                        row.skip_reason = "stale_hold_generation"
                        row.claim_owner = None
                        row.claim_expires_at = None
                        return False
                    substate = await self._read_execution_substate(session, row.event_id)
                    if substate is not ExecutionSubstate.MANUAL_RESOLUTION:
                        validate_graph_resume_transition(
                            GraphResumeIntentStatus.CLAIMED,
                            GraphResumeIntentStatus.SKIPPED,
                        )
                        row.status = GraphResumeIntentStatus.SKIPPED.value
                        row.skip_reason = "hold_already_cleared"
                        row.claim_owner = None
                        row.claim_expires_at = None
                        return False
                    validate_graph_resume_transition(
                        GraphResumeIntentStatus.CLAIMED,
                        GraphResumeIntentStatus.STARTED,
                    )
                    row.status = GraphResumeIntentStatus.STARTED.value
                    row.updated_at = datetime.now(UTC)
                    event_id = row.event_id
                    generation = int(row.hold_generation)

        try:
            if self._resume_runner is None:
                raise RuntimeError("resume_runner is not bound")
            if kind == INTENT_KIND_NESTED_GRAPH_WAKEUP:
                if await self._nested_wakeup_blocked_by_manual_hold(event_id):
                    logger.warning(
                        "nested graph wakeup deferred: manual hold active "
                        "intent=%s event=%s",
                        intent_id,
                        event_id,
                    )
                    await self._mark_deferred(intent_id, error="manual_resolution_hold")
                    return False
                await self._resume_runner(event_id)
                if await self._nested_wakeup_still_waiting(event_id):
                    logger.warning(
                        "nested graph wakeup made no progress intent=%s event=%s",
                        intent_id,
                        event_id,
                    )
                    await self._mark_deferred(
                        intent_id,
                        error="nested_wakeup_still_waiting",
                    )
                    return False
                await self._mark_terminal(intent_id)
                return True
            # Keep MANUAL_RESOLUTION until resume succeeds so a crash mid-run
            # remains reclaimable (clearing first would fence as hold_already_cleared).
            await self._resume_runner(event_id)
        except Exception as exc:
            from app.orchestration.graph_resume_observability import GraphResumeDeferredError

            if isinstance(exc, GraphResumeDeferredError):
                logger.warning(
                    "graph resume intent deferred intent=%s event=%s error_type=%s",
                    intent_id,
                    event_id,
                    exc.error_type,
                )
                await self._mark_deferred(intent_id, error=str(exc))
                return False
            logger.exception("graph resume intent failed intent=%s event=%s", intent_id, event_id)
            await self._mark_failure(intent_id, error=str(exc))
            return False

        try:
            await self._clear_manual_resolution_for_resume(event_id, generation)
        except ValidationError:
            # Resume path may have cleared substate or re-armed a newer hold.
            logger.info(
                "post-resume hold clear skipped intent=%s event=%s generation=%s",
                intent_id,
                event_id,
                generation,
            )
        await self._mark_terminal(intent_id)
        return True

    async def _clear_manual_resolution_for_resume(
        self,
        event_id: str,
        expected_generation: int,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                event = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
                if event is None:
                    raise ValidationError(
                        "event missing during resume clear",
                        details={"event_id": event_id},
                    )
                hold = await self._read_manual_hold(session, event_id)
                if hold is None or hold.generation != expected_generation:
                    raise ValidationError(
                        "hold generation changed before resume",
                        details={
                            "event_id": event_id,
                            "expected_generation": expected_generation,
                            "actual_generation": None if hold is None else hold.generation,
                        },
                    )
                authoritative = EventStatus(event.status)
        if self._runtime is not None:
            await self._runtime.set_execution_substate(
                event_id,
                ExecutionSubstate.NONE,
                event_status=authoritative,
            )
        else:
            await self._set_execution_substate_direct(
                event_id,
                ExecutionSubstate.NONE,
                event_status=authoritative,
            )

    async def _mark_terminal(self, intent_id: str) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.GraphResumeIntent, intent_id, with_for_update=True)
                if row is None:
                    return
                current = GraphResumeIntentStatus(row.status)
                if current in TERMINAL_GRAPH_RESUME_STATUSES:
                    return
                validate_graph_resume_transition(current, GraphResumeIntentStatus.TERMINAL)
                row.status = GraphResumeIntentStatus.TERMINAL.value
                row.claim_owner = None
                row.claim_expires_at = None
                row.updated_at = datetime.now(UTC)

    async def _mark_deferred(self, intent_id: str, *, error: str) -> None:
        """Return the intent to RETRY without burning the DEAD attempt budget."""
        event_id: str | None = None
        intent_kind: str | None = None
        marked = False
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.GraphResumeIntent, intent_id, with_for_update=True)
                if row is None:
                    return
                current = GraphResumeIntentStatus(row.status)
                if current in TERMINAL_GRAPH_RESUME_STATUSES:
                    return
                validate_graph_resume_transition(current, GraphResumeIntentStatus.RETRY)
                row.status = GraphResumeIntentStatus.RETRY.value
                row.revision = int(row.revision or 1) + 1
                row.last_error = error[:2000]
                row.claim_owner = None
                row.claim_expires_at = None
                row.updated_at = datetime.now(UTC)
                event_id = row.event_id
                intent_kind = str(row.intent_kind)
                marked = True
        if marked and event_id is not None and intent_kind == INTENT_KIND_NESTED_GRAPH_WAKEUP:
            self.schedule_dispatch(
                event_id=event_id,
                intent_id=intent_id,
                trigger="nested_wakeup_deferred",
                countdown_s=self._nested_retry_backoff_s,
            )

    async def _mark_failure(self, intent_id: str, *, error: str) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.GraphResumeIntent, intent_id, with_for_update=True)
                if row is None:
                    return
                current = GraphResumeIntentStatus(row.status)
                if current in TERMINAL_GRAPH_RESUME_STATUSES:
                    return
                attempt = int(row.attempt or 0) + 1
                if attempt >= self._max_attempts:
                    validate_graph_resume_transition(current, GraphResumeIntentStatus.DEAD)
                    row.status = GraphResumeIntentStatus.DEAD.value
                else:
                    validate_graph_resume_transition(current, GraphResumeIntentStatus.RETRY)
                    row.status = GraphResumeIntentStatus.RETRY.value
                    row.revision = int(row.revision or 1) + 1
                row.attempt = attempt
                row.last_error = error[:2000]
                row.claim_owner = None
                row.claim_expires_at = None
                row.updated_at = datetime.now(UTC)

    async def _set_execution_substate_direct(
        self,
        event_id: str,
        substate: ExecutionSubstate,
        *,
        event_status: EventStatus,
    ) -> None:
        from app.models.workflow import validate_execution_substate

        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
                if row is None:
                    raise ValidationError(
                        "security_event not found",
                        details={"event_id": event_id},
                    )
                authoritative = EventStatus(row.status)
                if authoritative is not event_status:
                    raise ValidationError(
                        "caller EventStatus does not match authoritative state",
                        details={
                            "event_id": event_id,
                            "caller_status": event_status.value,
                            "authoritative_status": authoritative.value,
                        },
                    )
                current = await self._read_execution_substate(session, event_id)
                validate_execution_substate(authoritative, current, substate)
                if current is not substate:
                    await append_context_journal_in_session(
                        session,
                        event_id,
                        "execution_substate",
                        substate.value,
                    )

    async def _read_execution_substate(
        self,
        session: AsyncSession,
        event_id: str,
    ) -> ExecutionSubstate:
        raw = await session.scalar(
            select(orm.EventContextJournal.value)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "execution_substate",
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        value = unwrap_journal_value(raw)
        try:
            return ExecutionSubstate(str(value or ExecutionSubstate.NONE.value))
        except ValueError:
            return ExecutionSubstate.NONE

    async def _read_manual_hold(
        self,
        session: AsyncSession,
        event_id: str,
    ) -> ManualHoldSnapshot | None:
        raw = await session.scalar(
            select(orm.EventContextJournal.value)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == MANUAL_HOLD_JOURNAL_FIELD,
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        return parse_manual_hold_snapshot(unwrap_journal_value(raw))

    @staticmethod
    def _record_from_row(row: orm.GraphResumeIntent) -> GraphResumeIntentRecord:
        return GraphResumeIntentRecord(
            intent_id=row.intent_id,
            event_id=row.event_id,
            intent_kind=row.intent_kind,
            intent_version=row.intent_version,
            status=GraphResumeIntentStatus(row.status),
            revision=int(row.revision or 1),
            attempt=int(row.attempt or 0),
            hold_generation=int(row.hold_generation),
            checkpoint_id=row.checkpoint_id,
            operation_id=row.operation_id,
            resolution_source=row.resolution_source,
            subject_kind=row.subject_kind,
            subject_id=row.subject_id,
            resolution=row.resolution,
            principal=row.principal,
            skip_reason=row.skip_reason,
            last_error=row.last_error,
        )


__all__ = [
    "ManualResolutionService",
    "RESOLUTION_SOURCE_ACTION_UNKNOWN",
    "RESOLUTION_SOURCE_NESTED_WAKEUP",
    "RESOLUTION_SOURCE_WRITEBACK_AUTO",
    "RESOLUTION_SOURCE_WRITEBACK_MANUAL",
    "SUBJECT_KIND_ACTION",
    "SUBJECT_KIND_EVENT",
    "SUBJECT_KIND_WRITEBACK",
    "new_graph_resume_intent_id",
    "resolution_payload_sha256",
]
