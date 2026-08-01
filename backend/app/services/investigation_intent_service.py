"""PostgreSQL durable auto-investigate intent dispatcher (ISSUE-108 / #612)."""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Sequence

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.db import models as orm
from app.models.enums import EventStatus, InvestigationIntentStatus
from app.models.investigation_intent import (
    INTENT_KIND_AUTO_INVESTIGATE,
    INTENT_VERSION_ISSUE108_V1,
    TERMINAL_INTENT_STATUSES,
    validate_intent_transition,
)
from app.services.auto_investigate_policy import AutoInvestigatePolicyService
from app.services.degraded_flag_service import DegradedFlagService

logger = logging.getLogger(__name__)

_DISPATCH_WORKER_ID = "intent-dispatcher-1"

# Event left NEW while intent is STARTED beyond this window → worker crash / retry.
_STARTED_STALE_MIN_S = 660

_EVENT_INVESTIGATION_UNDERWAY = frozenset(
    {
        EventStatus.TRIAGING.value,
        EventStatus.COLLECTING_EVIDENCE.value,
        EventStatus.ANALYZING.value,
        EventStatus.SCORING.value,
        EventStatus.PLANNING_RESPONSE.value,
        EventStatus.WAITING_APPROVAL.value,
        EventStatus.EXECUTING_RESPONSE.value,
        EventStatus.VERIFYING.value,
        EventStatus.REPLANNING.value,
        EventStatus.CONTAINED.value,
        EventStatus.REPORTING.value,
        EventStatus.CLOSED.value,
    }
)


def new_intent_id() -> str:
    return f"iin-{secrets.token_hex(8)}"


def deterministic_investigation_task_id(intent_id: str, revision: int) -> str:
    """Stable Celery task id derived from intent identity (#612)."""
    return hashlib.sha256(f"{intent_id}:{revision}".encode("utf-8")).hexdigest()


class InvestigationIntentService:
    """Owns investigation_intent rows and broker dispatch bookkeeping."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        policy: AutoInvestigatePolicyService | None = None,
        degraded_flags: DegradedFlagService | None = None,
        settings: Settings | None = None,
        worker_id: str = _DISPATCH_WORKER_ID,
    ) -> None:
        self._session_factory = session_factory
        self._policy = policy or AutoInvestigatePolicyService(settings)
        self._degraded = degraded_flags
        self._settings = settings or get_settings()
        self._worker_id = worker_id

    @property
    def policy(self) -> AutoInvestigatePolicyService:
        return self._policy

    async def maybe_create_pending_in_session(
        self,
        session: AsyncSession,
        event: orm.SecurityEvent,
        *,
        link_role: str,
        source_product: str | None,
        created_or_promoted: bool,
    ) -> str | None:
        """Insert a pending intent in the same transaction as event create/promote."""
        if not created_or_promoted or not self._policy.enabled:
            return None
        decision = self._policy.evaluate(
            event,
            link_role=link_role,
            source_product=source_product,
        )
        if not decision.eligible:
            return None
        existing = await session.scalar(
            select(orm.InvestigationIntent.intent_id).where(
                orm.InvestigationIntent.event_id == event.event_id,
                orm.InvestigationIntent.intent_kind == INTENT_KIND_AUTO_INVESTIGATE,
                orm.InvestigationIntent.intent_version == INTENT_VERSION_ISSUE108_V1,
            )
        )
        if existing is not None:
            return None
        intent_id = new_intent_id()
        row = orm.InvestigationIntent(
            intent_id=intent_id,
            event_id=event.event_id,
            intent_kind=INTENT_KIND_AUTO_INVESTIGATE,
            intent_version=INTENT_VERSION_ISSUE108_V1,
            status=InvestigationIntentStatus.PENDING.value,
            revision=1,
            attempt=0,
            include_response_execution=False,
        )
        session.add(row)
        session.add(
            orm.EventAuditLog(
                event_id=event.event_id,
                from_status=event.status,
                to_status=event.status,
                operator="AutoInvestigatePolicyService",
                reason=decision.reason,
            )
        )
        try:
            await session.flush()
        except IntegrityError:
            logger.info(
                "investigation intent already exists event=%s kind=%s",
                event.event_id,
                INTENT_KIND_AUTO_INVESTIGATE,
            )
            return None
        return intent_id

    def schedule_dispatch(self, intent_ids: Sequence[str]) -> None:
        """Best-effort async dispatch trigger; must never raise to ingest callers."""
        if not intent_ids or not self._policy.enabled:
            return
        try:
            from app.tasks.investigation_intent_tasks import dispatch_pending_investigation_intents

            dispatch_pending_investigation_intents.delay()
        except Exception:
            logger.warning(
                "failed to enqueue investigation intent dispatch count=%d",
                len(intent_ids),
                exc_info=True,
            )

    async def claim_and_publish_batch(self, *, limit: int = 10) -> int:
        claimed = await self._claim_batch(limit=limit)
        published = 0
        for intent_id in claimed:
            if await self._publish_claimed_intent(intent_id):
                published += 1
        return published

    async def mark_started(self, intent_id: str, *, broker_task_id: str) -> None:
        """ENQUEUED→STARTED on first delivery; idempotent for Celery retries/redelivery."""
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.InvestigationIntent, intent_id)
                if row is None:
                    return
                current = InvestigationIntentStatus(row.status)
                if current in TERMINAL_INTENT_STATUSES:
                    return
                if current is InvestigationIntentStatus.STARTED:
                    if row.broker_task_id == broker_task_id:
                        return
                    expected = deterministic_investigation_task_id(
                        row.intent_id,
                        int(row.revision or 1),
                    )
                    if broker_task_id == expected:
                        row.broker_task_id = broker_task_id
                        return
                    logger.warning(
                        "investigation intent already started intent=%s existing_task=%s new_task=%s",
                        intent_id,
                        row.broker_task_id,
                        broker_task_id,
                    )
                    return
                if (
                    current is InvestigationIntentStatus.ENQUEUED
                    and row.broker_task_id
                    and row.broker_task_id != broker_task_id
                ):
                    logger.warning(
                        "stale broker task ignored intent=%s expected=%s got=%s",
                        intent_id,
                        row.broker_task_id,
                        broker_task_id,
                    )
                    return
                validate_intent_transition(current, InvestigationIntentStatus.STARTED)
                row.status = InvestigationIntentStatus.STARTED.value
                row.broker_task_id = broker_task_id
                row.claim_owner = None
                row.claim_expires_at = None

    async def mark_terminal(self, intent_id: str) -> None:
        await self._transition(intent_id, InvestigationIntentStatus.TERMINAL, clear_claim=True)

    async def mark_skipped(self, intent_id: str, *, reason: str) -> None:
        await self._transition(
            intent_id,
            InvestigationIntentStatus.SKIPPED,
            skip_reason=reason,
            clear_claim=True,
        )

    async def mark_retry(self, intent_id: str, *, error: str) -> None:
        await self._transition(
            intent_id,
            InvestigationIntentStatus.RETRY,
            last_error=error,
            increment_attempt=True,
            clear_claim=True,
        )

    async def mark_dead(self, intent_id: str, *, error: str) -> None:
        await self._transition(
            intent_id,
            InvestigationIntentStatus.DEAD,
            last_error=error,
            clear_claim=True,
        )

    async def reconcile_stale(self, *, limit: int = 20) -> int:
        now = datetime.now(UTC)
        lease_seconds = int(self._settings.auto_investigate_claim_lease_s)
        max_attempts = int(self._settings.auto_investigate_max_attempts)
        started_stale_s = max(lease_seconds * 4, _STARTED_STALE_MIN_S)
        reconciled = 0
        async with self._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.scalars(
                        select(orm.InvestigationIntent)
                        .where(
                            orm.InvestigationIntent.status.in_(
                                (
                                    InvestigationIntentStatus.CLAIMED.value,
                                    InvestigationIntentStatus.ENQUEUED.value,
                                    InvestigationIntentStatus.STARTED.value,
                                )
                            )
                        )
                        .order_by(orm.InvestigationIntent.updated_at.asc())
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                for row in rows:
                    status = InvestigationIntentStatus(row.status)
                    if not self._is_stale_intent_row(
                        row,
                        status=status,
                        now=now,
                        lease_seconds=lease_seconds,
                        started_stale_s=started_stale_s,
                    ):
                        continue
                    event = await session.get(orm.SecurityEvent, row.event_id)
                    if await self._reconcile_stale_row(
                        row,
                        status=status,
                        event=event,
                        max_attempts=max_attempts,
                    ):
                        reconciled += 1
        if reconciled:
            self.schedule_dispatch([])
        provisional_created = await self._materialize_provisional_intents(
            limit=int(self._settings.auto_investigate_materialize_batch_size)
        )
        return reconciled + provisional_created

    def _is_stale_intent_row(
        self,
        row: orm.InvestigationIntent,
        *,
        status: InvestigationIntentStatus,
        now: datetime,
        lease_seconds: int,
        started_stale_s: int,
    ) -> bool:
        if row.claim_expires_at is not None and row.claim_expires_at < now:
            return True
        if status is InvestigationIntentStatus.ENQUEUED:
            return (now - row.updated_at) > timedelta(seconds=lease_seconds * 4)
        if status is InvestigationIntentStatus.STARTED:
            return (now - row.updated_at) > timedelta(seconds=started_stale_s)
        return False

    async def _reconcile_stale_row(
        self,
        row: orm.InvestigationIntent,
        *,
        status: InvestigationIntentStatus,
        event: orm.SecurityEvent | None,
        max_attempts: int,
    ) -> bool:
        if status is InvestigationIntentStatus.STARTED and event is not None:
            if event.status in _EVENT_INVESTIGATION_UNDERWAY:
                validate_intent_transition(status, InvestigationIntentStatus.TERMINAL)
                row.status = InvestigationIntentStatus.TERMINAL.value
                row.claim_owner = None
                row.claim_expires_at = None
                return True
            if event.status == EventStatus.FAILED.value:
                validate_intent_transition(status, InvestigationIntentStatus.SKIPPED)
                row.status = InvestigationIntentStatus.SKIPPED.value
                row.skip_reason = "event_failed"
                row.claim_owner = None
                row.claim_expires_at = None
                return True

        next_attempt = int(row.attempt or 0) + 1
        if next_attempt >= max_attempts:
            validate_intent_transition(status, InvestigationIntentStatus.DEAD)
            row.status = InvestigationIntentStatus.DEAD.value
            row.last_error = row.last_error or "max_attempts_exceeded"
        else:
            validate_intent_transition(status, InvestigationIntentStatus.RETRY)
            row.status = InvestigationIntentStatus.RETRY.value
            row.attempt = next_attempt
            row.last_error = row.last_error or "stale_intent_reconciled"
        row.broker_task_id = None
        row.claim_owner = None
        row.claim_expires_at = None
        row.revision = int(row.revision or 1) + 1
        return True

    async def lookup_by_broker_task_id(self, broker_task_id: str) -> orm.InvestigationIntent | None:
        async with self._session_factory() as session:
            return await session.scalar(
                select(orm.InvestigationIntent).where(
                    orm.InvestigationIntent.broker_task_id == broker_task_id
                )
            )

    async def lookup_active_for_event(self, event_id: str) -> orm.InvestigationIntent | None:
        async with self._session_factory() as session:
            return await session.scalar(
                select(orm.InvestigationIntent)
                .where(
                    orm.InvestigationIntent.event_id == event_id,
                    orm.InvestigationIntent.intent_kind == INTENT_KIND_AUTO_INVESTIGATE,
                    orm.InvestigationIntent.intent_version == INTENT_VERSION_ISSUE108_V1,
                )
                .order_by(orm.InvestigationIntent.created_at.desc())
            )

    async def _claim_batch(self, *, limit: int) -> list[str]:
        now = datetime.now(UTC)
        lease = timedelta(seconds=int(self._settings.auto_investigate_claim_lease_s))
        claimed: list[str] = []
        async with self._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.scalars(
                        select(orm.InvestigationIntent)
                        .where(
                            or_(
                                orm.InvestigationIntent.status.in_(
                                    (
                                        InvestigationIntentStatus.PENDING.value,
                                        InvestigationIntentStatus.RETRY.value,
                                    )
                                ),
                                and_(
                                    orm.InvestigationIntent.status
                                    == InvestigationIntentStatus.CLAIMED.value,
                                    orm.InvestigationIntent.claim_expires_at.is_not(None),
                                    orm.InvestigationIntent.claim_expires_at < now,
                                ),
                            )
                        )
                        .order_by(orm.InvestigationIntent.created_at.asc())
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                for row in rows:
                    current = InvestigationIntentStatus(row.status)
                    if (
                        current is InvestigationIntentStatus.CLAIMED
                        and row.claim_expires_at is not None
                        and row.claim_expires_at < now
                    ):
                        validate_intent_transition(current, InvestigationIntentStatus.RETRY)
                        row.status = InvestigationIntentStatus.RETRY.value
                        row.attempt = int(row.attempt or 0) + 1
                        current = InvestigationIntentStatus.RETRY
                    validate_intent_transition(current, InvestigationIntentStatus.CLAIMED)
                    row.status = InvestigationIntentStatus.CLAIMED.value
                    row.claim_owner = self._worker_id
                    row.claim_expires_at = now + lease
                    claimed.append(row.intent_id)
        return claimed

    async def _publish_claimed_intent(self, intent_id: str) -> bool:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.InvestigationIntent, intent_id)
                if row is None:
                    return False
                if InvestigationIntentStatus(row.status) is not InvestigationIntentStatus.CLAIMED:
                    return False
                event = await session.get(orm.SecurityEvent, row.event_id)
                if event is None:
                    await self._set_status_in_session(
                        row,
                        InvestigationIntentStatus.SKIPPED,
                        skip_reason="event_missing",
                    )
                    return False
                if event.status != EventStatus.NEW.value:
                    await self._set_status_in_session(
                        row,
                        InvestigationIntentStatus.SKIPPED,
                        skip_reason="event_not_new",
                    )
                    return False
                task_id = deterministic_investigation_task_id(row.intent_id, int(row.revision))
                from app.tasks.investigation_tasks import (
                    delete_task_metadata,
                    publish_investigation_for_intent,
                    register_task_metadata,
                )

                try:
                    await register_task_metadata(task_id, row.event_id)
                    publish_investigation_for_intent(
                        event_id=row.event_id,
                        task_id=task_id,
                        intent_id=row.intent_id,
                    )
                except Exception as exc:
                    await delete_task_metadata(task_id)
                    logger.warning(
                        "broker publish failed intent=%s event=%s err=%s",
                        row.intent_id,
                        row.event_id,
                        exc,
                        exc_info=True,
                    )
                    if int(row.attempt or 0) + 1 >= int(self._settings.auto_investigate_max_attempts):
                        await self._set_status_in_session(
                            row,
                            InvestigationIntentStatus.DEAD,
                            last_error=str(exc),
                        )
                    else:
                        await self._set_status_in_session(
                            row,
                            InvestigationIntentStatus.RETRY,
                            last_error=str(exc),
                            increment_attempt=True,
                        )
                    if self._degraded is not None:
                        await self._degraded.set_flag(
                            row.event_id,
                            "auto_investigate_dispatch_unavailable",
                            True,
                            writer="InvestigationIntentService",
                        )
                    return False
                validate_intent_transition(
                    InvestigationIntentStatus.CLAIMED,
                    InvestigationIntentStatus.ENQUEUED,
                )
                row.status = InvestigationIntentStatus.ENQUEUED.value
                row.broker_task_id = task_id
                row.claim_owner = None
                row.claim_expires_at = None
                row.last_error = None
                return True

    async def _transition(
        self,
        intent_id: str,
        target: InvestigationIntentStatus,
        *,
        broker_task_id: str | None = None,
        skip_reason: str | None = None,
        last_error: str | None = None,
        increment_attempt: bool = False,
        clear_claim: bool = False,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.InvestigationIntent, intent_id)
                if row is None:
                    return
                current = InvestigationIntentStatus(row.status)
                if current in TERMINAL_INTENT_STATUSES:
                    return
                validate_intent_transition(current, target)
                row.status = target.value
                if broker_task_id is not None:
                    row.broker_task_id = broker_task_id
                if skip_reason is not None:
                    row.skip_reason = skip_reason
                if last_error is not None:
                    row.last_error = last_error
                if increment_attempt:
                    row.attempt = int(row.attempt or 0) + 1
                    row.revision = int(row.revision or 1) + 1
                if clear_claim:
                    row.claim_owner = None
                    row.claim_expires_at = None

    async def _set_status_in_session(
        self,
        row: orm.InvestigationIntent,
        target: InvestigationIntentStatus,
        *,
        skip_reason: str | None = None,
        last_error: str | None = None,
        increment_attempt: bool = False,
    ) -> None:
        current = InvestigationIntentStatus(row.status)
        validate_intent_transition(current, target)
        row.status = target.value
        if skip_reason is not None:
            row.skip_reason = skip_reason
        if last_error is not None:
            row.last_error = last_error
        if increment_attempt:
            row.attempt = int(row.attempt or 0) + 1
            row.revision = int(row.revision or 1) + 1
        row.claim_owner = None
        row.claim_expires_at = None

    async def _materialize_provisional_intents(self, *, limit: int) -> int:
        if not self._policy.enabled:
            return 0
        window = timedelta(seconds=int(self._settings.auto_investigate_provisional_window_s))
        cutoff = datetime.now(UTC) - window
        intent_exists = (
            select(orm.InvestigationIntent.intent_id)
            .where(
                orm.InvestigationIntent.event_id == orm.SecurityEvent.event_id,
                orm.InvestigationIntent.intent_kind == INTENT_KIND_AUTO_INVESTIGATE,
                orm.InvestigationIntent.intent_version == INTENT_VERSION_ISSUE108_V1,
            )
            .exists()
        )
        created = 0
        async with self._session_factory() as session:
            async with session.begin():
                links = (
                    await session.scalars(
                        select(orm.SourceEventLink)
                        .join(
                            orm.SecurityEvent,
                            orm.SecurityEvent.event_id == orm.SourceEventLink.event_id,
                        )
                        .where(
                            orm.SourceEventLink.role == "provisional",
                            orm.SecurityEvent.status == EventStatus.NEW.value,
                            orm.SecurityEvent.created_at <= cutoff,
                            ~intent_exists,
                        )
                        .order_by(orm.SecurityEvent.created_at.asc())
                        .limit(limit)
                    )
                ).all()
                for link in links:
                    event = await session.get(orm.SecurityEvent, link.event_id)
                    if event is None:
                        continue
                    source_product = None
                    if event.creation_source_ref:
                        raw = event.creation_source_ref.get("source_product")
                        if isinstance(raw, str):
                            source_product = raw
                    intent_id = await self.maybe_create_pending_in_session(
                        session,
                        event,
                        link_role="primary",
                        source_product=source_product,
                        created_or_promoted=True,
                    )
                    if intent_id is not None:
                        created += 1
        if created:
            self.schedule_dispatch([])
        return created


__all__ = [
    "InvestigationIntentService",
    "deterministic_investigation_task_id",
    "new_intent_id",
]
