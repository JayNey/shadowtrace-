"""Soft Celery time-limit outcome ownership (ISSUE-314).

Task/intent layer is the single owner for soft-limit terminal vs bounded-recovery
decisions. SuperAgent must re-raise ``SoftTimeLimitExceeded`` without writing
``EventStatus.FAILED`` so event and intent outcomes stay atomic here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.metrics import record_soft_time_limit_outcome
from app.db import models as orm
from app.models.enums import (
    EventStatus,
    InvestigationIntentStatus,
    WritebackStatus,
)
from app.models.investigation_intent import (
    TERMINAL_INTENT_STATUSES,
    validate_intent_transition,
)
from app.models.workflow import validate_transition
from app.services.investigation_intent_service import deterministic_investigation_task_id
from app.services.state_machine_service import _build_authoritative_context

logger = logging.getLogger(__name__)

_SOFT_LIMIT_REASON = "soft_time_limit_exceeded"
_SOFT_LIMIT_OPERATOR = "InvestigationTask"

# Pure investigation phases — safe for one bounded checkpoint resume (no execute replay).
# REPORTING is intentionally excluded: dispatch resume set does not include it
# (investigation_intent_service._EVENT_INVESTIGATION_RESUMABLE), so RECOVERED would
# leave REPORTING + SKIPPED — a forbidden event/intent fork (ISSUE-314).
_PURE_INVESTIGATION_STATUSES = frozenset(
    {
        EventStatus.NEW.value,
        EventStatus.TRIAGING.value,
        EventStatus.COLLECTING_EVIDENCE.value,
        EventStatus.ANALYZING.value,
        EventStatus.SCORING.value,
    }
)

_EVENT_TERMINAL_STATUSES = frozenset(
    {
        EventStatus.FAILED.value,
        EventStatus.CLOSED.value,
        EventStatus.CONTAINED.value,
    }
)

# Successful / non-FAILED terminals — never rewrite to FAILED on late soft-limit.
_EVENT_SUCCESS_TERMINAL_STATUSES = frozenset(
    {
        EventStatus.CLOSED.value,
        EventStatus.CONTAINED.value,
    }
)

_SIDE_EFFECT_PHASE_STATUSES = frozenset(
    {
        EventStatus.PLANNING_RESPONSE.value,
        EventStatus.WAITING_APPROVAL.value,
        EventStatus.EXECUTING_RESPONSE.value,
        EventStatus.VERIFYING.value,
        EventStatus.REPLANNING.value,
    }
)


class SoftTimeLimitDecision(StrEnum):
    TERMINAL = "terminal"
    RECOVERED = "recovered"
    RECONCILE_REQUIRED = "reconcile_required"
    IGNORED = "ignored"


@dataclass(frozen=True)
class SoftTimeLimitProbe:
    has_checkpoint: bool
    checkpoint_recoverable: bool
    last_checkpoint_node: str | None
    side_effect_signals: tuple[str, ...]
    unknown_outbox_count: int


@dataclass(frozen=True)
class SoftTimeLimitOutcomeResult:
    decision: SoftTimeLimitDecision
    event_id: str
    intent_id: str | None
    event_status: str | None
    intent_status: str | None
    intent_error: str | None
    last_checkpoint_node: str | None
    reason: str = _SOFT_LIMIT_REASON


def _utc_now() -> datetime:
    return datetime.now(UTC)


async def _probe_unknown_outbox_count(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> int:
    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(orm.DispositionOutbox.latest_writeback_status).where(
                    orm.DispositionOutbox.event_id == event_id,
                    orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                )
            )
        ).all()
    return sum(1 for status in rows if status == WritebackStatus.UNKNOWN.value)


async def _probe_graph_checkpoint(event_id: str) -> tuple[bool, bool, str | None, list[str]]:
    """Return (has_checkpoint, recoverable, last_node, side_effect_signals)."""
    side_effect_signals: list[str] = []
    try:
        from app.api.v1.deps import get_super_agent
        from app.orchestration.checkpointer import get_checkpoint_health

        agent = await get_super_agent()
        graph = getattr(agent, "_investigation_graph", None)
        if graph is None:
            health = get_checkpoint_health()
            return False, bool(health.get("recoverable")), None, side_effect_signals

        snapshot = await graph.aget_state({"configurable": {"thread_id": event_id}})
        if snapshot is None or not snapshot.values:
            health = get_checkpoint_health()
            return False, bool(health.get("recoverable")), None, side_effect_signals

        values = snapshot.values
        node_trace = list(values.get("node_trace") or [])
        last_node = node_trace[-1] if node_trace else None

        if values.get("verify_need_writeback_recovery"):
            side_effect_signals.append("verify_need_writeback_recovery")
        pending_actions = values.get("verify_pending_writeback_action_ids") or []
        if pending_actions:
            side_effect_signals.append("verify_pending_writeback_action_ids")
        status_map = values.get("verify_writeback_status_map") or {}
        if isinstance(status_map, dict):
            for wb_id, status in status_map.items():
                if status == WritebackStatus.UNKNOWN.value:
                    side_effect_signals.append(f"unknown_writeback:{wb_id}")
        scalar_status = values.get("verify_writeback_status")
        if scalar_status == WritebackStatus.UNKNOWN.value:
            side_effect_signals.append("unknown_writeback_status")

        health = get_checkpoint_health()
        recoverable = bool(health.get("recoverable")) and not side_effect_signals
        return True, recoverable, last_node, side_effect_signals
    except Exception:
        logger.debug(
            "soft time limit checkpoint probe failed event=%s",
            event_id,
            exc_info=True,
        )
        return False, False, None, side_effect_signals


async def probe_soft_time_limit_context(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> SoftTimeLimitProbe:
    unknown_count = await _probe_unknown_outbox_count(session_factory, event_id)
    has_cp, recoverable, last_node, signals = await _probe_graph_checkpoint(event_id)
    if unknown_count:
        signals = [*signals, f"unknown_outbox_count:{unknown_count}"]
    return SoftTimeLimitProbe(
        has_checkpoint=has_cp,
        checkpoint_recoverable=recoverable and unknown_count == 0,
        last_checkpoint_node=last_node,
        side_effect_signals=tuple(signals),
        unknown_outbox_count=unknown_count,
    )


def decide_soft_time_limit_outcome(
    *,
    event_status: str,
    probe: SoftTimeLimitProbe,
    intent_attempt: int | None,
    max_attempts: int,
    has_intent: bool,
) -> SoftTimeLimitDecision:
    # Late soft-limit after a successful terminal must not poison CLOSED/CONTAINED.
    if event_status in _EVENT_SUCCESS_TERMINAL_STATUSES:
        return SoftTimeLimitDecision.IGNORED

    if event_status == EventStatus.FAILED.value:
        return SoftTimeLimitDecision.TERMINAL

    if probe.unknown_outbox_count > 0 or any(
        signal.startswith("unknown_") for signal in probe.side_effect_signals
    ):
        return SoftTimeLimitDecision.RECONCILE_REQUIRED

    if event_status in _SIDE_EFFECT_PHASE_STATUSES or probe.side_effect_signals:
        return SoftTimeLimitDecision.RECONCILE_REQUIRED

    next_attempt = int(intent_attempt or 0) + 1 if has_intent else max_attempts
    if (
        event_status in _PURE_INVESTIGATION_STATUSES
        and probe.has_checkpoint
        and probe.checkpoint_recoverable
        and has_intent
        and next_attempt < max_attempts
    ):
        return SoftTimeLimitDecision.RECOVERED

    return SoftTimeLimitDecision.TERMINAL


def _is_stale_broker_owner(
    intent_row: orm.InvestigationIntent | None,
    broker_task_id: str | None,
) -> bool:
    """True when the caller no longer owns the intent broker id.

    Applies to any non-terminal intent status (STARTED/RETRY/ENQUEUED/CLAIMED/…);
    after RECOVERED the broker id rotates, so a late soft-limit from the old
    delivery must be a full no-op.
    """
    if intent_row is None or broker_task_id is None:
        return False
    try:
        current = InvestigationIntentStatus(intent_row.status)
    except ValueError:
        return False
    if current in TERMINAL_INTENT_STATUSES:
        return False
    current_broker = intent_row.broker_task_id
    return bool(current_broker) and str(current_broker) != str(broker_task_id)


def _mark_intent_dead_in_session(
    intent_row: orm.InvestigationIntent,
    *,
    reason: str,
) -> None:
    current = InvestigationIntentStatus(intent_row.status)
    if current in TERMINAL_INTENT_STATUSES:
        return
    validate_intent_transition(current, InvestigationIntentStatus.DEAD)
    intent_row.status = InvestigationIntentStatus.DEAD.value
    intent_row.last_error = reason
    intent_row.claim_owner = None
    intent_row.claim_expires_at = None


async def _transition_event_failed_in_session(
    session: AsyncSession,
    event_id: str,
    row: orm.SecurityEvent,
    *,
    reason: str,
    audit_service: Any | None,
) -> None:
    current = EventStatus(row.status)
    if current is EventStatus.FAILED:
        return
    authoritative_ctx = await _build_authoritative_context(session, event_id, row, None)
    validate_transition(current, EventStatus.FAILED, authoritative_ctx)
    from_status = row.status
    row.status = EventStatus.FAILED.value
    row.row_version = int(row.row_version or 1) + 1
    row.updated_at = _utc_now()
    if audit_service is not None:
        await audit_service.log_transition_in_session(
            session,
            event_id,
            from_status=from_status,
            to_status=EventStatus.FAILED.value,
            operator=_SOFT_LIMIT_OPERATOR,
            reason=reason,
        )


async def apply_soft_time_limit_outcome(
    event_id: str,
    *,
    session_factory: async_sessionmaker[AsyncSession],
    intent_id: str | None = None,
    broker_task_id: str | None = None,
    settings: Settings | None = None,
    intent_service: Any | None = None,
    degraded_flags: Any | None = None,
) -> SoftTimeLimitOutcomeResult:
    """Apply atomic soft-limit outcome for event (+ optional intent) in one TX."""
    resolved_settings = settings or get_settings()
    max_attempts = int(resolved_settings.auto_investigate_max_attempts)
    probe = await probe_soft_time_limit_context(session_factory, event_id)

    from app.services.event_audit_log_service import EventAuditLogService

    audit_service = EventAuditLogService(session_factory)

    event_status: str | None = None
    intent_status: str | None = None
    intent_error: str | None = None
    decision = SoftTimeLimitDecision.TERMINAL
    ignore_reason = f"{_SOFT_LIMIT_REASON}:stale_broker"

    async with session_factory() as session:
        async with session.begin():
            event_row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            if event_row is None:
                logger.warning("soft time limit: event missing event=%s", event_id)
                record_soft_time_limit_outcome(decision=SoftTimeLimitDecision.TERMINAL.value)
                return SoftTimeLimitOutcomeResult(
                    decision=SoftTimeLimitDecision.TERMINAL,
                    event_id=event_id,
                    intent_id=intent_id,
                    event_status=None,
                    intent_status=None,
                    intent_error="event_missing",
                    last_checkpoint_node=probe.last_checkpoint_node,
                )

            event_status = str(event_row.status)
            intent_row: orm.InvestigationIntent | None = None
            if intent_id is not None:
                intent_row = await session.get(
                    orm.InvestigationIntent,
                    intent_id,
                    with_for_update=True,
                )
                if intent_row is not None:
                    intent_status = str(intent_row.status)
                    intent_error = intent_row.last_error

            # Refresh ambiguous-side-effect signals under the row lock (TOCTOU).
            locked_unknown = (
                await session.scalars(
                    select(orm.DispositionOutbox.latest_writeback_status).where(
                        orm.DispositionOutbox.event_id == event_id,
                        orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                    )
                )
            ).all()
            locked_unknown_count = sum(
                1 for status in locked_unknown if status == WritebackStatus.UNKNOWN.value
            )
            if locked_unknown_count != probe.unknown_outbox_count:
                signals = [
                    signal
                    for signal in probe.side_effect_signals
                    if not str(signal).startswith("unknown_outbox_count:")
                ]
                if locked_unknown_count:
                    signals.append(f"unknown_outbox_count:{locked_unknown_count}")
                probe = SoftTimeLimitProbe(
                    has_checkpoint=probe.has_checkpoint,
                    checkpoint_recoverable=(
                        probe.checkpoint_recoverable and locked_unknown_count == 0
                    ),
                    last_checkpoint_node=probe.last_checkpoint_node,
                    side_effect_signals=tuple(signals),
                    unknown_outbox_count=locked_unknown_count,
                )

            # ISSUE-314: stale/old broker owner must be a full no-op (no event
            # FAILED, no intent DEAD, no checkpoint invalidation, no dispatch).
            if _is_stale_broker_owner(intent_row, broker_task_id):
                logger.info(
                    "soft time limit ignored stale broker intent=%s expected=%s got=%s",
                    intent_id,
                    intent_row.broker_task_id if intent_row is not None else None,
                    broker_task_id,
                )
                decision = SoftTimeLimitDecision.IGNORED
                ignore_reason = f"{_SOFT_LIMIT_REASON}:stale_broker"
            else:
                decision = decide_soft_time_limit_outcome(
                    event_status=event_status,
                    probe=probe,
                    intent_attempt=int(intent_row.attempt or 0)
                    if intent_row is not None
                    else None,
                    max_attempts=max_attempts,
                    has_intent=intent_row is not None
                    and InvestigationIntentStatus(intent_row.status)
                    not in TERMINAL_INTENT_STATUSES,
                )

                recovered_applied = False
                if decision is SoftTimeLimitDecision.IGNORED:
                    ignore_reason = f"{_SOFT_LIMIT_REASON}:already_terminal"
                    # CLOSED/CONTAINED: never FAILED-rewrite; heal dangling intent.
                    if (
                        event_status in _EVENT_SUCCESS_TERMINAL_STATUSES
                        and intent_row is not None
                    ):
                        _mark_intent_dead_in_session(
                            intent_row, reason=_SOFT_LIMIT_REASON
                        )
                        intent_status = intent_row.status
                        intent_error = intent_row.last_error
                elif decision is SoftTimeLimitDecision.RECOVERED and intent_row is not None:
                    current = InvestigationIntentStatus(intent_row.status)
                    if current in TERMINAL_INTENT_STATUSES:
                        decision = SoftTimeLimitDecision.TERMINAL
                    else:
                        validate_intent_transition(current, InvestigationIntentStatus.RETRY)
                        intent_row.status = InvestigationIntentStatus.RETRY.value
                        intent_row.attempt = int(intent_row.attempt or 0) + 1
                        intent_row.revision = int(intent_row.revision or 1) + 1
                        intent_row.last_error = _SOFT_LIMIT_REASON
                        intent_row.broker_task_id = deterministic_investigation_task_id(
                            intent_row.intent_id,
                            int(intent_row.revision),
                        )
                        intent_row.claim_owner = None
                        intent_row.claim_expires_at = None
                        intent_status = intent_row.status
                        intent_error = intent_row.last_error
                        recovered_applied = True

                if (
                    decision
                    in {
                        SoftTimeLimitDecision.TERMINAL,
                        SoftTimeLimitDecision.RECONCILE_REQUIRED,
                    }
                    and not recovered_applied
                ):
                    terminal_reason = (
                        _SOFT_LIMIT_REASON
                        if decision is SoftTimeLimitDecision.TERMINAL
                        else f"{_SOFT_LIMIT_REASON}:reconcile_required"
                    )
                    # Never rewrite CLOSED/CONTAINED; FAILED is already terminal.
                    if event_status not in _EVENT_TERMINAL_STATUSES:
                        await _transition_event_failed_in_session(
                            session,
                            event_id,
                            event_row,
                            reason=terminal_reason,
                            audit_service=audit_service,
                        )
                        event_status = EventStatus.FAILED.value

                    if intent_row is not None:
                        _mark_intent_dead_in_session(
                            intent_row, reason=terminal_reason
                        )
                        intent_status = intent_row.status
                        intent_error = intent_row.last_error

    if decision in {SoftTimeLimitDecision.TERMINAL, SoftTimeLimitDecision.RECONCILE_REQUIRED}:
        try:
            from app.orchestration.checkpointer import invalidate_event_checkpoint

            await invalidate_event_checkpoint(event_id)
        except Exception:
            logger.warning(
                "soft time limit checkpoint invalidation failed event=%s",
                event_id,
                exc_info=True,
            )

    if decision is SoftTimeLimitDecision.RECONCILE_REQUIRED and degraded_flags is not None:
        try:
            await degraded_flags.set_flag(
                event_id,
                "soft_time_limit_reconcile_required",
                True,
                writer=_SOFT_LIMIT_OPERATOR,
            )
        except Exception:
            logger.warning(
                "soft time limit reconcile flag failed event=%s",
                event_id,
                exc_info=True,
            )

    if decision is SoftTimeLimitDecision.RECOVERED and intent_service is not None and intent_id:
        intent_service.schedule_dispatch(
            event_id=event_id,
            intent_id=intent_id,
            trigger="soft_time_limit_recovered",
        )

    record_soft_time_limit_outcome(decision=decision.value)
    log_fn = logger.info if decision is SoftTimeLimitDecision.IGNORED else logger.warning
    log_fn(
        "soft time limit outcome event=%s intent=%s decision=%s status=%s node=%s signals=%s",
        event_id,
        intent_id,
        decision.value,
        event_status,
        probe.last_checkpoint_node,
        probe.side_effect_signals,
    )
    return SoftTimeLimitOutcomeResult(
        decision=decision,
        event_id=event_id,
        intent_id=intent_id,
        event_status=event_status,
        intent_status=intent_status,
        intent_error=intent_error,
        last_checkpoint_node=probe.last_checkpoint_node,
        reason=(
            ignore_reason
            if decision is SoftTimeLimitDecision.IGNORED
            else _SOFT_LIMIT_REASON
            if decision is SoftTimeLimitDecision.TERMINAL
            else f"{_SOFT_LIMIT_REASON}:{decision.value}"
        ),
    )


__all__ = [
    "SoftTimeLimitDecision",
    "SoftTimeLimitOutcomeResult",
    "SoftTimeLimitProbe",
    "apply_soft_time_limit_outcome",
    "decide_soft_time_limit_outcome",
    "probe_soft_time_limit_context",
]
