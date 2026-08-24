"""Single event-level writeback envelope projector.

CLOSED gate, GET ``/events/{id}`` writeback fields, and EventContext
``WritebackSummary`` must share membership and ranking. Entity side-effects
inherit ``writeback_required`` but are ``writeback_applicable=false`` /
``readiness=not_required``; they never carry terminal ``EVENT_STATUS_UPDATE``
and must not drive readiness, pending count, or overall status.

SQL ``MIN(writeback_readiness)`` is forbidden here: lexicographic order puts
``ready`` before ``source_unresolved``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import models as orm
from app.models.enums import (
    DispositionIntentKind,
    DispositionPolicy,
    SourceDisposition,
    WritebackReadiness,
    WritebackStatus,
)

_ENVELOPE_CATEGORIES = frozenset({"response", "rollback"})
_EXCLUDED_ACTION_STATUSES = frozenset({"rejected", "superseded"})
_PENDING_STATUSES = frozenset(
    {
        WritebackStatus.PENDING,
        WritebackStatus.SENDING,
        WritebackStatus.ACCEPTED,
        WritebackStatus.UNKNOWN,
    }
)

# Worst blocking reason among applicable-required actions wins.
READINESS_AGGREGATE_PRIORITY: tuple[WritebackReadiness, ...] = (
    WritebackReadiness.PERMISSION_DENIED,
    WritebackReadiness.CONNECTOR_UNAVAILABLE,
    WritebackReadiness.CAPABILITY_UNSUPPORTED,
    WritebackReadiness.CAPABILITY_UNKNOWN,
    WritebackReadiness.NOT_CONFIGURED,
    WritebackReadiness.SOURCE_UNRESOLVED,
    WritebackReadiness.READY,
    WritebackReadiness.NOT_REQUIRED,
)

# Terminal failures surface before in-flight; CONFIRMED is least severe.
STATUS_ENVELOPE_PRIORITY: tuple[WritebackStatus, ...] = (
    WritebackStatus.FAILED,
    WritebackStatus.CONFLICT,
    WritebackStatus.UNKNOWN,
    WritebackStatus.PENDING,
    WritebackStatus.SENDING,
    WritebackStatus.ACCEPTED,
    WritebackStatus.PARTIAL,
    WritebackStatus.CONFIRMED,
)

# Historical alias kept so EventContext ranking docs stay importable.
STATUS_AGGREGATE_PRIORITY = STATUS_ENVELOPE_PRIORITY

WritebackRowBundle = tuple[
    list[orm.Action],
    list[orm.DispositionOutbox],
    dict[str, orm.DispositionReceipt],
]


def pick_by_priority(present: set[Any], priority: tuple[Any, ...]) -> Any | None:
    """Return the first member of ``priority`` that is present."""
    for candidate in priority:
        if candidate in present:
            return candidate
    return None


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    raw = getattr(value, "value", value)
    return str(raw)


def current_plan_revision(actions: Sequence[Any]) -> int | None:
    revisions = [int(action.plan_revision) for action in actions]
    return max(revisions) if revisions else None


def is_current_plan_action(action: Any, revision: int | None) -> bool:
    if revision is not None and int(action.plan_revision) != int(revision):
        return False
    if action.superseded_by_revision is not None:
        return False
    if _as_str(action.status) in _EXCLUDED_ACTION_STATUSES:
        return False
    if _as_str(action.action_category) not in _ENVELOPE_CATEGORIES:
        return False
    return True


def is_envelope_action(action: Any, revision: int | None) -> bool:
    """True when this action may drive the event-level writeback envelope."""
    if not is_current_plan_action(action, revision):
        return False
    if not bool(action.writeback_required):
        return False
    if not bool(action.writeback_applicable):
        return False
    return True


def parse_readiness(raw: Any) -> WritebackReadiness:
    try:
        return WritebackReadiness(_as_str(raw))
    except ValueError:
        return WritebackReadiness.CAPABILITY_UNKNOWN


def parse_status(raw: Any) -> WritebackStatus | None:
    if raw is None or raw == "":
        return None
    try:
        return WritebackStatus(_as_str(raw))
    except ValueError:
        return WritebackStatus.UNKNOWN


def resolve_outbox_status(
    outbox: Any,
    receipts_by_writeback_id: Mapping[str, Any],
) -> WritebackStatus | None:
    latest_receipt = receipts_by_writeback_id.get(outbox.writeback_id)
    if latest_receipt is not None and latest_receipt.status:
        return parse_status(latest_receipt.status)
    return parse_status(outbox.latest_writeback_status)


@dataclass(frozen=True, slots=True)
class EventWritebackEnvelope:
    aggregate_readiness: WritebackReadiness
    aggregate_status: WritebackStatus | None
    pending_count: int
    current_revision: int | None
    required_action_count: int
    applicable_action_count: int
    envelope_action_ids: tuple[str, ...]
    blocked_action_ids: tuple[str, ...]
    readiness_counts: dict[WritebackReadiness, int]
    writeback_counts: dict[WritebackStatus, int]
    terminal_event_action_id: str | None
    terminal_event_writeback_id: str | None
    terminal_event_disposition: SourceDisposition | None
    terminal_event_confirmed: bool
    closure_cycle: int


def project_writeback_envelope(
    policy: DispositionPolicy,
    actions: Sequence[Any],
    outboxes: Sequence[Any],
    receipts_by_writeback_id: Mapping[str, Any] | None = None,
) -> EventWritebackEnvelope:
    """Project event-level writeback fields from persisted Action + outbox rows."""
    receipts = receipts_by_writeback_id or {}
    revision = current_plan_revision(actions)
    current_required = [
        action
        for action in actions
        if is_current_plan_action(action, revision) and action.writeback_required
    ]
    envelope_actions = [action for action in actions if is_envelope_action(action, revision)]
    envelope_ids = {action.action_id for action in envelope_actions}

    if policy is DispositionPolicy.NOT_REQUIRED:
        aggregate_readiness = WritebackReadiness.NOT_REQUIRED
    elif envelope_actions:
        readiness_present = {
            parse_readiness(action.writeback_readiness) for action in envelope_actions
        }
        picked = pick_by_priority(readiness_present, READINESS_AGGREGATE_PRIORITY)
        if isinstance(picked, WritebackReadiness):
            aggregate_readiness = picked
        else:
            aggregate_readiness = WritebackReadiness.CAPABILITY_UNKNOWN
    elif current_required:
        # Entity-only / missing terminal writeback: never invent READY.
        aggregate_readiness = WritebackReadiness.NOT_CONFIGURED
    else:
        # REQUIRED policy but nothing planned yet.
        aggregate_readiness = WritebackReadiness.CAPABILITY_UNKNOWN

    readiness_counts: Counter[WritebackReadiness] = Counter()
    blocked: list[str] = []
    for action in envelope_actions:
        readiness = parse_readiness(action.writeback_readiness)
        readiness_counts[readiness] += 1
        if readiness is not WritebackReadiness.READY:
            blocked.append(action.action_id)

    envelope_outboxes = [
        outbox
        for outbox in outboxes
        if outbox.action_id in envelope_ids and outbox.superseded_by_disposition_id is None
    ]

    status_counts: Counter[WritebackStatus] = Counter()
    closure_cycle = 0
    terminal_event_action_id: str | None = None
    terminal_event_writeback_id: str | None = None
    terminal_event_disposition: SourceDisposition | None = None
    terminal_event_confirmed = False
    for outbox in envelope_outboxes:
        closure_cycle = max(closure_cycle, int(outbox.closure_cycle or 0))
        status = resolve_outbox_status(outbox, receipts)
        if status is not None:
            status_counts[status] += 1
        if _as_str(outbox.intent_kind) == DispositionIntentKind.EVENT_STATUS_UPDATE.value:
            terminal_event_action_id = outbox.action_id
            terminal_event_writeback_id = outbox.writeback_id
            if status is WritebackStatus.CONFIRMED:
                terminal_event_confirmed = True
            payload = outbox.command_payload or {}
            disp = payload.get("disposition") or payload.get("source_disposition")
            if isinstance(disp, str):
                try:
                    terminal_event_disposition = SourceDisposition(disp)
                except ValueError:
                    terminal_event_disposition = None

    aggregate_status = (
        pick_by_priority(set(status_counts), STATUS_ENVELOPE_PRIORITY) if status_counts else None
    )
    if aggregate_status is not None and not isinstance(aggregate_status, WritebackStatus):
        aggregate_status = None

    pending_count = sum(status_counts[status] for status in _PENDING_STATUSES)

    envelope = EventWritebackEnvelope(
        aggregate_readiness=aggregate_readiness,
        aggregate_status=aggregate_status,
        pending_count=pending_count,
        current_revision=revision,
        required_action_count=len(current_required),
        applicable_action_count=len(envelope_actions),
        envelope_action_ids=tuple(action.action_id for action in envelope_actions),
        blocked_action_ids=tuple(blocked),
        readiness_counts=dict(readiness_counts),
        writeback_counts=dict(status_counts),
        terminal_event_action_id=terminal_event_action_id,
        terminal_event_writeback_id=terminal_event_writeback_id,
        terminal_event_disposition=terminal_event_disposition,
        terminal_event_confirmed=terminal_event_confirmed,
        closure_cycle=closure_cycle,
    )
    # #region agent log
    try:
        import json as _dbg_json
        import time as _dbg_time

        with open(
            "/Users/apple/Desktop/shadowtrace副本/.cursor/debug-0da307.log",
            "a",
            encoding="utf-8",
        ) as _dbg_f:
            _dbg_f.write(
                _dbg_json.dumps(
                    {
                        "sessionId": "0da307",
                        "runId": "post-fix",
                        "hypothesisId": "F",
                        "location": "writeback_event_projection.py:project_writeback_envelope",
                        "message": "shared writeback envelope",
                        "data": {
                            "policy": policy.value,
                            "revision": revision,
                            "required_count": envelope.required_action_count,
                            "applicable_count": envelope.applicable_action_count,
                            "envelope_action_ids": list(envelope.envelope_action_ids),
                            "readiness": envelope.aggregate_readiness.value,
                            "status": (
                                envelope.aggregate_status.value
                                if envelope.aggregate_status is not None
                                else None
                            ),
                            "pending": envelope.pending_count,
                            "writeback_counts": {
                                status.value: count
                                for status, count in envelope.writeback_counts.items()
                            },
                        },
                        "timestamp": int(_dbg_time.time() * 1000),
                    }
                )
                + "\n"
            )
    except Exception:
        pass
    # #endregion
    return envelope


async def load_writeback_rows(
    session: AsyncSession,
    event_id: str,
) -> tuple[list[orm.Action], list[orm.DispositionOutbox], dict[str, orm.DispositionReceipt]]:
    """Load Action + outbox + latest receipt rows for one event."""
    actions = list(
        (await session.scalars(select(orm.Action).where(orm.Action.event_id == event_id))).all()
    )
    outboxes = list(
        (
            await session.scalars(
                select(orm.DispositionOutbox).where(orm.DispositionOutbox.event_id == event_id)
            )
        ).all()
    )
    receipts_by_wb: dict[str, orm.DispositionReceipt] = {}
    writeback_ids = {outbox.writeback_id for outbox in outboxes}
    if writeback_ids:
        receipt_rows = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id.in_(writeback_ids)
                )
            )
        ).all()
        for receipt in receipt_rows:
            prev = receipts_by_wb.get(receipt.writeback_id)
            if prev is None or receipt.sequence > prev.sequence:
                receipts_by_wb[receipt.writeback_id] = receipt
    return actions, outboxes, receipts_by_wb


async def load_writeback_rows_for_events(
    session: AsyncSession,
    event_ids: Sequence[str],
) -> dict[str, WritebackRowBundle]:
    """Batch-load Action + outbox + latest receipt rows for a page of events.

    One query set for the whole page — list endpoints must not call
    ``load_writeback_rows`` per item.
    """
    unique_ids = list(dict.fromkeys(event_id for event_id in event_ids if event_id))
    if not unique_ids:
        return {}

    actions_by_event: dict[str, list[orm.Action]] = {event_id: [] for event_id in unique_ids}
    for action in (
        await session.scalars(select(orm.Action).where(orm.Action.event_id.in_(unique_ids)))
    ).all():
        actions_by_event.setdefault(action.event_id, []).append(action)

    outboxes_by_event: dict[str, list[orm.DispositionOutbox]] = {
        event_id: [] for event_id in unique_ids
    }
    writeback_ids: set[str] = set()
    for outbox in (
        await session.scalars(
            select(orm.DispositionOutbox).where(orm.DispositionOutbox.event_id.in_(unique_ids))
        )
    ).all():
        outboxes_by_event.setdefault(outbox.event_id, []).append(outbox)
        writeback_ids.add(outbox.writeback_id)

    receipts_by_wb: dict[str, orm.DispositionReceipt] = {}
    if writeback_ids:
        for receipt in (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id.in_(writeback_ids)
                )
            )
        ).all():
            prev = receipts_by_wb.get(receipt.writeback_id)
            if prev is None or receipt.sequence > prev.sequence:
                receipts_by_wb[receipt.writeback_id] = receipt

    result: dict[str, WritebackRowBundle] = {}
    for event_id in unique_ids:
        event_outboxes = outboxes_by_event.get(event_id, [])
        event_receipts = {
            outbox.writeback_id: receipts_by_wb[outbox.writeback_id]
            for outbox in event_outboxes
            if outbox.writeback_id in receipts_by_wb
        }
        result[event_id] = (
            actions_by_event.get(event_id, []),
            event_outboxes,
            event_receipts,
        )
    return result
