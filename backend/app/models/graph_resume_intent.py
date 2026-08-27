"""Durable graph resume intent contract (ISSUE-277 / #873)."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import GraphResumeIntentStatus

INTENT_KIND_MANUAL_RESOLUTION_RESUME = "manual_resolution_resume"
INTENT_KIND_APPROVAL_PLAN_RESUME = "approval_plan_resume"
INTENT_VERSION_ISSUE277_V1 = "issue277_v1"
APPROVAL_PLAN_RESUME_HOLD_GENERATION = 0

RESOLUTION_SOURCE_ACTION_UNKNOWN = "action_unknown"
RESOLUTION_SOURCE_WRITEBACK_MANUAL = "writeback_manual"
RESOLUTION_SOURCE_WRITEBACK_AUTO = "writeback_auto"
RESOLUTION_SOURCE_APPROVAL_PLAN = "approval_plan"
RESOLUTION_SOURCE_ANALYST_VERDICT = "analyst_final_verdict"

SUBJECT_KIND_ACTION = "action"
SUBJECT_KIND_WRITEBACK = "writeback"
SUBJECT_KIND_EVENT = "event"

MANUAL_HOLD_JOURNAL_FIELD = "manual_hold"

ACTIVE_GRAPH_RESUME_STATUSES = frozenset(
    {
        GraphResumeIntentStatus.PENDING,
        GraphResumeIntentStatus.CLAIMED,
        GraphResumeIntentStatus.STARTED,
        GraphResumeIntentStatus.RETRY,
    }
)

GRAPH_RESUME_TRANSITIONS: dict[GraphResumeIntentStatus, frozenset[GraphResumeIntentStatus]] = {
    GraphResumeIntentStatus.PENDING: frozenset(
        {
            GraphResumeIntentStatus.CLAIMED,
            GraphResumeIntentStatus.SKIPPED,
        }
    ),
    GraphResumeIntentStatus.CLAIMED: frozenset(
        {
            GraphResumeIntentStatus.STARTED,
            GraphResumeIntentStatus.RETRY,
            GraphResumeIntentStatus.PENDING,
            GraphResumeIntentStatus.SKIPPED,
            GraphResumeIntentStatus.DEAD,
        }
    ),
    GraphResumeIntentStatus.STARTED: frozenset(
        {
            GraphResumeIntentStatus.TERMINAL,
            GraphResumeIntentStatus.SKIPPED,
            GraphResumeIntentStatus.RETRY,
            GraphResumeIntentStatus.DEAD,
        }
    ),
    GraphResumeIntentStatus.RETRY: frozenset(
        {
            GraphResumeIntentStatus.CLAIMED,
            GraphResumeIntentStatus.DEAD,
            GraphResumeIntentStatus.SKIPPED,
        }
    ),
    GraphResumeIntentStatus.TERMINAL: frozenset(),
    GraphResumeIntentStatus.SKIPPED: frozenset(),
    GraphResumeIntentStatus.DEAD: frozenset({GraphResumeIntentStatus.RETRY}),
}

TERMINAL_GRAPH_RESUME_STATUSES = frozenset(
    {
        GraphResumeIntentStatus.TERMINAL,
        GraphResumeIntentStatus.SKIPPED,
        GraphResumeIntentStatus.DEAD,
    }
)


class GraphResumeIntentTransitionError(ValueError):
    """Raised when a graph resume intent status transition is not allowed."""


def validate_graph_resume_transition(
    current: GraphResumeIntentStatus,
    target: GraphResumeIntentStatus,
) -> None:
    allowed = GRAPH_RESUME_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise GraphResumeIntentTransitionError(
            f"invalid graph resume intent transition: {current.value} -> {target.value}"
        )


@dataclass(frozen=True)
class GraphResumeIntentRecord:
    intent_id: str
    event_id: str
    intent_kind: str
    intent_version: str
    status: GraphResumeIntentStatus
    revision: int
    attempt: int
    hold_generation: int
    checkpoint_id: str | None
    operation_id: str | None
    resolution_source: str
    subject_kind: str
    subject_id: str
    resolution: str | None
    principal: str | None
    skip_reason: str | None
    last_error: str | None


@dataclass(frozen=True)
class ManualHoldSnapshot:
    generation: int
    reason: str
    pending_ids: tuple[str, ...]
    checkpoint_id: str | None


def parse_manual_hold_snapshot(raw: object) -> ManualHoldSnapshot | None:
    if not isinstance(raw, dict):
        return None
    try:
        generation = int(raw.get("generation") or 0)
    except (TypeError, ValueError):
        return None
    if generation <= 0:
        return None
    pending_raw = raw.get("pending_ids") or []
    pending_ids = tuple(str(item) for item in pending_raw) if isinstance(pending_raw, list) else ()
    checkpoint_id = raw.get("checkpoint_id")
    return ManualHoldSnapshot(
        generation=generation,
        reason=str(raw.get("reason") or ""),
        pending_ids=pending_ids,
        checkpoint_id=str(checkpoint_id) if checkpoint_id is not None else None,
    )


__all__ = [
    "ACTIVE_GRAPH_RESUME_STATUSES",
    "APPROVAL_PLAN_RESUME_HOLD_GENERATION",
    "GRAPH_RESUME_TRANSITIONS",
    "INTENT_KIND_APPROVAL_PLAN_RESUME",
    "INTENT_KIND_MANUAL_RESOLUTION_RESUME",
    "INTENT_VERSION_ISSUE277_V1",
    "MANUAL_HOLD_JOURNAL_FIELD",
    "RESOLUTION_SOURCE_ACTION_UNKNOWN",
    "RESOLUTION_SOURCE_APPROVAL_PLAN",
    "RESOLUTION_SOURCE_WRITEBACK_AUTO",
    "RESOLUTION_SOURCE_WRITEBACK_MANUAL",
    "RESOLUTION_SOURCE_ANALYST_VERDICT",
    "SUBJECT_KIND_ACTION",
    "SUBJECT_KIND_EVENT",
    "SUBJECT_KIND_WRITEBACK",
    "TERMINAL_GRAPH_RESUME_STATUSES",
    "GraphResumeIntentRecord",
    "GraphResumeIntentTransitionError",
    "ManualHoldSnapshot",
    "parse_manual_hold_snapshot",
    "validate_graph_resume_transition",
]
