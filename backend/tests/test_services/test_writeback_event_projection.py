"""Unit tests for the shared event-level writeback envelope projector."""

from __future__ import annotations

from types import SimpleNamespace

from app.models.enums import (
    DispositionIntentKind,
    DispositionPolicy,
    WritebackReadiness,
    WritebackStatus,
)
from app.services.writeback_event_projection import (
    READINESS_AGGREGATE_PRIORITY,
    pick_by_priority,
    project_writeback_envelope,
)


def _action(
    *,
    action_id: str,
    tool_name: str = "update_source_event_disposition",
    required: bool = True,
    applicable: bool = True,
    readiness: WritebackReadiness = WritebackReadiness.READY,
    plan_revision: int = 1,
    category: str = "response",
    status: str = "success",
    superseded_by_revision: int | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        action_id=action_id,
        tool_name=tool_name,
        writeback_required=required,
        writeback_applicable=applicable,
        writeback_readiness=readiness.value,
        plan_revision=plan_revision,
        action_category=category,
        status=status,
        superseded_by_revision=superseded_by_revision,
    )


def _outbox(
    *,
    action_id: str,
    writeback_id: str,
    status: WritebackStatus,
    intent: DispositionIntentKind = DispositionIntentKind.EVENT_STATUS_UPDATE,
    superseded_by_disposition_id: str | None = None,
    closure_cycle: int = 1,
    disposition: str | None = "contained",
) -> SimpleNamespace:
    payload = {"disposition": disposition} if disposition is not None else {}
    return SimpleNamespace(
        action_id=action_id,
        writeback_id=writeback_id,
        latest_writeback_status=status.value,
        intent_kind=intent.value,
        superseded_by_disposition_id=superseded_by_disposition_id,
        closure_cycle=closure_cycle,
        command_payload=payload,
    )


def test_sql_min_would_prefer_ready_over_source_unresolved() -> None:
    """Lexicographic MIN is the live-eval footgun this projector exists to replace."""
    values = {
        WritebackReadiness.READY.value,
        WritebackReadiness.SOURCE_UNRESOLVED.value,
    }
    assert min(values) == WritebackReadiness.READY.value
    picked = pick_by_priority(
        {WritebackReadiness.READY, WritebackReadiness.SOURCE_UNRESOLVED},
        READINESS_AGGREGATE_PRIORITY,
    )
    assert picked is WritebackReadiness.SOURCE_UNRESOLVED


def test_envelope_ignores_entity_side_effect_not_required_readiness() -> None:
    entity = _action(
        action_id="act-ent",
        tool_name="isolate_host",
        applicable=False,
        readiness=WritebackReadiness.NOT_REQUIRED,
    )
    terminal = _action(action_id="act-term")
    envelope = project_writeback_envelope(
        DispositionPolicy.REQUIRED,
        [entity, terminal],
        [
            _outbox(
                action_id="act-ent",
                writeback_id="wbk-ent",
                status=WritebackStatus.ACCEPTED,
                intent=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
            ),
            _outbox(
                action_id="act-term",
                writeback_id="wbk-term",
                status=WritebackStatus.CONFIRMED,
            ),
        ],
    )
    assert envelope.aggregate_readiness is WritebackReadiness.READY
    assert envelope.aggregate_status is WritebackStatus.CONFIRMED
    assert envelope.pending_count == 0
    assert envelope.required_action_count == 2
    assert envelope.applicable_action_count == 1
    assert envelope.envelope_action_ids == ("act-term",)
    assert envelope.writeback_counts.get(WritebackStatus.ACCEPTED, 0) == 0
    assert envelope.terminal_event_confirmed is True


def test_envelope_readiness_uses_semantic_priority() -> None:
    envelope = project_writeback_envelope(
        DispositionPolicy.REQUIRED,
        [
            _action(action_id="act-ready"),
            _action(
                action_id="act-unresolved",
                readiness=WritebackReadiness.SOURCE_UNRESOLVED,
            ),
        ],
        [],
    )
    assert envelope.aggregate_readiness is WritebackReadiness.SOURCE_UNRESOLVED
    assert "act-unresolved" in envelope.blocked_action_ids
    assert "act-ready" not in envelope.blocked_action_ids


def test_envelope_failed_outranks_pending() -> None:
    envelope = project_writeback_envelope(
        DispositionPolicy.REQUIRED,
        [_action(action_id="act-term")],
        [
            _outbox(
                action_id="act-term",
                writeback_id="wbk-pending",
                status=WritebackStatus.PENDING,
                intent=DispositionIntentKind.EVENT_STATUS_UPDATE,
            ),
            _outbox(
                action_id="act-term",
                writeback_id="wbk-failed",
                status=WritebackStatus.FAILED,
                intent=DispositionIntentKind.EVENT_STATUS_UPDATE,
            ),
        ],
    )
    assert envelope.aggregate_status is WritebackStatus.FAILED
    assert envelope.pending_count == 1


def test_envelope_ignores_historical_revision_outboxes() -> None:
    envelope = project_writeback_envelope(
        DispositionPolicy.REQUIRED,
        [
            _action(action_id="act-hist", plan_revision=1),
            _action(action_id="act-cur", plan_revision=2),
        ],
        [
            _outbox(
                action_id="act-hist",
                writeback_id="wbk-hist",
                status=WritebackStatus.FAILED,
            ),
            _outbox(
                action_id="act-cur",
                writeback_id="wbk-cur",
                status=WritebackStatus.CONFIRMED,
            ),
        ],
    )
    assert envelope.current_revision == 2
    assert envelope.envelope_action_ids == ("act-cur",)
    assert envelope.aggregate_status is WritebackStatus.CONFIRMED
    assert envelope.pending_count == 0


def test_envelope_overlays_later_receipt_status() -> None:
    outbox = _outbox(
        action_id="act-term",
        writeback_id="wbk-term",
        status=WritebackStatus.ACCEPTED,
    )
    receipt = SimpleNamespace(
        writeback_id="wbk-term",
        sequence=1,
        status=WritebackStatus.CONFIRMED.value,
    )
    envelope = project_writeback_envelope(
        DispositionPolicy.REQUIRED,
        [_action(action_id="act-term")],
        [outbox],
        {"wbk-term": receipt},
    )
    assert envelope.aggregate_status is WritebackStatus.CONFIRMED
    assert envelope.pending_count == 0
    assert envelope.terminal_event_confirmed is True


def test_required_policy_with_no_actions_does_not_invent_ready() -> None:
    envelope = project_writeback_envelope(DispositionPolicy.REQUIRED, [], [])
    assert envelope.aggregate_readiness is WritebackReadiness.CAPABILITY_UNKNOWN
    assert envelope.aggregate_status is None
    assert envelope.pending_count == 0
