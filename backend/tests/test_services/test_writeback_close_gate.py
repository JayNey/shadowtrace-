"""WritebackCloseGate API error mapping and outbox projection helpers (ISSUE-171)."""

from __future__ import annotations

import pytest

from app.core.errors import (
    WritebackConflictError,
    WritebackFailedError,
    WritebackPendingError,
    WritebackUnsupportedError,
)
from app.models.enums import WritebackStatus
from app.models.workflow import WritebackCloseGateReason, WritebackCloseGateViolation
from app.services.writeback_close_gate import raise_api_writeback_gate_error


@pytest.mark.parametrize(
    ("violation", "error_type", "error_code"),
    [
        (
            WritebackCloseGateViolation(reason=WritebackCloseGateReason.NO_APPLICABLE),
            WritebackUnsupportedError,
            "writeback_unsupported",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.READINESS_NOT_READY,
                action_id="act-1",
                writeback_readiness="capability_unknown",
            ),
            WritebackUnsupportedError,
            "writeback_unsupported",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.NO_COMMAND,
                action_id="act-1",
            ),
            WritebackUnsupportedError,
            "writeback_unsupported",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.INTENTS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.PENDING.value,
            ),
            WritebackPendingError,
            "writeback_pending",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.INTENTS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.FAILED.value,
            ),
            WritebackFailedError,
            "writeback_failed",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.INTENTS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.CONFLICT.value,
            ),
            WritebackConflictError,
            "writeback_conflict",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.STATUS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.ACCEPTED.value,
            ),
            WritebackPendingError,
            "writeback_pending",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.STATUS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.FAILED.value,
            ),
            WritebackFailedError,
            "writeback_failed",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.STATUS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.CONFLICT.value,
            ),
            WritebackConflictError,
            "writeback_conflict",
        ),
    ],
)
def test_raise_api_writeback_gate_error_reason_matrix(
    violation: WritebackCloseGateViolation,
    error_type: type[Exception],
    error_code: str,
) -> None:
    with pytest.raises(error_type) as exc_info:
        raise_api_writeback_gate_error(violation, event_id="evt-matrix")
    err = exc_info.value
    assert getattr(err, "error_code", None) == error_code
    assert err.details["event_id"] == "evt-matrix"  # type: ignore[attr-defined]
