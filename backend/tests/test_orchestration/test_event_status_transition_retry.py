"""EventStatus transition retry helper tests (ISSUE-234)."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.errors import InvalidStateTransitionError, ShadowTraceError, ValidationError
from app.models.enums import EventStatus
from app.models.workflow import TransitionContext, validate_transition
from app.orchestration.event_status_transition_retry import transition_with_bounded_retry
from app.orchestration.workflow_graph import _transition_status


@dataclass
class _FlakyGraphStateMachine:
    status: EventStatus = EventStatus.NEW
    transitions: list[tuple[str, EventStatus, str | None]] = field(default_factory=list)
    statuses: dict[str, EventStatus] = field(default_factory=dict)
    fail_count: int = 0
    attempts: int = 0

    async def transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: Any = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> Any:
        del operator
        self.attempts += 1
        if self.attempts <= self.fail_count:
            raise ConnectionError("db unavailable")
        current = self.statuses.get(event_id, EventStatus.NEW)
        validate_transition(current, target, context or TransitionContext())
        self.transitions.append((event_id, target, reason))
        self.statuses[event_id] = target
        self.status = target
        return SimpleNamespace(event_id=event_id, status=target)


@pytest.mark.asyncio
async def test_shared_helper_retries_transient_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = 0

    async def _call() -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise ConnectionError("db unavailable")

    async def _noop_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(
        "app.orchestration.event_status_transition_retry.asyncio.sleep",
        _noop_sleep,
    )

    await transition_with_bounded_retry(
        _call,
        event_id="evt-retry",
        target=EventStatus.TRIAGING,
        max_retries=2,
        backoff_seconds=0.1,
        log_prefix="Test",
    )
    assert attempts == 2


@pytest.mark.asyncio
async def test_shared_helper_non_retryable_fails_immediately() -> None:
    attempts = 0

    async def _call() -> None:
        nonlocal attempts
        attempts += 1
        raise ValidationError("permanent")

    with pytest.raises(ShadowTraceError) as exc:
        await transition_with_bounded_retry(
            _call,
            event_id="evt-perm",
            target=EventStatus.TRIAGING,
            max_retries=3,
            backoff_seconds=0.0,
            log_prefix="Test",
        )

    assert attempts == 1
    assert exc.value.details["failures"][0]["retryable"] is False


@pytest.mark.asyncio
async def test_shared_helper_preserves_soft_time_limit() -> None:
    from celery.exceptions import SoftTimeLimitExceeded

    attempts = 0

    async def _call() -> None:
        nonlocal attempts
        attempts += 1
        raise SoftTimeLimitExceeded()

    with pytest.raises(SoftTimeLimitExceeded):
        await transition_with_bounded_retry(
            _call,
            event_id="evt-soft",
            target=EventStatus.FAILED,
            max_retries=2,
            backoff_seconds=0.0,
            log_prefix="Test",
        )

    assert attempts == 1


@pytest.mark.asyncio
async def test_workflow_graph_transition_status_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    machine = _FlakyGraphStateMachine(fail_count=1)
    services = {"state_machine": machine}
    state = {"event_id": "evt-graph-retry", "event_status": EventStatus.NEW.value}

    monkeypatch.setattr(
        "app.orchestration.workflow_graph.get_settings",
        lambda: SimpleNamespace(
            super_agent_transition_max_retries=2,
            super_agent_transition_retry_backoff_seconds=0.0,
        ),
    )

    patch = await _transition_status(
        services,
        state,
        EventStatus.TRIAGING,
        reason="test:retry",
    )

    assert patch["event_status"] == EventStatus.TRIAGING.value
    assert machine.attempts == 2
    assert machine.statuses["evt-graph-retry"] == EventStatus.TRIAGING


@pytest.mark.asyncio
async def test_workflow_graph_invalid_transition_not_retried() -> None:
    machine = _FlakyGraphStateMachine()

    async def _raise_invalid(*_args: Any, **_kwargs: Any) -> None:
        machine.attempts += 1
        raise InvalidStateTransitionError(
            "illegal",
            current=EventStatus.NEW,
            target=EventStatus.CLOSED,
        )

    machine.transition = _raise_invalid  # type: ignore[method-assign]
    services = {"state_machine": machine}
    state = {"event_id": "evt-graph-invalid", "event_status": EventStatus.NEW.value}

    with pytest.raises(InvalidStateTransitionError):
        await _transition_status(
            services,
            state,
            EventStatus.CLOSED,
            reason="test:invalid",
        )

    assert machine.attempts == 1
