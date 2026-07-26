"""ReplanHandler — replan trigger, constraint enforcement, and escalation (ISSUE-062).

ReplanHandler ONLY handles ``execution_failed`` / ``effect_not_verified`` action
problems.  Writeback waiting/failed/unknown/conflict is handled separately by
``WritebackRecoveryHandler`` and must NEVER enter REPLANNING.

When ``replan_count`` reaches ``MAX_REPLAN_COUNT`` and the plan still fails, the
handler sets ``security_event.escalated=true``, routes the event through
CONTAINED (partial success) or FAILED (all failed), and proceeds to report
generation with a mandatory human-escalation note.

Design
------
* ``evaluate_replan(…)`` — returns the replan decision (continue / escalate).
* ``execute_replan(…)`` — transitions state to REPLANNING and increments the
  counter.  Actual plan revision is done by ``planner_node()`` which already
  calls ``PlannerAgent.revise()`` when ``replan_count > 0``.
* ``escalate(…)`` — marks ``escalated=true`` and transitions through CONTAINED
  or FAILED into REPORTING.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from app.models.enums import EventStatus
from app.models.workflow import MAX_REPLAN_COUNT, TransitionContext

logger = logging.getLogger(__name__)

_REPLAN_OPERATOR = "ReplanHandler"


# --------------------------------------------------------------------------- #
# Ports
# --------------------------------------------------------------------------- #


class _StateMachinePort(Protocol):
    async def transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: Any | None = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> Any: ...


class _WorkflowRuntimePort(Protocol):
    async def set_execution_substate(
        self,
        event_id: str,
        substate: Any,
        *,
        event_status: EventStatus,
    ) -> None: ...


# --------------------------------------------------------------------------- #
# Types
# --------------------------------------------------------------------------- #


class ReplanDecision(StrEnum):
    CONTINUE = "continue"
    ESCALATE = "escalate"


@dataclass
class ReplanResult:
    """Outcome of ``ReplanHandler.evaluate_replan()``."""

    decision: ReplanDecision
    replan_count: int
    max_replan_count: int = MAX_REPLAN_COUNT
    escalated: bool = False
    reason: str = ""


@dataclass
class EscalationResult:
    """Outcome of ``ReplanHandler.escalate()``."""

    escalated: bool
    target_status: EventStatus
    reason: str


# --------------------------------------------------------------------------- #
# Handler
# --------------------------------------------------------------------------- #


class ReplanHandler:
    """Enforce ``MAX_REPLAN_COUNT`` and escalate when the limit is hit.

    Only **execution_failed** and **effect_not_verified** action problems
    should enter this handler.  Writeback issues go to
    ``WritebackRecoveryHandler`` — they do NOT consume replan_count and do
    NOT trigger REPLANNING.
    """

    def __init__(
        self,
        *,
        state_machine: _StateMachinePort,
        runtime: _WorkflowRuntimePort,
    ) -> None:
        self._state_machine = state_machine
        self._runtime = runtime

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def evaluate_replan(
        self,
        current_replan_count: int,
        *,
        failed_actions: list[str] | None = None,
    ) -> ReplanResult:
        """Decide whether another replan cycle is allowed.

        Parameters
        ----------
        current_replan_count:
            The replan_count from the current InvestigationState or event row.
            Values from the row are authoritative; the state copy is used
            only when the row is not yet committed.
        failed_actions:
            Action IDs that failed verification; used only for logging.

        Returns
        -------
        ReplanResult
            ``decision=CONTINUE`` when another cycle is allowed;
            ``decision=ESCALATE`` when the limit has been reached.
        """
        next_count = current_replan_count + 1
        if next_count > MAX_REPLAN_COUNT:
            logger.warning(
                "replan_count=%d exceeds MAX_REPLAN_COUNT=%d for failed_actions=%s; escalating",
                next_count,
                MAX_REPLAN_COUNT,
                failed_actions or [],
            )
            return ReplanResult(
                decision=ReplanDecision.ESCALATE,
                replan_count=current_replan_count,
                max_replan_count=MAX_REPLAN_COUNT,
                escalated=True,
                reason=f"replan_count_exceeded:{next_count}>{MAX_REPLAN_COUNT}",
            )

        logger.info(
            "replan allowed: count=%d/%d for failed_actions=%s",
            next_count,
            MAX_REPLAN_COUNT,
            failed_actions or [],
        )
        return ReplanResult(
            decision=ReplanDecision.CONTINUE,
            replan_count=next_count,
            max_replan_count=MAX_REPLAN_COUNT,
            escalated=False,
            reason=f"replan_cycle_{next_count}",
        )

    async def execute_replan(
        self,
        event_id: str,
        *,
        current_replan_count: int,
        failed_actions: list[str] | None = None,
    ) -> ReplanResult:
        """Validate, transition to REPLANNING, increment counter, and return result.

        The transition to REPLANNING is performed by the state machine so the
        ``replan_count`` bump is atomic with the status write.  After this
        returns with ``decision=CONTINUE``, the graph edge from
        ``NODE_REPLAN`` to ``NODE_PLANNER`` takes over — ``planner_node()``
        already calls ``PlannerAgent.revise()`` when ``replan_count > 0``.

        Raises
        ------
        InvalidStateTransitionError
            If the state machine rejects the REPLANNING transition (e.g.
            replan_count would exceed MAX_REPLAN_COUNT inside the row-locked
            pre-transition check).
        """
        result = self.evaluate_replan(current_replan_count, failed_actions=failed_actions)

        if result.decision is ReplanDecision.ESCALATE:
            return result

        reason = (
            f"replan:cycle_{result.replan_count}:"
            f"{','.join(failed_actions or ['unknown'])}"
        )
        await self._state_machine.transition(
            event_id,
            EventStatus.REPLANNING,
            operator=_REPLAN_OPERATOR,
            reason=reason,
        )

        return result

    async def escalate(
        self,
        event_id: str,
        *,
        has_partial_success: bool = False,
        failed_actions: list[str] | None = None,
    ) -> EscalationResult:
        """Escalate after replan_count exhausted.

        Sets ``escalated=true`` on the event row and transitions through
        CONTAINED (when any action partially succeeded) or FAILED (all failed)
        into REPORTING.  The report generator reads ``escalated`` to include
        a mandatory human-escalation section.

        Callers must subsequently route to ``report_node``.
        """
        target = EventStatus.CONTAINED if has_partial_success else EventStatus.FAILED
        reason = (
            f"replan:escalated:max_replan_count={MAX_REPLAN_COUNT}:"
            f"{','.join(failed_actions or ['unknown'])}"
        )
        await self._state_machine.transition(
            event_id,
            target,
            context=TransitionContext(escalated=True),
            operator=_REPLAN_OPERATOR,
            reason=reason,
        )

        logger.warning(
            "replan escalation: event=%s target=%s has_partial=%s",
            event_id,
            target.value,
            has_partial_success,
        )
        return EscalationResult(
            escalated=True,
            target_status=target,
            reason=reason,
        )

    @staticmethod
    def needs_replan(state: dict[str, Any]) -> bool:
        """Return True when the verification result signals need_action_replan."""
        return bool(state.get("verify_need_action_replan"))


# --------------------------------------------------------------------------- #
# Graph-node helper
# --------------------------------------------------------------------------- #


async def replan_graph_node(
    state: dict[str, Any],
    *,
    handler: ReplanHandler,
    convergence_guard: Any | None = None,
) -> dict[str, Any]:
    """Graph node entry point for ``NODE_REPLAN``.

    This replaces the ISSUE-048 placeholder ``replan_node``.  It evaluates
    the replan count, transitions to REPLANNING (or escalates), and returns
    the state patches the graph needs to route correctly.

    Parameters
    ----------
    state:
        Current InvestigationState dict.
    handler:
        Configured ReplanHandler instance.
    convergence_guard:
        Optional ConvergenceGuard for recording replan steps (ISSUE-062).

    Returns
    -------
    dict
        State patches including ``replan_count``, ``escalated``, and
        ``event_status`` so the conditional edge after this node can route
        to PLANNER (continue) or REPORT (escalated).
    """
    event_id = str(state.get("event_id", "unknown"))
    current_count = int(state.get("replan_count", 0))

    # Type-safe extraction of failed_actions (ISSUE-062: guard against
    # non-iterable values in the state dict).
    raw_failed = state.get("verify_failed_actions")
    if raw_failed is None:
        failed_actions: list[str] = []
    elif isinstance(raw_failed, (list, tuple)):
        failed_actions = [str(a) for a in raw_failed]
    else:
        logger.warning(
            "replan_graph_node: unexpected type for verify_failed_actions: %s",
            type(raw_failed).__name__,
        )
        failed_actions = []

    # Record replan step in convergence guard (ISSUE-062).
    if convergence_guard is not None:
        try:
            await convergence_guard.record_step(event_id, "replan")
        except Exception:
            logger.exception(
                "ConvergenceGuard.record_step('replan') failed for event=%s",
                event_id,
            )

    result = await handler.execute_replan(
        event_id,
        current_replan_count=current_count,
        failed_actions=failed_actions,
    )

    if result.decision is ReplanDecision.ESCALATE:
        has_partial = bool(state.get("verify_has_partial_success"))
        esc = await handler.escalate(
            event_id,
            has_partial_success=has_partial,
            failed_actions=failed_actions,
        )
        return {
            "event_status": esc.target_status.value,
            "replan_count": current_count,
            "escalated": True,
            "halted": False,
        }

    # Continue: the graph edge NODE_REPLAN → NODE_PLANNER takes over.
    return {
        "event_status": EventStatus.REPLANNING.value,
        "replan_count": result.replan_count,
        "escalated": False,
        "halted": False,
    }


__all__ = [
    "EscalationResult",
    "ReplanDecision",
    "ReplanHandler",
    "ReplanResult",
    "replan_graph_node",
]
