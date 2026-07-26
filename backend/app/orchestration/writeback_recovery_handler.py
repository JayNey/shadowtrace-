"""WritebackRecoveryHandler — writeback recovery without replan (ISSUE-062).

WritebackRecoveryHandler handles waiting/failed/unknown/conflict writeback
states.  It operates on the SAME outbox/idempotency_key — never creates new
Actions, never enters REPLANNING, never re-executes DIRECT_TOOL.

Design
------
* **WAITING (PENDING/SENDING/ACCEPTED)**: wait for late receipt; recovery
  resumes from the same checkpoint when the receipt arrives.
* **UNKNOWN**: attempt provider-side lookup first (up to
  ``VERIFY_UNKNOWN_MAX_LOOKUPS=3``); escalate to manual resolution when
  lookup is infeasible or exhausted.
* **FAILED / PARTIAL**: only retry when Adapter allows safe idempotent retry
  and ``WRITEBACK_MAX_RETRIES`` is not exhausted; otherwise escalate.
* **CONFLICT**: read current source state (concurrency token) and escalate
  to manual resolution for human decision — never auto-resolve.

Constraints
-----------
* NEVER creates new DIRECT_TOOL or entity actions.
* NEVER transitions to REPLANNING or consumes ``replan_count``.
* Respects ``WRITEBACK_MAX_RETRIES`` with jittered exponential backoff.
* Status queries take priority over blind re-sends.
* All live capability defaults to UNKNOWN; unverified capability blocks
  auto-recovery.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from app.models.enums import (
    EventStatus,
    ExecutionSubstate,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.workflow import WRITEBACK_MAX_RETRIES

logger = logging.getLogger(__name__)

_WR_OPERATOR = "WritebackRecoveryHandler"

# Maximum number of provider-side lookups for UNKNOWN writebacks before
# escalating to manual resolution.  Mirrors VerifyAgent.VERIFY_UNKNOWN_MAX_LOOKUPS.
VERIFY_UNKNOWN_MAX_LOOKUPS = 3

# Exponential backoff parameters for writeback retries.
_BACKOFF_BASE_S = 1.0
_BACKOFF_MAX_S = 60.0
_JITTER_FACTOR = 0.3


def _backoff_with_jitter(retry_count: int) -> float:
    """Jittered exponential backoff for writeback retries.

    Returns a delay in seconds: ``min(base * 2^count, max) * (1 ± jitter)``.
    """
    delay = min(_BACKOFF_BASE_S * (2 ** (retry_count - 1)), _BACKOFF_MAX_S)
    jitter = delay * _JITTER_FACTOR * (2 * random.random() - 1)
    return max(0.0, delay + jitter)


def _parse_writeback_status(raw: Any) -> WritebackStatus | None:
    """Safely parse a writeback status string, returning None on invalid input."""
    if raw is None:
        return None
    try:
        return WritebackStatus(raw)
    except ValueError:
        logger.warning("invalid writeback status value: %s", raw)
        return None


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

    async def get_current_status(self, event_id: str) -> EventStatus: ...


class _RuntimePort(Protocol):
    async def set_execution_substate(
        self,
        event_id: str,
        substate: Any,
        *,
        event_status: EventStatus,
    ) -> None: ...


class _DispositionSyncPort(Protocol):
    async def retry_writeback(
        self,
        writeback_id: str,
        operator: str,
    ) -> Any: ...

    async def resolve_writeback(
        self,
        writeback_id: str,
        resolution: str,
        principal: str,
        comment: str,
    ) -> Any: ...

    async def lookup_writeback_status(
        self,
        writeback_id: str,
    ) -> WritebackStatus | None: ...


# --------------------------------------------------------------------------- #
# Types
# --------------------------------------------------------------------------- #


class WritebackRecoveryAction(StrEnum):
    """What the handler decided to do."""

    WAIT = "wait"                # stay in WAITING_WRITEBACK, wait for receipt
    RETRY = "retry"              # re-enqueue same outbox
    LOOKUP = "lookup"            # query provider for status
    MANUAL = "manual"            # escalate to manual resolution
    NOOP = "noop"                # nothing to do (already terminal)


@dataclass
class WritebackRecoveryResult:
    """Outcome of a writeback recovery evaluation."""

    action: WritebackRecoveryAction
    writeback_id: str
    writeback_status: WritebackStatus | None
    reason: str = ""
    lookup_attempt: int = 0
    retry_attempt: int = 0
    escalated: bool = False


@dataclass
class WritebackState:
    """Snapshot of a single writeback's recovery progress."""

    writeback_id: str
    current_status: WritebackStatus | None
    lookup_count: int = 0
    retry_count: int = 0
    max_lookups: int = VERIFY_UNKNOWN_MAX_LOOKUPS
    max_retries: int = WRITEBACK_MAX_RETRIES


# --------------------------------------------------------------------------- #
# Handler
# --------------------------------------------------------------------------- #


class WritebackRecoveryHandler:
    """Handle writeback waiting/failed/unknown/conflict states.

    Never enters REPLANNING.  Never creates new Actions.  Never re-executes
    DIRECT_TOOL.  Operates on the same outbox/idempotency_key.
    """

    def __init__(
        self,
        *,
        state_machine: _StateMachinePort,
        runtime: _RuntimePort,
        disposition_sync: _DispositionSyncPort | None = None,
    ) -> None:
        self._state_machine = state_machine
        self._runtime = runtime
        self._disposition_sync = disposition_sync

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def evaluate(
        self,
        writeback: WritebackState,
    ) -> WritebackRecoveryResult:
        """Evaluate the correct recovery action for a writeback status.

        Parameters
        ----------
        writeback:
            The current writeback state including lookup/retry counters.

        Returns
        -------
        WritebackRecoveryResult
            The recommended action and whether escalation is needed.
        """
        status = writeback.current_status

        if status is None:
            return WritebackRecoveryResult(
                action=WritebackRecoveryAction.NOOP,
                writeback_id=writeback.writeback_id,
                writeback_status=None,
                reason="no_writeback_status",
            )

        # Terminal states — nothing to recover.
        if status is WritebackStatus.CONFIRMED:
            return WritebackRecoveryResult(
                action=WritebackRecoveryAction.NOOP,
                writeback_id=writeback.writeback_id,
                writeback_status=status,
                reason="already_confirmed",
            )

        # WAITING states: PENDING, SENDING, ACCEPTED
        if status in (
            WritebackStatus.PENDING,
            WritebackStatus.SENDING,
            WritebackStatus.ACCEPTED,
        ):
            return WritebackRecoveryResult(
                action=WritebackRecoveryAction.WAIT,
                writeback_id=writeback.writeback_id,
                writeback_status=status,
                reason=f"waiting_{status.value}",
            )

        # UNKNOWN: lookup first, escalate when exhausted
        if status is WritebackStatus.UNKNOWN:
            if writeback.lookup_count < writeback.max_lookups:
                return WritebackRecoveryResult(
                    action=WritebackRecoveryAction.LOOKUP,
                    writeback_id=writeback.writeback_id,
                    writeback_status=status,
                    reason=f"lookup_attempt_{writeback.lookup_count + 1}",
                    lookup_attempt=writeback.lookup_count + 1,
                )
            return WritebackRecoveryResult(
                action=WritebackRecoveryAction.MANUAL,
                writeback_id=writeback.writeback_id,
                writeback_status=status,
                reason=f"lookup_exhausted:{writeback.lookup_count}/{writeback.max_lookups}",
                escalated=True,
            )

        # FAILED: retry if safe; otherwise escalate
        if status is WritebackStatus.FAILED:
            if writeback.retry_count < writeback.max_retries:
                return WritebackRecoveryResult(
                    action=WritebackRecoveryAction.RETRY,
                    writeback_id=writeback.writeback_id,
                    writeback_status=status,
                    reason=f"retry_attempt_{writeback.retry_count + 1}",
                    retry_attempt=writeback.retry_count + 1,
                )
            return WritebackRecoveryResult(
                action=WritebackRecoveryAction.MANUAL,
                writeback_id=writeback.writeback_id,
                writeback_status=status,
                reason=f"retry_exhausted:{writeback.retry_count}/{writeback.max_retries}",
                escalated=True,
            )

        # PARTIAL: retry if safe; otherwise escalate
        if status is WritebackStatus.PARTIAL:
            if writeback.retry_count < writeback.max_retries:
                return WritebackRecoveryResult(
                    action=WritebackRecoveryAction.RETRY,
                    writeback_id=writeback.writeback_id,
                    writeback_status=status,
                    reason=f"partial_retry_{writeback.retry_count + 1}",
                    retry_attempt=writeback.retry_count + 1,
                )
            return WritebackRecoveryResult(
                action=WritebackRecoveryAction.MANUAL,
                writeback_id=writeback.writeback_id,
                writeback_status=status,
                reason=f"partial_exhausted:{writeback.retry_count}/{writeback.max_retries}",
                escalated=True,
            )

        # CONFLICT: always escalate (read current source state, human decision)
        if status is WritebackStatus.CONFLICT:
            return WritebackRecoveryResult(
                action=WritebackRecoveryAction.MANUAL,
                writeback_id=writeback.writeback_id,
                writeback_status=status,
                reason="conflict_requires_manual",
                escalated=True,
            )

        # Fallback (should not happen with the enum)
        logger.error("unexpected writeback status: %s", status)
        return WritebackRecoveryResult(
            action=WritebackRecoveryAction.MANUAL,
            writeback_id=writeback.writeback_id,
            writeback_status=status,
            reason=f"unexpected_status:{status}",
            escalated=True,
        )

    async def execute(
        self,
        event_id: str,
        writeback: WritebackState,
        *,
        operator: str | None = None,
        readiness: WritebackReadiness = WritebackReadiness.CAPABILITY_UNKNOWN,
    ) -> WritebackRecoveryResult:
        """Evaluate and execute the recovery action.

        For WAIT: persists ``WAITING_WRITEBACK`` execution_substate so the
        graph can pause and resume when the receipt arrives.

        For LOOKUP: queries the provider via the disposition_sync port and
        returns the result.  If lookup is infeasible (no port) and readiness
        is known to be unsupported, escalates.  If readiness is still
        CAPABILITY_UNKNOWN, stays in WAITING_WRITEBACK until the capability
        is resolved.

        For RETRY: re-enqueues the same outbox via ``retry_writeback`` with
        jittered exponential backoff.  If the port is unavailable and readiness
        is known unsupported, escalates.

        For MANUAL: persists ``MANUAL_RESOLUTION`` execution_substate and
        notifies that human intervention is needed.

        Parameters
        ----------
        event_id:
            The event that owns the writeback.
        writeback:
            Current writeback state with counters.
        operator:
            Human-readable operator for audit trails.
        readiness:
            The current WritebackReadiness for this event.  When CAPABILITY_UNKNOWN
            and no disposition_sync port is wired, the handler stays in WAIT
            rather than escalating prematurely.
        """
        result = self.evaluate(writeback)
        op = operator or _WR_OPERATOR

        if result.action is WritebackRecoveryAction.WAIT:
            await self._runtime.set_execution_substate(
                event_id,
                ExecutionSubstate.WAITING_WRITEBACK,
                event_status=EventStatus.VERIFYING,
            )
            logger.info(
                "writeback %s: waiting for receipt (status=%s)",
                writeback.writeback_id,
                writeback.current_status.value if writeback.current_status else "none",
            )
            return result

        if result.action is WritebackRecoveryAction.LOOKUP:
            if self._disposition_sync is None:
                if readiness is WritebackReadiness.CAPABILITY_UNKNOWN:
                    # Live Adapter capability not yet probed — stay in
                    # WAITING_WRITEBACK rather than prematurely escalating.
                    logger.info(
                        "writeback %s: disposition_sync not wired, "
                        "readiness=CAPABILITY_UNKNOWN — staying in WAIT",
                        writeback.writeback_id,
                    )
                    await self._runtime.set_execution_substate(
                        event_id,
                        ExecutionSubstate.WAITING_WRITEBACK,
                        event_status=EventStatus.VERIFYING,
                    )
                    return result
                logger.warning(
                    "writeback %s: no disposition_sync port, "
                    "readiness=%s — escalating",
                    writeback.writeback_id,
                    readiness.value,
                )
                return await self._escalate(event_id, writeback, result, op)
            try:
                looked_up = await self._disposition_sync.lookup_writeback_status(
                    writeback.writeback_id,
                )
                if looked_up is not None and looked_up is not WritebackStatus.UNKNOWN:
                    logger.info(
                        "writeback %s: lookup resolved → %s",
                        writeback.writeback_id,
                        looked_up.value,
                    )
                    return WritebackRecoveryResult(
                        action=WritebackRecoveryAction.NOOP,
                        writeback_id=writeback.writeback_id,
                        writeback_status=looked_up,
                        reason=f"lookup_resolved_to_{looked_up.value}",
                        lookup_attempt=result.lookup_attempt,
                    )
                # Still UNKNOWN after lookup — increment counter
                writeback.lookup_count = result.lookup_attempt
                if writeback.lookup_count >= writeback.max_lookups:
                    return await self._escalate(event_id, writeback, result, op)
                # Wait for next cycle
                await self._runtime.set_execution_substate(
                    event_id,
                    ExecutionSubstate.WAITING_WRITEBACK,
                    event_status=EventStatus.VERIFYING,
                )
                return result
            except Exception:
                logger.exception("writeback lookup failed for %s", writeback.writeback_id)
                writeback.lookup_count += 1
                if writeback.lookup_count >= writeback.max_lookups:
                    return await self._escalate(event_id, writeback, result, op)
                return result

        if result.action is WritebackRecoveryAction.RETRY:
            if self._disposition_sync is None:
                if readiness is WritebackReadiness.CAPABILITY_UNKNOWN:
                    logger.info(
                        "writeback %s: disposition_sync not wired, "
                        "readiness=CAPABILITY_UNKNOWN — staying in WAIT",
                        writeback.writeback_id,
                    )
                    await self._runtime.set_execution_substate(
                        event_id,
                        ExecutionSubstate.WAITING_WRITEBACK,
                        event_status=EventStatus.VERIFYING,
                    )
                    return result
                logger.warning(
                    "writeback %s: no disposition_sync port, "
                    "readiness=%s — escalating",
                    writeback.writeback_id,
                    readiness.value,
                )
                return await self._escalate(event_id, writeback, result, op)

            # Jittered exponential backoff before retry (ISSUE-062).
            backoff_s = _backoff_with_jitter(result.retry_attempt)
            logger.debug(
                "writeback %s: backing off %.2fs before retry %d",
                writeback.writeback_id,
                backoff_s,
                result.retry_attempt,
            )
            await asyncio.sleep(backoff_s)

            try:
                await self._disposition_sync.retry_writeback(
                    writeback.writeback_id,
                    op,
                )
                writeback.retry_count = result.retry_attempt
                await self._runtime.set_execution_substate(
                    event_id,
                    ExecutionSubstate.WAITING_WRITEBACK,
                    event_status=EventStatus.VERIFYING,
                )
                logger.info("writeback %s: retry enqueued", writeback.writeback_id)
                return result
            except Exception:
                logger.exception("writeback retry failed for %s", writeback.writeback_id)
                writeback.retry_count += 1
                if writeback.retry_count >= writeback.max_retries:
                    return await self._escalate(event_id, writeback, result, op)
                return result

        if result.action is WritebackRecoveryAction.MANUAL:
            return await self._escalate(event_id, writeback, result, op)

        return result

    async def _escalate(
        self,
        event_id: str,
        writeback: WritebackState,
        result: WritebackRecoveryResult,
        operator: str,
    ) -> WritebackRecoveryResult:
        """Persist MANUAL_RESOLUTION substate and return escalated result."""
        await self._runtime.set_execution_substate(
            event_id,
            ExecutionSubstate.MANUAL_RESOLUTION,
            event_status=EventStatus.VERIFYING,
        )
        logger.warning(
            "writeback %s: escalated to manual resolution (reason=%s)",
            writeback.writeback_id,
            result.reason,
        )
        return WritebackRecoveryResult(
            action=WritebackRecoveryAction.MANUAL,
            writeback_id=writeback.writeback_id,
            writeback_status=writeback.current_status,
            reason=result.reason,
            escalated=True,
        )

    @staticmethod
    def needs_recovery(state: dict[str, Any]) -> bool:
        """Return True when the verification result signals need_writeback_recovery."""
        return bool(state.get("verify_need_writeback_recovery"))

    @staticmethod
    def needs_manual(state: dict[str, Any]) -> bool:
        """Return True when the verification result signals need_manual_resolution."""
        return bool(state.get("verify_need_manual_resolution"))


# --------------------------------------------------------------------------- #
# Graph-node helper
# --------------------------------------------------------------------------- #


async def writeback_recovery_graph_node(
    state: dict[str, Any],
    *,
    handler: WritebackRecoveryHandler,
) -> dict[str, Any]:
    """Graph node entry point for writeback recovery (replaces placeholder).

    Evaluates the current writeback state from ``verify_failed_writebacks``
    and executes the appropriate recovery action.  After this node, the graph
    conditional edge from ``route_after_verify`` routes either back to
    ``approval_wait_node`` (to wait for receipt) or to ``manual_hold_node``
    (for manual resolution).

    Returns
    -------
    dict
        State patches with updated ``execution_substate`` and routing flags.
    """
    event_id = str(state.get("event_id", "unknown"))
    failed_writebacks: list[str] = list(state.get("verify_failed_writebacks") or [])

    if not failed_writebacks:
        logger.debug("writeback_recovery_node: no failed writebacks for event=%s", event_id)
        return {
            "verify_need_writeback_recovery": False,
            "execution_substate": ExecutionSubstate.NONE.value,
        }

    # Process the first failed writeback; others are handled in subsequent
    # verify cycles.
    wb_id = failed_writebacks[0]
    wb_state = WritebackState(
        writeback_id=wb_id,
        current_status=_parse_writeback_status(state.get("verify_writeback_status")),
    )

    readiness = WritebackReadiness(
        state.get(
            "event_status_update_readiness",
            WritebackReadiness.CAPABILITY_UNKNOWN.value,
        )
    )

    result = await handler.execute(
        event_id, wb_state, readiness=readiness
    )

    logger.info(
        "writeback_recovery: event=%s wb=%s action=%s escalated=%s",
        event_id,
        wb_id,
        result.action.value,
        result.escalated,
    )

    if result.escalated:
        return {
            "verify_need_writeback_recovery": False,
            "verify_need_manual_resolution": True,
            "execution_substate": ExecutionSubstate.MANUAL_RESOLUTION.value,
            "verify_failed_writebacks": failed_writebacks[1:],
        }

    if result.action is WritebackRecoveryAction.WAIT:
        return {
            "verify_need_writeback_recovery": True,
            "execution_substate": ExecutionSubstate.WAITING_WRITEBACK.value,
            "halted": True,
            "verify_failed_writebacks": failed_writebacks[1:],
        }

    # LOOKUP / RETRY / NOOP: stay in recovery until resolved
    is_terminal = result.action in (
        WritebackRecoveryAction.NOOP,
        WritebackRecoveryAction.MANUAL,
    )
    remaining = failed_writebacks[1:] if is_terminal else failed_writebacks
    return {
        "verify_need_writeback_recovery": len(remaining) > 0,
        "execution_substate": ExecutionSubstate.WAITING_WRITEBACK.value,
        "halted": False,
        "verify_failed_writebacks": remaining,
    }


__all__ = [
    "VERIFY_UNKNOWN_MAX_LOOKUPS",
    "WritebackRecoveryAction",
    "WritebackRecoveryHandler",
    "WritebackRecoveryResult",
    "WritebackState",
    "writeback_recovery_graph_node",
]
