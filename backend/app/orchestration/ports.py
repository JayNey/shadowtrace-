"""Shared protocol ports for orchestration components (ISSUE-062).

Extracted from the per-file private ``_StateMachinePort`` definitions in
``workflow_graph.py``, ``replan_handler.py``, and ``writeback_recovery_handler.py``
which had diverged — ``workflow_graph.py`` was missing ``get_current_status``,
causing mypy protocol-incompatibility errors when the port was passed to
``WritebackRecoveryHandler``.
"""

from __future__ import annotations

from typing import Any, Protocol

from app.models.enums import EventStatus
from app.models.workflow import TransitionContext


class StateMachinePort(Protocol):
    """Unified state-machine port for graph nodes and handlers.

    ``transition`` persists a status change; ``get_current_status`` reads
    the authoritative current status from the DB row (used by writeback
    recovery to guard against stale in-memory state).
    """

    async def transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: TransitionContext | None = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> Any: ...

    async def get_current_status(self, event_id: str) -> EventStatus: ...


__all__ = ["StateMachinePort"]
