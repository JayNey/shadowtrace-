"""Authoritative persistence for ``analysis_only_complete`` (ISSUE-266 / ID-REL-002).

Journal + durable snapshot must agree before CLOSED snapshot refresh; Redis is
rebuildable and failures are surfaced via degraded flags.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any, Protocol

from app.core.errors import DependencyUnavailableError
from app.models.enums import EventStatus

logger = logging.getLogger(__name__)


class _ContextStorePort(Protocol):
    async def set(self, event_id: str, key: str, value: Any, version: int | None = None) -> Any: ...

    async def set_analysis_only_complete(
        self,
        event_id: str,
        complete: bool = True,
    ) -> Any: ...

    async def get(self, event_id: str, key: str) -> Any: ...

    async def refresh_closed_snapshot(self, event_id: str) -> Any: ...


class _EventServicePort(Protocol):
    async def get_event(self, event_id: str) -> Any: ...

    async def merge_analysis_only_complete_context_snapshot(
        self,
        event_id: str,
        complete: bool,
    ) -> None: ...


class _DegradedFlagsPort(Protocol):
    async def set_flag(
        self,
        event_id: str,
        flag_name: str,
        value: Any,
        *,
        writer: str,
    ) -> Any: ...


async def persist_analysis_only_complete_authoritative(
    event_id: str,
    *,
    context_store: _ContextStorePort | None,
    event_service: _EventServicePort | None = None,
    degraded_flags: _DegradedFlagsPort | None = None,
    writer: str = "AnalysisOnlyCompletePersistence",
    refresh_closed_snapshot: bool = True,
) -> bool:
    """Persist ``analysis_only_complete=true`` to journal and durable snapshot.

    Monotonic: never downgrades an existing ``true`` journal value. When the
    event is already CLOSED, optionally refresh the frozen snapshot from
    journal so rebuild paths converge on durable truth.
    """
    if context_store is None:
        raise DependencyUnavailableError(
            "analysis_only_complete persistence requires context_store"
        )

    atomic_set = getattr(context_store, "set_analysis_only_complete", None)
    if not inspect.iscoroutinefunction(atomic_set):
        atomic_set = None
    already_true = False
    durable_ok = False
    redis_ok = True
    used_atomic_store = atomic_set is not None

    if atomic_set is not None:
        try:
            result = await atomic_set(event_id, True)
            durable_ok = True
            redis_ok = bool(getattr(result, "redis_ok", True))
        except Exception:
            logger.warning(
                "failed to atomically persist analysis_only_complete event=%s",
                event_id,
                exc_info=True,
            )
            durable_ok = False
    else:
        try:
            current = await context_store.get(event_id, "analysis_only_complete")
            already_true = current is True
        except Exception:
            logger.debug(
                "analysis_only_complete read failed event=%s",
                event_id,
                exc_info=True,
            )

        durable_ok = already_true
        if not already_true:
            try:
                result = await context_store.set(
                    event_id,
                    "analysis_only_complete",
                    True,
                )
                durable_ok = True
                redis_ok = bool(getattr(result, "redis_ok", True))
            except Exception:
                logger.warning(
                    "failed to persist analysis_only_complete journal event=%s",
                    event_id,
                    exc_info=True,
                )
                durable_ok = False

    if not redis_ok and degraded_flags is not None:
        try:
            await degraded_flags.set_flag(
                event_id,
                "redis_context_unavailable",
                True,
                writer=writer,
            )
        except Exception:
            logger.warning(
                "failed to record redis_context_unavailable event=%s",
                event_id,
                exc_info=True,
            )

    if not used_atomic_store and event_service is not None:
        try:
            await event_service.merge_analysis_only_complete_context_snapshot(
                event_id,
                True,
            )
        except Exception:
            logger.warning(
                "failed to merge analysis_only_complete snapshot event=%s",
                event_id,
                exc_info=True,
            )
            # Non-atomic path: journal alone is insufficient without durable snapshot.
            durable_ok = False

    if durable_ok and refresh_closed_snapshot and event_service is not None:
        try:
            event = await event_service.get_event(event_id)
            if event is not None and getattr(event, "status", None) is EventStatus.CLOSED:
                await context_store.refresh_closed_snapshot(event_id)
        except Exception:
            logger.warning(
                "failed to refresh CLOSED snapshot after analysis_only_complete event=%s",
                event_id,
                exc_info=True,
            )

    if not durable_ok:
        raise DependencyUnavailableError("failed to durably persist analysis_only_complete")
    return durable_ok


__all__ = ["persist_analysis_only_complete_authoritative"]
