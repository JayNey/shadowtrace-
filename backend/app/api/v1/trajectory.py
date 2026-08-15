"""Trajectory analysis API (ISSUE-066)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import get_event_service
from app.api.v1.errors import EventNotFoundError
from app.core.auth import ReadPrincipal
from app.core.errors import DependencyUnavailableError
from app.models.trajectory import TrajectoryReport
from app.services.trajectory_analyzer import TrajectoryAnalyzer

if TYPE_CHECKING:
    from app.services.event_service import EventService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["trajectory"])


def _try_get_session_factory() -> async_sessionmaker[AsyncSession] | None:
    """Return the session factory, or None if DB is unavailable."""
    try:
        from app.api.v1.deps import _get_session_factory

        return _get_session_factory()
    except (ImportError, ModuleNotFoundError):
        logger.warning("Database session factory unavailable — trajectory store down")
        return None
    except (ValueError, TypeError):
        raise
    except (ConnectionRefusedError, TimeoutError, OSError):
        logger.warning("Database session factory unavailable (transient)", exc_info=True)
        return None


@router.get(
    "/events/{event_id}/trajectory",
    response_model=TrajectoryReport,
)
async def get_trajectory(
    event_id: str,
    principal: ReadPrincipal,
    event_service: EventService = Depends(get_event_service),
) -> TrajectoryReport:
    """Return structured trajectory quality metrics for *event_id*."""
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    sf = _try_get_session_factory()
    if sf is None:
        raise DependencyUnavailableError(
            message="trajectory store unavailable",
            error_code="dependency_unavailable",
            details={"event_id": event_id, "dependency": "postgres"},
        )

    try:
        analyzer = TrajectoryAnalyzer(sf)
        return await analyzer.analyze(event_id)
    except (SQLAlchemyError, OSError) as exc:
        logger.warning("Trajectory analysis unavailable for %s: %s", event_id, exc, exc_info=True)
        raise DependencyUnavailableError(
            message="trajectory store unavailable",
            error_code="dependency_unavailable",
            details={"event_id": event_id, "dependency": "postgres"},
        ) from exc
