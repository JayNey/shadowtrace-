"""Attack-storyline timeline endpoint (ISSUE-070)."""

from __future__ import annotations

from typing import Annotated, Protocol

from fastapi import APIRouter, Depends

from app.api.v1.deps import _get_context_store, get_event_service
from app.api.v1.errors import EventNotFoundError, ResourceNotFoundError
from app.core.auth import CurrentPrincipal
from app.models.agent_io import AttackStoryline
from app.models.context import EventContext

router = APIRouter()


class _EventReader(Protocol):
    async def get_event(self, event_id: str) -> object | None: ...


class _ContextReader(Protocol):
    async def get_full_context(self, event_id: str) -> EventContext: ...


@router.get("/events/{event_id}/timeline", response_model=AttackStoryline)
async def get_timeline(
    event_id: str,
    principal: CurrentPrincipal,
    event_service: Annotated[_EventReader, Depends(get_event_service)],
    context_store: Annotated[_ContextReader, Depends(_get_context_store)],
) -> AttackStoryline:
    """Return the generated attack storyline stored in ``EventContext``."""

    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(
            f"event {event_id} not found",
            details={"event_id": event_id},
        )

    try:
        context = await context_store.get_full_context(event_id)
    except KeyError as exc:
        # The event may have been deleted between the existence check and the
        # context read, or its context may not have been initialized yet.
        # Both cases mean that no storyline is currently available to clients.
        raise ResourceNotFoundError(
            f"storyline for event {event_id} is not ready",
            error_code="storyline_not_ready",
            details={"event_id": event_id},
        ) from exc
    storyline = context.storyline
    if storyline is None:
        raise ResourceNotFoundError(
            f"storyline for event {event_id} is not ready",
            error_code="storyline_not_ready",
            details={"event_id": event_id},
        )

    return AttackStoryline.model_validate(storyline)
