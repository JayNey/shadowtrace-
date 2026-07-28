"""Optional conversational event Q&A endpoint (ISSUE-076)."""

from __future__ import annotations

import logging
from typing import Annotated, Any, Protocol

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from app.api.v1.deps import _get_investigation_stack, get_event_service
from app.api.v1.errors import EventNotFoundError
from app.core.auth import CurrentPrincipal
from app.core.errors import DependencyUnavailableError
from app.services.decision_trace_service import DecisionTraceService
from app.services.event_qa_service import ChatAnswer, ChatHistoryItem, EventQAService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["chat"])
_event_qa_service: EventQAService | None = None


class _EventReader(Protocol):
    async def get_event(self, event_id: str) -> object | None: ...


class _QAService(Protocol):
    async def answer(
        self,
        event_id: str,
        question: str,
        history: list[ChatHistoryItem],
    ) -> ChatAnswer: ...


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1, max_length=2000)
    history: list[ChatHistoryItem] = Field(default_factory=list, max_length=10)


async def get_event_qa_service() -> EventQAService:
    """Build the optional Q&A service lazily so an unused route has no startup cost."""

    global _event_qa_service
    if _event_qa_service is None:
        stack: dict[str, Any] = await _get_investigation_stack()
        _event_qa_service = EventQAService(
            context_store=stack["context_store"],
            decision_trace_service=DecisionTraceService(stack["session_factory"]),
            llm_client=stack["llm_client"],
        )
    return _event_qa_service


@router.post("/events/{event_id}/chat", response_model=ChatAnswer)
async def event_chat(
    event_id: str,
    request: ChatRequest,
    principal: CurrentPrincipal,
    event_service: Annotated[_EventReader, Depends(get_event_service)],
    qa_service: Annotated[_QAService, Depends(get_event_qa_service)],
) -> ChatAnswer:
    """Answer an event-scoped question with validated source references."""

    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(
            f"event {event_id} not found",
            details={"event_id": event_id},
        )
    try:
        return await qa_service.answer(event_id, request.question, request.history)
    except Exception as exc:
        logger.warning("event Q&A unavailable event_id=%s: %s", event_id, exc, exc_info=True)
        raise DependencyUnavailableError(
            "event Q&A is temporarily unavailable",
            error_code="qa_unavailable",
            details={"event_id": event_id},
        ) from exc


__all__ = ["ChatRequest", "event_chat", "get_event_qa_service", "router"]
