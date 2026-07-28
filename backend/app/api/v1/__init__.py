"""API v1 router package."""

from fastapi import APIRouter

from app.api.v1 import (
    actions,
    chat,
    connectors,
    dispositions,
    events,
    execution_jobs,
    graph,
    health,
    knowledge,
    source_records,
    stats,
    timeline,
    tools,
    trajectory,
)
from app.core.config import get_settings


def create_api_router(*, include_chat: bool = True) -> APIRouter:
    """Build the v1 router; chat can be disabled without touching core routes."""

    router = APIRouter()
    router.include_router(health.router)
    router.include_router(events.router)
    router.include_router(actions.router)
    router.include_router(source_records.router)
    router.include_router(connectors.router)
    router.include_router(dispositions.router)
    router.include_router(execution_jobs.router)
    router.include_router(tools.router)
    router.include_router(knowledge.router)
    router.include_router(stats.router)
    router.include_router(trajectory.router)
    router.include_router(timeline.router)
    router.include_router(graph.router)
    if include_chat:
        router.include_router(chat.router)
    return router


api_router = create_api_router(include_chat=get_settings().event_chat_enabled)
