"""Off-critical-path LLM storyline refine (after rule persist)."""

from __future__ import annotations

import asyncio
import logging

from app.core.celery_app import celery_app
from app.services.storyline_service import STORYLINE_REFINE_TASK

logger = logging.getLogger(__name__)


def _release_loop_resources() -> None:
    from app.api.v1.deps import (
        reset_investigation_stack_cache,
        reset_loop_bound_redis_resources,
    )

    reset_investigation_stack_cache()
    reset_loop_bound_redis_resources()


async def _refine_storyline(event_id: str) -> None:
    from app.api.v1.deps import _get_context_store, _get_investigation_stack

    stack = await _get_investigation_stack()
    context_store = _get_context_store()
    context = await context_store.get_full_context(event_id)
    service = stack["storyline_service"]
    await service.generate(context.model_dump(mode="json"), defer_llm=False)


@celery_app.task(  # type: ignore[untyped-decorator]
    name=STORYLINE_REFINE_TASK,
    acks_late=True,
    soft_time_limit=180,
    queue="investigation",
)
def refine_storyline(event_id: str) -> dict[str, str]:
    """Replace the rule storyline with an LLM version when the provider is up."""
    try:
        asyncio.run(_refine_storyline(event_id))
    except Exception:
        logger.warning("storyline refine failed event=%s", event_id, exc_info=True)
        return {"event_id": event_id, "status": "failed"}
    finally:
        _release_loop_resources()
    return {"event_id": event_id, "status": "ok"}


__all__ = ["refine_storyline"]
