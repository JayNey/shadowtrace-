"""Resolve request-scoped playbook KnowledgeQueryPlan (ISSUE-139 / #645)."""

from __future__ import annotations

import logging

from app.core.config import Settings
from app.core.embedding.release import build_embedding_release
from app.models.knowledge_release import KnowledgeQueryPlan
from app.models.playbook_release import PLAYBOOK_CORPUS_ID, PLAYBOOK_KB_NAME
from app.services.knowledge_query_plan_service import resolve_knowledge_query_plan
from app.services.playbook_release_service import PlaybookReleaseService

logger = logging.getLogger(__name__)


async def resolve_active_playbook_query_plan(
    service: PlaybookReleaseService,
    settings: Settings,
    *,
    trace_id: str,
    tenant_id: str = "",
    principal: str = "",
) -> KnowledgeQueryPlan | None:
    active = await service.get_active_release()
    if active is None:
        logger.debug("no active playbook release for corpus=%s", PLAYBOOK_CORPUS_ID)
        return None
    embedding_release_id = active.embedding_release_id
    if not embedding_release_id:
        embedding_release_id = build_embedding_release(settings).release_id
    return resolve_knowledge_query_plan(
        corpus_id=PLAYBOOK_CORPUS_ID,
        active_release_id=active.release_id,
        embedding_release_id=embedding_release_id,
        trace_id=trace_id,
        kb_name=PLAYBOOK_KB_NAME,
        tenant_id=tenant_id,
        principal=principal,
    )


__all__ = ["resolve_active_playbook_query_plan"]
