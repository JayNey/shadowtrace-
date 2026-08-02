"""KnowledgeQueryPlan resolution tests (ISSUE-128 / #634)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import Settings
from app.models.knowledge_release import (
    ATTACK_CORPUS_ID,
    ATTACK_SOURCE_ID,
    KnowledgeImportStatus,
    KnowledgeRelease,
    KnowledgeReleaseLifecycleState,
    KnowledgeReleaseProvenance,
)
from app.services.knowledge_query_plan_service import resolve_active_knowledge_query_plan


def _active_release(
    *,
    vector_ready: bool = False,
    embedding_release_id: str | None = None,
) -> KnowledgeRelease:
    return KnowledgeRelease(
        release_id="krel-embed-pin-test",
        corpus_id=ATTACK_CORPUS_ID,
        source_id=ATTACK_SOURCE_ID,
        release_version="v15.1",
        content_hash="b" * 64,
        provenance=KnowledgeReleaseProvenance(source_path="fixture://embed"),
        import_status=KnowledgeImportStatus.VALIDATED,
        lifecycle_state=KnowledgeReleaseLifecycleState.ACTIVE,
        vector_ready=vector_ready,
        embedding_release_id=embedding_release_id,
        idempotency_key=f"{ATTACK_CORPUS_ID}:{'b' * 64}",
    )


@pytest.mark.asyncio
async def test_resolve_active_plan_uses_release_embedding_when_vector_ready() -> None:
    service = MagicMock()
    service.get_active_release = AsyncMock(
        return_value=_active_release(
            vector_ready=True,
            embedding_release_id="emb-bound-to-release",
        )
    )
    settings = Settings(EMBEDDING_MODE="mock", EMBEDDING_RELEASE_ID="emb-from-settings")

    plan = await resolve_active_knowledge_query_plan(
        service,
        settings,
        trace_id="trace-embed-pin",
    )

    assert plan is not None
    assert plan.embedding_release_id == "emb-bound-to-release"


@pytest.mark.asyncio
async def test_resolve_active_plan_uses_settings_embedding_when_not_vector_ready() -> None:
    service = MagicMock()
    service.get_active_release = AsyncMock(
        return_value=_active_release(vector_ready=False, embedding_release_id=None)
    )
    settings = Settings(EMBEDDING_MODE="mock", EMBEDDING_RELEASE_ID="emb-from-settings")

    plan = await resolve_active_knowledge_query_plan(
        service,
        settings,
        trace_id="trace-rel-only",
    )

    assert plan is not None
    assert plan.embedding_release_id == "emb-from-settings"
