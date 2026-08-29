"""HybridRetriever: concurrent vector + keyword retrieval across KBs (ISSUE-045)."""

from __future__ import annotations

import asyncio
import logging

from app.core.embedding.base import EmbeddingError
from app.core.embedding.service import EmbeddingService
from app.models.knowledge import RetrievedChunk
from app.rag.context import RetrievalContext
from app.rag.event_type_filter import storage_event_type_equals
from app.rag.keyword_aliases import keyword_queries_for_kb
from app.services.knowledge_store import KnowledgeStore

logger = logging.getLogger(__name__)

_FP_FETCH_K_FLOOR = 16


def fetch_k_for_kb(
    kb_name: str,
    top_k: int,
    *,
    max_candidates: int | None = None,
) -> int:
    """Per-KB candidate fetch size. fp_case_kb floors at 16; others stay top_k*2."""
    fetch_k = top_k * 2
    if kb_name == "fp_case_kb":
        fetch_k = max(fetch_k, _FP_FETCH_K_FLOOR)
    if max_candidates is not None:
        fetch_k = min(fetch_k, max_candidates)
    return fetch_k


class HybridRetriever:
    """For each query variant, run vector + keyword search concurrently across KBs.

    Each search path fetches ``top_k * 2`` candidates; the separate result lists
    are fed into RRF fusion downstream.
    """

    def __init__(self, store: KnowledgeStore, embed_service: EmbeddingService) -> None:
        self._store = store
        self._embed = embed_service
        self.vector_unavailable = False
        self.keyword_unavailable = False

    async def retrieve(
        self,
        queries: list[str],
        kb_names: list[str],
        top_k: int = 5,
        *,
        context: RetrievalContext,
    ) -> list[list[RetrievedChunk]]:
        """Return one result list per (query, kb, method[, keyword variant]).

        Order: for each query, for each kb, vector then each keyword variant.
        Empty keyword reductions are skipped (no ``plainto_tsquery``).
        """
        self.vector_unavailable = False
        self.keyword_unavailable = False
        tenant_id = context.tenant_id
        logger.debug(
            "HybridRetriever tenant=%s event=%s kb_count=%d query_count=%d",
            tenant_id,
            context.event_id,
            len(kb_names),
            len(queries),
        )

        tasks: list[asyncio.Task[list[RetrievedChunk]]] = []
        for query in queries:
            for kb in kb_names:
                fetch_k = fetch_k_for_kb(
                    kb,
                    top_k,
                    max_candidates=(
                        context.query_plan.budget.max_candidates
                        if context.query_plan is not None
                        else None
                    ),
                )

                async def _vector_search(
                    query: str = query,
                    kb: str = kb,
                    fetch_k: int = fetch_k,
                ) -> list[RetrievedChunk]:
                    release_id, embedding_release_id, typed_filters = (
                        context.storage_filters_for_kb(kb)
                    )
                    try:
                        vec = await self._embed.embed_query(query)
                    except EmbeddingError as exc:
                        logger.warning(
                            "vector search unavailable kb=%s tenant=%s: %s",
                            kb,
                            tenant_id,
                            exc,
                        )
                        self.vector_unavailable = True
                        return []
                    try:
                        return await self._store.vector_search(
                            kb,
                            vec,
                            top_k=fetch_k,
                            tenant_id=tenant_id,
                            release_id=release_id,
                            embedding_release_id=embedding_release_id,
                            typed_filters=typed_filters,
                            event_type_equals=storage_event_type_equals(
                                kb, context.event_type
                            ),
                        )
                    except Exception as exc:
                        logger.warning(
                            "vector search failed kb=%s tenant=%s: %s",
                            kb,
                            tenant_id,
                            exc,
                        )
                        self.vector_unavailable = True
                        return []

                async def _keyword_search(
                    keyword_query: str,
                    kb: str = kb,
                    fetch_k: int = fetch_k,
                ) -> list[RetrievedChunk]:
                    release_id, embedding_release_id, typed_filters = (
                        context.storage_filters_for_kb(kb)
                    )
                    try:
                        return await self._store.keyword_search(
                            kb,
                            keyword_query,
                            top_k=fetch_k,
                            tenant_id=tenant_id,
                            release_id=release_id,
                            embedding_release_id=embedding_release_id,
                            typed_filters=typed_filters,
                            event_type_equals=storage_event_type_equals(
                                kb, context.event_type
                            ),
                        )
                    except Exception as exc:
                        logger.warning(
                            "keyword search failed kb=%s tenant=%s: %s",
                            kb,
                            tenant_id,
                            exc,
                        )
                        self.keyword_unavailable = True
                        return []

                tasks.append(asyncio.create_task(_vector_search()))
                for keyword_query in keyword_queries_for_kb(kb, query, limit=2):
                    tasks.append(asyncio.create_task(_keyword_search(keyword_query)))

        results: list[list[RetrievedChunk]] = []
        for task in tasks:
            try:
                results.append(await task)
            except Exception:
                self.keyword_unavailable = True
                results.append([])
        return results
