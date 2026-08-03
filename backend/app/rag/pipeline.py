"""RetrievalPipeline: full RAG pipeline orchestrator (ISSUE-045, ISSUE-130 / #636)."""

from __future__ import annotations

import logging
import time
from dataclasses import replace

from app.core.config import Settings, get_settings
from app.core.embedding.release import build_embedding_release
from app.core.telemetry import traced_operation
from app.models.knowledge import RetrievalResult, RetrievedChunk
from app.models.knowledge_release import KnowledgeQueryPlanHints
from app.rag.citation_tracer import CitationTracer
from app.rag.context import RetrievalContext
from app.rag.hybrid_retriever import HybridRetriever
from app.rag.query_rewriter import QueryRewriter
from app.rag.reranker import Reranker
from app.rag.rrf_fusion import rrf_fuse
from app.services.knowledge_query_plan_validator import validate_knowledge_query_plan

logger = logging.getLogger(__name__)

_PLAN_REJECTED = "knowledge_query_plan_rejected"


class RetrievalPipeline:
    """Wire query rewriting → plan validation → hybrid retrieval → RRF → rerank → citation.

    Each non-retrieval step that fails is recorded in ``degraded_steps`` and the
    pipeline continues with the best available intermediate results.  Plan validation
    and all-retrieval-empty outcomes fail closed without widening scope.

    #636 Phase A: release-pinned pre-filters apply only through this pipeline path
    with a validated ``KnowledgeQueryPlan``. Direct ``KnowledgeStore.hybrid_search`` /
    ``vector_search_query`` callers bypass plan validation until #644 production wiring.
    Graph retrieval is out of scope for Phase A (vector + keyword only).
    """

    def __init__(
        self,
        rewriter: QueryRewriter,
        retriever: HybridRetriever,
        reranker: Reranker,
        *,
        settings: Settings | None = None,
    ) -> None:
        self._rewriter = rewriter
        self._retriever = retriever
        self._reranker = reranker
        self._settings = settings

    async def retrieve(
        self,
        query: str,
        kb_names: list[str],
        top_k: int = 5,
        *,
        context: RetrievalContext,
        plan_hints: KnowledgeQueryPlanHints | None = None,
    ) -> RetrievalResult:
        degraded: list[str] = []
        plan_hash = context.query_plan.plan_hash if context.query_plan else None

        with traced_operation(
            "retrieval_pipeline.retrieve",
            tenant_id=context.tenant_id,
            principal=context.principal,
            event_id=context.event_id,
            trace_id=context.trace_id,
            knowledge_release_id=(
                context.query_plan.active_release_id if context.query_plan else None
            ),
            embedding_release_id=(
                context.query_plan.embedding_release_id if context.query_plan else None
            ),
            knowledge_plan_hash=plan_hash or None,
        ) as span:
            started = time.perf_counter()
            result = await self._retrieve_impl(
                query,
                kb_names,
                top_k,
                context=context,
                degraded=degraded,
                plan_hints=plan_hints,
            )
            if span is not None:
                span.set_attribute("retrieval_result_count", len(result.chunks))
                span.set_attribute(
                    "retrieval_latency_ms",
                    int((time.perf_counter() - started) * 1000),
                )
            return result

    async def _retrieve_impl(
        self,
        query: str,
        kb_names: list[str],
        top_k: int,
        *,
        context: RetrievalContext,
        degraded: list[str],
        plan_hints: KnowledgeQueryPlanHints | None = None,
    ) -> RetrievalResult:
        active_context = context
        effective_top_k = top_k

        if context.query_plan is not None:
            if context.query_plan.kb_name not in kb_names:
                return RetrievalResult(
                    query=query,
                    rewritten_queries=[query],
                    chunks=[],
                    citations=[],
                    degraded_steps=degraded + [_PLAN_REJECTED, "plan_kb_not_in_scope"],
                    knowledge_query_plan={
                        "rejected_reasons": ["plan_kb_not_in_scope"],
                        "sanitized_plan_hash": "",
                    },
                )
            if set(kb_names) != {context.query_plan.kb_name}:
                return RetrievalResult(
                    query=query,
                    rewritten_queries=[query],
                    chunks=[],
                    citations=[],
                    degraded_steps=degraded + [_PLAN_REJECTED, "plan_kb_scope_mismatch"],
                    knowledge_query_plan={
                        "rejected_reasons": ["plan_kb_scope_mismatch"],
                        "sanitized_plan_hash": "",
                    },
                )
            cfg = self._settings or get_settings()
            active_embedding_release_id = build_embedding_release(cfg).release_id
            outcome = validate_knowledge_query_plan(
                context.query_plan,
                tenant_id=context.tenant_id,
                principal=context.principal,
                kb_names=kb_names,
                active_embedding_release_id=active_embedding_release_id,
                hints=plan_hints,
            )
            if not outcome.accepted:
                return RetrievalResult(
                    query=query,
                    rewritten_queries=[query],
                    chunks=[],
                    citations=[],
                    degraded_steps=degraded + [_PLAN_REJECTED, *outcome.rejected_reasons],
                    knowledge_query_plan={
                        "rejected_reasons": outcome.rejected_reasons,
                        "sanitized_plan_hash": outcome.sanitized_plan_hash,
                    },
                )
            if outcome.plan is not None:
                active_context = replace(context, query_plan=outcome.plan)
                effective_top_k = min(top_k, outcome.plan.budget.top_k)
                if outcome.degraded_reasons:
                    degraded.extend(outcome.degraded_reasons)

        # Step 1: Query rewriting
        rewritten: list[str]
        try:
            rewritten = await self._rewriter.rewrite(query, context=active_context)
        except Exception as exc:
            logger.warning("Query rewriting failed: %s", exc)
            degraded.append("query_rewriter")
            rewritten = [query]

        # Step 2: Hybrid retrieval (per query, per kb, vector + keyword).
        result_lists = await self._retriever.retrieve(
            rewritten, kb_names, top_k=effective_top_k, context=active_context
        )

        # If all lists are empty, return empty
        if not any(result_lists):
            plan_payload = (
                active_context.query_plan.model_dump(mode="json")
                if active_context.query_plan is not None
                else None
            )
            return RetrievalResult(
                query=query,
                rewritten_queries=rewritten,
                chunks=[],
                citations=[],
                degraded_steps=degraded,
                knowledge_query_plan=plan_payload,
            )

        # Step 3: RRF fusion
        fused: list[RetrievedChunk] = rrf_fuse(result_lists, k=60)

        # Step 4: Rerank
        reranked: list[RetrievedChunk]
        try:
            reranked = await self._reranker.rerank(query, fused, effective_top_k)
        except Exception as exc:
            logger.warning("Reranking failed, using RRF order: %s", exc)
            degraded.append("reranker")
            reranked = fused[:effective_top_k]
            reranked = _ensure_normalized(reranked)

        # Step 5: Citations
        citations = CitationTracer.generate(query, reranked)

        plan_payload = (
            active_context.query_plan.model_dump(mode="json")
            if active_context.query_plan is not None
            else None
        )

        return RetrievalResult(
            query=query,
            rewritten_queries=rewritten,
            chunks=reranked,
            citations=citations,
            degraded_steps=degraded,
            knowledge_query_plan=plan_payload,
        )


def _ensure_normalized(chunks: list[RetrievedChunk]) -> list[RetrievedChunk]:
    """Re-normalize chunk scores to [0, 1] when reranker was skipped."""
    if not chunks:
        return chunks
    scores = [c.score for c in chunks]
    max_s = max(scores)
    min_s = min(scores)
    rng = max_s - min_s if max_s != min_s else 1.0
    result: list[RetrievedChunk] = []
    for c in chunks:
        norm_score = (c.score - min_s) / rng if rng > 0 else 1.0
        result.append(
            RetrievedChunk(
                chunk_id=c.chunk_id,
                kb_name=c.kb_name,
                content=c.content,
                metadata=c.metadata,
                score=norm_score,
                retrieval_method=c.retrieval_method,
                raw_rrf_score=c.raw_rrf_score,
            )
        )
    return result
