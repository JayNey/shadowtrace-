"""RetrievalPipeline: full RAG pipeline orchestrator (ISSUE-045, ISSUE-130 / #636)."""

from __future__ import annotations

import logging
import time
from dataclasses import replace
from typing import Any

from app.core.config import Settings, get_settings
from app.core.embedding.release import build_embedding_release
from app.core.telemetry import traced_operation
from app.models.knowledge import (
    ORG_CONTEXT_KB_NAME,
    RetrievalMetrics,
    RetrievalResult,
    RetrievedChunk,
)
from app.models.knowledge_release import KnowledgeQueryPlanHints
from app.rag.citation_tracer import CitationTracer
from app.rag.constraint_rrf import c_rrf_fuse
from app.rag.context import RetrievalContext
from app.rag.hybrid_retriever import HybridRetriever
from app.rag.query_rewrite_policy import should_skip_query_rewrite
from app.rag.query_rewriter import QueryRewriter
from app.rag.reranker import Reranker
from app.rag.retrieval_router import decide_retrieval_action, should_short_circuit_org_exact
from app.rag.rrf_fusion import rrf_fuse
from app.services.knowledge_query_plan_validator import validate_knowledge_query_plan
from app.services.org_context_matcher import (
    OrgContextMatcher,
    facts_from_query,
    hits_to_retrieved_chunks,
    list_org_context_chunks,
)

logger = logging.getLogger(__name__)

_PLAN_REJECTED = "knowledge_query_plan_rejected"
_RELEASE_PINNED_KBS = frozenset({"attack_kb", "playbook_kb"})


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
            wall_ms = (time.perf_counter() - started) * 1000.0
            metrics = result.retrieval_metrics or RetrievalMetrics()
            if metrics.total_ms <= 0:
                metrics = metrics.model_copy(update={"total_ms": wall_ms})
                result = result.model_copy(update={"retrieval_metrics": metrics})
            if span is not None:
                span.set_attribute("retrieval_result_count", len(result.chunks))
                span.set_attribute("retrieval_latency_ms", int(metrics.total_ms))
                span.set_attribute("rag.rewrite_ms", int(metrics.rewrite_ms))
                span.set_attribute("rag.retrieve_ms", int(metrics.retrieve_ms))
                span.set_attribute("rag.rrf_ms", int(metrics.rrf_ms))
                span.set_attribute("rag.rerank_ms", int(metrics.rerank_ms))
                span.set_attribute("rag.total_ms", int(metrics.total_ms))
                span.set_attribute("rag.llm_rewrite_calls", metrics.llm_rewrite_calls)
                span.set_attribute(
                    "rag.org_context_exact_hit",
                    metrics.org_context_exact_hit,
                )
                span.set_attribute("rag.constraint_channel", metrics.constraint_channel)
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
        impl_started = time.perf_counter()
        active_context = context
        effective_top_k = top_k

        cfg = self._settings or get_settings()
        if context.query_plan is None and cfg.app_env.strip().lower() == "production":
            pinned_requested = _RELEASE_PINNED_KBS.intersection(kb_names)
            if pinned_requested:
                return _empty_result(
                    query,
                    degraded=degraded + [_PLAN_REJECTED, "plan_required_in_production"],
                    knowledge_query_plan={
                        "rejected_reasons": ["plan_required_in_production"],
                        "sanitized_plan_hash": "",
                        "kb_names": kb_names,
                    },
                    started=impl_started,
                )

        if context.query_plan is not None:
            if context.query_plan.kb_name not in kb_names:
                return _empty_result(
                    query,
                    degraded=degraded + [_PLAN_REJECTED, "plan_kb_not_in_scope"],
                    knowledge_query_plan={
                        "rejected_reasons": ["plan_kb_not_in_scope"],
                        "sanitized_plan_hash": "",
                    },
                    started=impl_started,
                )
            if set(kb_names) != {context.query_plan.kb_name}:
                return _empty_result(
                    query,
                    degraded=degraded + [_PLAN_REJECTED, "plan_kb_scope_mismatch"],
                    knowledge_query_plan={
                        "rejected_reasons": ["plan_kb_scope_mismatch"],
                        "sanitized_plan_hash": "",
                    },
                    started=impl_started,
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
                return _empty_result(
                    query,
                    degraded=degraded + [_PLAN_REJECTED, *outcome.rejected_reasons],
                    knowledge_query_plan={
                        "rejected_reasons": outcome.rejected_reasons,
                        "sanitized_plan_hash": outcome.sanitized_plan_hash,
                    },
                    started=impl_started,
                )
            if outcome.plan is not None:
                active_context = replace(context, query_plan=outcome.plan)
                effective_top_k = min(top_k, outcome.plan.budget.top_k)
                if outcome.degraded_reasons:
                    degraded.extend(outcome.degraded_reasons)

        skip_rewrite = should_skip_query_rewrite(
            query,
            facts=active_context.org_context_facts,
        )
        pending_exact_chunks: list[RetrievedChunk] = []
        org_exact_hit = False
        if kb_names == [ORG_CONTEXT_KB_NAME]:
            exact = await self._retrieve_org_context_exact(
                query,
                effective_top_k,
                context=active_context,
                degraded=degraded,
                started=impl_started,
            )
            if exact is not None:
                hit = bool(
                    exact.retrieval_metrics and exact.retrieval_metrics.org_context_exact_hit
                )
                if hit and should_short_circuit_org_exact(
                    has_conflict=active_context.has_evidence_conflict
                ):
                    return _with_retrieval_action(exact, "sufficient")
                if hit:
                    pending_exact_chunks = list(exact.chunks)
                    org_exact_hit = True
                else:
                    return _with_retrieval_action(exact, "uncertain")

        rewrite_ms = 0.0
        llm_rewrite_calls = 0
        rewritten: list[str]
        if skip_rewrite:
            rewritten = [query]
        else:
            rewrite_started = time.perf_counter()
            try:
                rewritten = await self._rewriter.rewrite(query, context=active_context)
                llm_rewrite_calls = 1
            except Exception as exc:
                logger.warning("Query rewriting failed: %s", exc)
                degraded.append("query_rewriter")
                rewritten = [query]
                llm_rewrite_calls = 1
            rewrite_ms = _elapsed_ms(rewrite_started)

        retrieve_started = time.perf_counter()
        result_lists = await self._retriever.retrieve(
            rewritten, kb_names, top_k=effective_top_k, context=active_context
        )
        retrieve_ms = _elapsed_ms(retrieve_started)

        plan_payload = (
            active_context.query_plan.model_dump(mode="json")
            if active_context.query_plan is not None
            else None
        )
        action = decide_retrieval_action(
            has_conflict=active_context.has_evidence_conflict,
            org_exact_hit=org_exact_hit,
        )
        if not any(result_lists):
            chunks = list(pending_exact_chunks)
            citations = CitationTracer.generate(query, chunks) if chunks else []
            return RetrievalResult(
                query=query,
                rewritten_queries=rewritten,
                chunks=chunks,
                citations=citations,
                degraded_steps=degraded,
                knowledge_query_plan=plan_payload,
                retrieval_metrics=RetrievalMetrics(
                    rewrite_ms=rewrite_ms,
                    retrieve_ms=retrieve_ms,
                    total_ms=_elapsed_ms(impl_started),
                    llm_rewrite_calls=llm_rewrite_calls,
                    org_context_exact_hit=org_exact_hit,
                    retrieval_action=action,
                ),
            )

        rrf_started = time.perf_counter()
        constraint_channel = False
        if kb_names == [ORG_CONTEXT_KB_NAME] or not active_context.org_constraints:
            fused = rrf_fuse(result_lists, k=60)
        else:
            fused, constraint_channel = c_rrf_fuse(
                result_lists,
                active_context.org_constraints,
                k=60,
            )
        rrf_ms = _elapsed_ms(rrf_started)

        rerank_started = time.perf_counter()
        if constraint_channel:
            reranked = _ensure_normalized(fused[:effective_top_k])
        else:
            try:
                reranked = await self._reranker.rerank(query, fused, effective_top_k)
            except Exception as exc:
                logger.warning("Reranking failed, using RRF order: %s", exc)
                degraded.append("reranker")
                reranked = _ensure_normalized(fused[:effective_top_k])
        rerank_ms = _elapsed_ms(rerank_started)

        if pending_exact_chunks:
            seen = {chunk.chunk_id for chunk in pending_exact_chunks}
            reranked = pending_exact_chunks + [
                chunk for chunk in reranked if chunk.chunk_id not in seen
            ]
            reranked = reranked[:effective_top_k]
        citations = CitationTracer.generate(query, reranked)
        return RetrievalResult(
            query=query,
            rewritten_queries=rewritten,
            chunks=reranked,
            citations=citations,
            degraded_steps=degraded,
            knowledge_query_plan=plan_payload,
            retrieval_metrics=RetrievalMetrics(
                rewrite_ms=rewrite_ms,
                retrieve_ms=retrieve_ms,
                rrf_ms=rrf_ms,
                rerank_ms=rerank_ms,
                total_ms=_elapsed_ms(impl_started),
                llm_rewrite_calls=llm_rewrite_calls,
                constraint_channel=constraint_channel,
                org_context_exact_hit=org_exact_hit,
                retrieval_action=action,
            ),
        )

    async def _retrieve_org_context_exact(
        self,
        query: str,
        top_k: int,
        *,
        context: RetrievalContext,
        degraded: list[str],
        started: float,
    ) -> RetrievalResult | None:
        """Exact metadata match for org_context_kb.

        Returns a result for exact hits or an empty catalog. None means fall
        through to hybrid (no structured entities, listing failure, or miss).
        """
        facts = context.org_context_facts
        query_facts = facts_from_query(query, now=facts.now if facts is not None else None)
        facts = facts.merge(query_facts) if facts is not None else query_facts
        if not facts.has_structured_entities():
            return None
        store = getattr(self._retriever, "_store", None)
        if store is None or not hasattr(store, "list_chunks"):
            degraded.append("org_context_exact")
            return None
        retrieve_started = time.perf_counter()
        try:
            listed = await list_org_context_chunks(store, context.tenant_id)
        except Exception as exc:
            logger.warning("org_context exact listing failed: %s", exc)
            degraded.append("org_context_exact")
            return None
        retrieve_ms = _elapsed_ms(retrieve_started)
        plan_payload = (
            context.query_plan.model_dump(mode="json") if context.query_plan is not None else None
        )
        if not listed:
            degraded.append("org_context_empty")
            return RetrievalResult(
                query=query,
                rewritten_queries=[query],
                chunks=[],
                citations=[],
                degraded_steps=list(degraded),
                knowledge_query_plan=plan_payload,
                retrieval_metrics=RetrievalMetrics(
                    retrieve_ms=retrieve_ms,
                    total_ms=_elapsed_ms(started),
                    llm_rewrite_calls=0,
                    org_context_exact_hit=False,
                    retrieval_action="uncertain",
                ),
            )
        hits = OrgContextMatcher.match(facts, listed, now=facts.now)
        if not hits:
            degraded.append("org_context_exact_miss")
            return None
        retrieved = hits_to_retrieved_chunks(hits)[:top_k]
        citations = CitationTracer.generate(query, retrieved)
        return RetrievalResult(
            query=query,
            rewritten_queries=[query],
            chunks=retrieved,
            citations=citations,
            degraded_steps=list(degraded),
            knowledge_query_plan=plan_payload,
            retrieval_metrics=RetrievalMetrics(
                retrieve_ms=retrieve_ms,
                total_ms=_elapsed_ms(started),
                llm_rewrite_calls=0,
                org_context_exact_hit=True,
                retrieval_action="sufficient",
            ),
        )


def _elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000.0


def _with_retrieval_action(result: RetrievalResult, action: str) -> RetrievalResult:
    metrics = result.retrieval_metrics or RetrievalMetrics()
    return result.model_copy(
        update={"retrieval_metrics": metrics.model_copy(update={"retrieval_action": action})}
    )


def _empty_result(
    query: str,
    *,
    degraded: list[str],
    knowledge_query_plan: dict[str, Any] | None,
    started: float,
) -> RetrievalResult:
    return RetrievalResult(
        query=query,
        rewritten_queries=[query],
        chunks=[],
        citations=[],
        degraded_steps=degraded,
        knowledge_query_plan=knowledge_query_plan,
        retrieval_metrics=RetrievalMetrics(total_ms=_elapsed_ms(started)),
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
