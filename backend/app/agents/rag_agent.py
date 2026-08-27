"""RAGAgent: knowledge-augmented retrieval across investigation KBs (ISSUE-046).

Concurrently queries attack_kb, fp_case_kb, history_case_kb, playbook_kb,
and org_context_kb via RetrievalPipeline, assembles a structured RAGOutput,
and persists it to EventContext.rag_output.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import replace
from typing import Any, cast

from celery.exceptions import SoftTimeLimitExceeded

from app.agents.base import BaseAgent
from app.agents.rag_query_builder import RAGQueryBuilder
from app.core.config import Settings, get_settings
from app.core.errors import (
    DependencyUnavailableError,
    GuardrailViolationError,
    ShadowTraceError,
)
from app.models.agent_io import (
    AttackTechniqueMatch,
    Citation,
    FpSimilarity,
    OrgContextMatch,
    RAGAgentInput,
    RAGOutput,
    SimilarCaseSummary,
)
from app.models.enums import EventType, FinalVerdict
from app.models.knowledge import RetrievalMetrics, RetrievalResult
from app.models.knowledge_release import KnowledgeQueryPlan
from app.models.playbook_release import PlaybookRef
from app.rag.constraint_rrf import OrgConstraint, constraints_from_org_matches
from app.rag.context import RetrievalContext
from app.rag.retrieval_router import attack_kb_top_k, evidence_conflict_present
from app.services.knowledge_query_plan_service import resolve_active_knowledge_query_plan
from app.services.knowledge_release_service import KnowledgeReleaseService
from app.services.org_context_matcher import (
    coerce_org_context_kind,
    is_exact_org_context_match,
    load_org_context_matches,
)
from app.services.playbook_kb_service import playbook_ref_from_metadata
from app.services.playbook_query_plan_service import resolve_active_playbook_query_plan
from app.services.playbook_release_service import PlaybookReleaseService

logger = logging.getLogger(__name__)

_ORG_KB = "org_context_kb"
_KB_NAMES = [
    "attack_kb",
    "fp_case_kb",
    "history_case_kb",
    "playbook_kb",
    _ORG_KB,
]
_OTHER_KBS = [name for name in _KB_NAMES if name != _ORG_KB]
_TOP_K = 5
_NO_ACTIVE_RELEASE = "no_active_knowledge_release"
_NO_ACTIVE_PLAYBOOK_RELEASE = "no_active_playbook_release"


class RAGAgent(BaseAgent[RAGAgentInput, RAGOutput]):
    """Stage 6 Agent: two-phase RAG across five knowledge bases.

    Phase 1 retrieves ``org_context_kb`` and materializes allow-constraints.
    Phase 2 retrieves the other four KBs concurrently; hybrid fusion uses
    Constrained RRF when those constraints are non-empty. A single KB failure
    does not interrupt the others. When all five KBs are unavailable the
    agent returns an empty RAGOutput with ``degraded=True``.
    """

    agent_name: str = "rag_agent"

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        tool_executor: Any | None = None,
        working_memory: Any | None = None,
        budget_service: Any | None = None,
        output_guard: Any | None = None,
        trace_service: Any | None = None,
        audit_service: Any | None = None,
        event_bus: Any | None = None,
        pipeline: Any | None = None,
        knowledge_release_service: KnowledgeReleaseService | None = None,
        playbook_release_service: PlaybookReleaseService | None = None,
        settings: Settings | None = None,
    ) -> None:
        super().__init__(
            llm_client=llm_client,
            tool_executor=tool_executor,
            working_memory=working_memory,
            budget_service=budget_service,
            output_guard=output_guard,
            trace_service=trace_service,
            audit_service=audit_service,
            event_bus=event_bus,
        )
        self._pipeline = pipeline
        self._knowledge_release_service = knowledge_release_service
        self._playbook_release_service = playbook_release_service
        self._settings = settings

    # ------------------------------------------------------------------ #
    # _run
    # ------------------------------------------------------------------ #

    async def _run(self, input: RAGAgentInput) -> RAGOutput:
        queries = RAGQueryBuilder.build_queries(input.triage_result, input.evidence_output)

        # Two-phase retrieval: org_context_kb first, then the other four in parallel.
        if self._pipeline is None:
            output = RAGOutput(degraded=True)
            await self._write_rag_output(input, output)
            return output

        cfg = self._settings or get_settings()
        attack_plan = await self._resolve_attack_query_plan(input)
        playbook_plan = await self._resolve_playbook_query_plan(input)
        base_context = RetrievalContext.from_rag_input(input, settings=cfg, query_plan=attack_plan)
        attack_kb_blocked = self._knowledge_release_service is not None and attack_plan is None
        playbook_kb_blocked = self._playbook_kb_blocked(cfg, playbook_plan)
        has_conflict = evidence_conflict_present(input.evidence_output)
        org_result = await self._retrieve_for_kb(
            _ORG_KB,
            queries.get(_ORG_KB, ""),
            top_k=_TOP_K,
            base_context=base_context,
            attack_plan=attack_plan,
            playbook_plan=playbook_plan,
            org_constraints=(),
        )
        # Catalog exact-hits are independent of hybrid citations (retrieval ≠ match).
        org_context_matches = _merge_org_context_matches(
            await self._catalog_org_context_matches(input, tenant_id=base_context.tenant_id),
            _build_org_context_matches(org_result),
        )
        org_constraints = constraints_from_org_matches(org_context_matches)
        retrieve_outcomes = await asyncio.gather(
            *(
                self._retrieve_for_kb(
                    kb_name,
                    queries.get(kb_name, ""),
                    top_k=(
                        attack_kb_top_k(has_conflict=has_conflict)
                        if kb_name == "attack_kb"
                        else _TOP_K
                    ),
                    base_context=base_context,
                    attack_plan=attack_plan,
                    playbook_plan=playbook_plan,
                    blocked=(
                        (kb_name == "attack_kb" and attack_kb_blocked)
                        or (kb_name == "playbook_kb" and playbook_kb_blocked)
                    ),
                    org_constraints=org_constraints,
                )
                for kb_name in _OTHER_KBS
            ),
            return_exceptions=False,
        )
        results = {_ORG_KB: org_result, **dict(zip(_OTHER_KBS, retrieve_outcomes, strict=True))}

        # Assemble output sections.
        attack_techniques = _build_attack_techniques(results.get("attack_kb"))
        fp_similarity = _build_fp_similarity(results.get("fp_case_kb"))
        similar_cases = _build_similar_cases(
            results.get("history_case_kb"),
            event_type=input.triage_result.event_type,
        )
        playbook_refs = _build_playbook_refs(results.get("playbook_kb"))
        citations = _aggregate_citations(results)

        all_failed = all(r is None for r in results.values())
        plan_payload = _build_knowledge_query_plan_payload(attack_plan, playbook_plan)
        output = RAGOutput(
            attack_techniques=attack_techniques,
            fp_similarity=fp_similarity,
            similar_cases=similar_cases,
            playbook_refs=playbook_refs,
            org_context_matches=org_context_matches,
            citations=citations,
            knowledge_query_plan=plan_payload,
            retrieval_metrics=_aggregate_retrieval_metrics(results),
            degraded=all_failed,
        )

        # Persist to EventContext.
        await self._write_rag_output(input, output)

        return output

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    async def _resolve_attack_query_plan(self, input: RAGAgentInput) -> KnowledgeQueryPlan | None:
        if self._knowledge_release_service is None:
            return None
        cfg = self._settings or get_settings()
        trace_id = (input.trace_id or f"evt:{input.event_id}").strip()
        return await resolve_active_knowledge_query_plan(
            self._knowledge_release_service,
            cfg,
            trace_id=trace_id,
            tenant_id=(input.tenant_id or "").strip(),
            principal=(input.principal or "").strip(),
        )

    async def _resolve_playbook_query_plan(self, input: RAGAgentInput) -> KnowledgeQueryPlan | None:
        if self._playbook_release_service is None:
            return None
        cfg = self._settings or get_settings()
        trace_id = (input.trace_id or f"evt:{input.event_id}").strip()
        return await resolve_active_playbook_query_plan(
            self._playbook_release_service,
            cfg,
            trace_id=trace_id,
            tenant_id=(input.tenant_id or "").strip(),
            principal=(input.principal or "").strip(),
        )

    def _playbook_kb_blocked(
        self,
        cfg: Settings,
        playbook_plan: KnowledgeQueryPlan | None,
    ) -> bool:
        if self._playbook_release_service is None:
            return False
        require_active = (
            cfg.app_env.strip().lower() == "production" or cfg.playbook_release_require_active
        )
        return require_active and playbook_plan is None

    async def _retrieve_for_kb(
        self,
        kb_name: str,
        query: str,
        top_k: int = 5,
        *,
        base_context: RetrievalContext,
        attack_plan: KnowledgeQueryPlan | None,
        playbook_plan: KnowledgeQueryPlan | None,
        blocked: bool = False,
        org_constraints: tuple[OrgConstraint, ...] | None = None,
    ) -> RetrievalResult | None:
        if blocked:
            degraded = [
                _NO_ACTIVE_RELEASE if kb_name == "attack_kb" else _NO_ACTIVE_PLAYBOOK_RELEASE
            ]
            plan = attack_plan if kb_name == "attack_kb" else playbook_plan
            return RetrievalResult(
                query=query,
                degraded_steps=degraded,
                knowledge_query_plan=(plan.model_dump(mode="json") if plan is not None else None),
            )
        query_plan = None
        if kb_name == "attack_kb":
            query_plan = attack_plan
        elif kb_name == "playbook_kb":
            query_plan = playbook_plan
        context = replace(
            base_context,
            query_plan=query_plan,
            org_constraints=(
                org_constraints if org_constraints is not None else base_context.org_constraints
            ),
        )
        return await self._retrieve_safe(kb_name, query, top_k=top_k, context=context)

    async def _catalog_org_context_matches(
        self,
        input: RAGAgentInput,
        *,
        tenant_id: str,
    ) -> list[OrgContextMatch]:
        """Exact matcher over the org_context catalog. Independent of hybrid retrieval."""
        store = getattr(getattr(self._pipeline, "_retriever", None), "_store", None)
        if store is None or not hasattr(store, "list_chunks"):
            return []
        try:
            return await load_org_context_matches(
                store,
                triage_result=input.triage_result,
                evidence_output=input.evidence_output,
                tenant_id=tenant_id,
                occurred_at=input.occurred_at,
            )
        except Exception as exc:
            logger.warning("org_context catalog match failed: %s", exc)
            return []

    async def _retrieve_safe(
        self,
        kb_name: str,
        query: str,
        top_k: int = 5,
        *,
        context: RetrievalContext,
    ) -> RetrievalResult | None:
        """Call pipeline.retrieve, returning None on failure."""
        if self._pipeline is None:
            return None
        try:
            return cast(
                RetrievalResult,
                await self._pipeline.retrieve(
                    query,
                    [kb_name],
                    top_k=top_k,
                    context=context,
                ),
            )
        except SoftTimeLimitExceeded:
            # ISSUE-314: do not degrade soft-limit into empty retrieval.
            raise
        except Exception as exc:
            logger.warning(
                "RAG retrieval failed for kb=%s query=%.100s: %s",
                kb_name,
                query,
                exc,
            )
            return None

    async def _write_rag_output(self, input: RAGAgentInput, output: RAGOutput) -> None:
        """Persist ``rag_output`` to ``EventContext``."""
        wm = self.working_memory
        if wm is None:
            return
        try:
            await wm.write(
                input.event_id,
                "rag_output",
                output.model_dump(mode="json"),
            )
        except GuardrailViolationError:
            logger.exception(
                "GuardrailViolationError writing rag_output for event=%s",
                input.event_id,
            )
            raise
        except (DependencyUnavailableError, ConnectionError, TimeoutError):
            logger.warning(
                "Transient failure writing rag_output for event=%s",
                input.event_id,
                exc_info=True,
            )
            output.degraded = True
        except ShadowTraceError as exc:
            if exc.retryable:
                logger.warning(
                    "Retryable error writing rag_output for event=%s: %s",
                    input.event_id,
                    exc.error_code,
                    exc_info=True,
                )
                output.degraded = True
            else:
                raise


# --------------------------------------------------------------------------- #
# Result assembly helpers
# --------------------------------------------------------------------------- #


def _build_knowledge_query_plan_payload(
    attack_plan: KnowledgeQueryPlan | None,
    playbook_plan: KnowledgeQueryPlan | None,
) -> dict[str, Any] | None:
    """Trace payload keyed by kb_name when one or more release-pinned plans apply."""
    plans: dict[str, Any] = {}
    if attack_plan is not None:
        plans["attack_kb"] = attack_plan.model_dump(mode="json")
    if playbook_plan is not None:
        plans["playbook_kb"] = playbook_plan.model_dump(mode="json")
    return plans or None


def _build_attack_techniques(
    result: RetrievalResult | None,
) -> list[AttackTechniqueMatch]:
    """Extract attack technique matches from attack_kb retrieval result.

    Only techniques with a reranked score >= 0.3 are kept.  match_confidence
    is the chunk score clipped to [0, 1].
    """
    if result is None or not result.chunks:
        return []

    citation_by_chunk = {c.chunk_id: c.citation_id for c in result.citations}

    techniques: list[AttackTechniqueMatch] = []
    for chunk in result.chunks:
        score = max(0.0, min(1.0, chunk.score))
        if score < 0.3:
            continue
        meta = chunk.metadata
        technique_id = meta.get("technique_id", "")
        if not technique_id:
            continue
        technique_name = meta.get("technique_name", "")
        tactics: list[str] = meta.get("tactics", [])
        if not isinstance(tactics, list):
            tactics = []
        citation_id = citation_by_chunk.get(chunk.chunk_id)
        if not citation_id:
            continue
        techniques.append(
            AttackTechniqueMatch(
                technique_id=technique_id,
                technique_name=technique_name,
                tactics=tactics,
                match_confidence=score,
                citation_id=citation_id,
            )
        )

    # Sort by confidence descending, deduplicate by technique_id.
    seen: set[str] = set()
    deduped: list[AttackTechniqueMatch] = []
    for t in sorted(techniques, key=lambda x: x.match_confidence, reverse=True):
        if t.technique_id not in seen:
            seen.add(t.technique_id)
            deduped.append(t)
    return deduped


def _build_fp_similarity(result: RetrievalResult | None) -> FpSimilarity:
    """Compute false-positive similarity from fp_case_kb retrieval result."""
    if result is None or not result.chunks:
        return FpSimilarity(max_score=0.0)

    best = max(result.chunks, key=lambda c: c.score)
    max_score = max(0.0, min(1.0, best.score))
    meta = best.metadata
    return FpSimilarity(
        max_score=max_score,
        matched_case_id=meta.get("case_id"),
        matched_pattern=meta.get("pattern_summary"),
    )


_SIMILAR_CASE_MIN_SCORE = 0.25


def _build_similar_cases(
    result: RetrievalResult | None,
    *,
    event_type: EventType | None = None,
) -> list[SimilarCaseSummary]:
    """Extract similar case summaries from history_case_kb retrieval result.

    Prefer same ``event_type`` when the query has one; if that filter empties
    the list, keep other above-threshold hits (fail-soft).
    """
    if result is None or not result.chunks:
        return []

    cases: list[SimilarCaseSummary] = []
    for chunk in result.chunks:
        score = max(0.0, min(1.0, chunk.score))
        if score < _SIMILAR_CASE_MIN_SCORE:
            continue
        meta = chunk.metadata
        event_type_raw = meta.get("event_type")
        parsed_event_type: EventType | None = None
        if isinstance(event_type_raw, str):
            try:
                parsed_event_type = EventType(event_type_raw)
            except ValueError:
                pass

        verdict_raw = meta.get("final_verdict")
        final_verdict: FinalVerdict | None = None
        if isinstance(verdict_raw, str):
            try:
                final_verdict = FinalVerdict(verdict_raw)
            except ValueError:
                pass

        risk_score_raw = meta.get("risk_score")
        risk_score: int | None = None
        if isinstance(risk_score_raw, (int, float)):
            risk_score = max(0, min(100, int(risk_score_raw)))

        cases.append(
            SimilarCaseSummary(
                case_id=meta.get("case_id", ""),
                event_type=parsed_event_type,
                summary=meta.get("summary", ""),
                final_verdict=final_verdict,
                risk_score=risk_score,
                score=score,
            )
        )

    cases.sort(key=lambda item: item.score if item.score is not None else 0.0, reverse=True)
    if event_type is None:
        return cases
    same_type = [item for item in cases if item.event_type is event_type]
    return same_type or cases


def _build_playbook_refs(result: RetrievalResult | None) -> list[PlaybookRef]:
    """Extract immutable playbook refs from playbook_kb retrieval result."""
    if result is None or not result.chunks:
        return []

    seen: set[str] = set()
    refs: list[PlaybookRef] = []
    for chunk in result.chunks:
        ref = playbook_ref_from_metadata(chunk.metadata)
        if ref is None:
            continue
        key = f"{ref.release_id}:{ref.playbook_id}"
        if key in seen:
            continue
        seen.add(key)
        refs.append(ref)
    return refs


def _merge_org_context_matches(
    catalog: list[OrgContextMatch],
    retrieved: list[OrgContextMatch],
) -> list[OrgContextMatch]:
    """Catalog exact-hits win; retrieved exact-hits fill gaps by chunk_id."""
    merged: list[OrgContextMatch] = []
    seen: set[str] = set()
    for match in (*catalog, *retrieved):
        key = match.chunk_id or f"{match.kind}:{match.matched_value}:{match.match_type}"
        if key in seen:
            continue
        seen.add(key)
        merged.append(match)
    return merged


def _build_org_context_matches(result: RetrievalResult | None) -> list[OrgContextMatch]:
    """Project org_context_kb chunks into typed matches. Hits are evidence only."""
    if result is None or not result.chunks:
        return []
    citation_by_chunk = {c.chunk_id: c.citation_id for c in result.citations}
    matches: list[OrgContextMatch] = []
    for chunk in result.chunks:
        kind = coerce_org_context_kind(str(chunk.metadata.get("kind") or ""))
        if kind is None:
            continue
        citation_id = citation_by_chunk.get(chunk.chunk_id)
        if not citation_id:
            continue
        match_type = str(chunk.metadata.get("match_type") or "")
        if not is_exact_org_context_match(
            match_type,
            retrieval_method=chunk.retrieval_method,
        ):
            continue
        matched_value = str(chunk.metadata.get("matched_value") or "")
        if not matched_value:
            for key in ("domains", "hosts", "accounts", "ips"):
                values = chunk.metadata.get(key)
                if isinstance(values, list) and values:
                    matched_value = str(values[0])
                    break
        matches.append(
            OrgContextMatch(
                kind=kind,
                matched_value=matched_value,
                explanation=chunk.content,
                citation_id=citation_id,
                chunk_id=chunk.chunk_id,
                match_type=match_type,
                match_confidence=max(0.0, min(1.0, chunk.score)),
            )
        )
    return matches


def _aggregate_citations(
    results: dict[str, RetrievalResult | None],
) -> list[Citation]:
    """Collect and deduplicate citations across all investigation KB results."""
    seen: set[str] = set()
    aggregated: list[Citation] = []
    for result in results.values():
        if result is None:
            continue
        for c in result.citations:
            if c.citation_id in seen:
                continue
            seen.add(c.citation_id)
            aggregated.append(
                Citation(
                    citation_id=c.citation_id,
                    chunk_id=c.chunk_id,
                    kb_name=c.kb_name,
                    quoted_text=c.quoted_text,
                    relevance_score=max(0.0, min(1.0, c.relevance_score)),
                    corpus_id=c.corpus_id,
                    release_id=c.release_id,
                    object_id=c.object_id,
                )
            )
    return aggregated


def _aggregate_retrieval_metrics(
    results: dict[str, RetrievalResult | None],
) -> RetrievalMetrics:
    """Two-phase wall clock is ``t_org + max(other KBs)``; rewrite calls are summed.

    Stage peaks (rewrite/retrieve/rrf/rerank) stay max-across-KBs. When
    ``org_context_kb`` is absent from *results*, wall clock falls back to max.
    """
    metrics = [
        result.retrieval_metrics
        for result in results.values()
        if result is not None and result.retrieval_metrics is not None
    ]
    if not metrics:
        return RetrievalMetrics()
    if "org_context_kb" in results:
        org = results["org_context_kb"]
        org_total = (
            org.retrieval_metrics.total_ms
            if org is not None and org.retrieval_metrics is not None
            else 0.0
        )
        other_totals = [
            result.retrieval_metrics.total_ms
            for key, result in results.items()
            if key != "org_context_kb"
            and result is not None
            and result.retrieval_metrics is not None
        ]
        wall = org_total + (max(other_totals) if other_totals else 0.0)
    else:
        wall = max(item.total_ms for item in metrics)
    return RetrievalMetrics(
        rewrite_ms=max(item.rewrite_ms for item in metrics),
        retrieve_ms=max(item.retrieve_ms for item in metrics),
        rrf_ms=max(item.rrf_ms for item in metrics),
        rerank_ms=max(item.rerank_ms for item in metrics),
        total_ms=wall,
        llm_rewrite_calls=sum(item.llm_rewrite_calls for item in metrics),
        org_context_exact_hit=any(item.org_context_exact_hit for item in metrics),
        constraint_channel=any(item.constraint_channel for item in metrics),
        retrieval_action=_aggregate_retrieval_action(metrics),
    )


def _aggregate_retrieval_action(metrics: list[RetrievalMetrics]) -> str:
    actions = [item.retrieval_action for item in metrics if item.retrieval_action]
    if "conflict" in actions:
        return "conflict"
    if "sufficient" in actions:
        return "sufficient"
    if "uncertain" in actions:
        return "uncertain"
    return ""
