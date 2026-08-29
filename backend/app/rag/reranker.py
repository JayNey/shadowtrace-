"""Reranker: score-based re-ranking with mock and remote backends (ISSUE-045)."""

from __future__ import annotations

import logging
import re

import httpx

from app.core.config import Settings, get_settings
from app.models.knowledge import RetrievedChunk

logger = logging.getLogger(__name__)

_EN_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,}")
_CJK_RUN = re.compile(r"[\u4e00-\u9fff]{2,}")


def effective_rerank_mode(settings: Settings) -> str:
    """Resolve RERANK_MODE. Mock embedding never uses remote (plan §4)."""
    mode = (settings.rerank_mode or "mock").strip().lower()
    if mode not in {"mock", "remote", "off"}:
        mode = "mock"
    if mode == "remote" and settings.embedding_mode.strip().lower() == "mock":
        return "mock"
    return mode


def remote_rerank_window(top_k: int) -> int:
    return max(top_k * 4, 20)


class Reranker:
    """Re-rank retrieved chunks by relevance to the query.

    Dispatch on ``RERANK_MODE``:
      - ``mock``: deterministic score + query-overlap weighted re-rank
      - ``remote``: OpenAI-compatible / Cohere-shaped rerank API
      - ``off``: fusion order only (caller usually skips this class)
    """

    def __init__(self, settings: Settings | None = None) -> None:
        cfg = settings or get_settings()
        self._settings = cfg
        self._mode = effective_rerank_mode(cfg)
        self._http: httpx.AsyncClient | None = None

    async def rerank(
        self, query: str, chunks: list[RetrievedChunk], top_k: int
    ) -> list[RetrievedChunk]:
        if not chunks:
            return []
        if self._mode == "off":
            return list(chunks[:top_k])
        if self._mode == "mock":
            return _mock_rerank(query, chunks, top_k)
        if self._mode == "remote":
            return await self._remote_rerank(query, chunks, top_k)
        raise NotImplementedError(
            f"RERANK_MODE={self._mode!r} is not implemented; use mock, remote, or off"
        )

    @property
    def mode(self) -> str:
        return self._mode

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None:
            base = (self._settings.rerank_api_base_url or "").strip().rstrip("/")
            if not base:
                raise RuntimeError("RERANK_API_BASE_URL is not configured")
            headers: dict[str, str] = {}
            api_key = (self._settings.rerank_api_key or "").strip()
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            self._http = httpx.AsyncClient(base_url=base, headers=headers)
        return self._http

    async def _remote_rerank(
        self, query: str, chunks: list[RetrievedChunk], top_k: int
    ) -> list[RetrievedChunk]:
        """Remote scores replace fusion scores. Do not blend with C-RRF."""
        window = remote_rerank_window(top_k)
        candidates = chunks[:window]
        documents = [chunk.content for chunk in candidates]
        http = await self._get_http()
        model = (self._settings.rerank_model_id or "").strip() or "rerank"
        payload = {
            "model": model,
            "query": query,
            "documents": documents,
            "top_n": top_k,
        }
        resp = await http.post("/rerank", json=payload, timeout=self._settings.rerank_timeout_seconds)
        resp.raise_for_status()
        ranked = _parse_remote_rerank_results(resp.json(), len(candidates))
        min_score = float(self._settings.rerank_min_score)
        out: list[RetrievedChunk] = []
        for index, relevance in ranked:
            if relevance < min_score:
                continue
            chunk = candidates[index]
            clipped = max(0.0, min(1.0, float(relevance)))
            out.append(
                RetrievedChunk(
                    chunk_id=chunk.chunk_id,
                    kb_name=chunk.kb_name,
                    content=chunk.content,
                    metadata=chunk.metadata,
                    score=clipped,
                    retrieval_method="reranked",
                    raw_rrf_score=chunk.raw_rrf_score,
                )
            )
            if len(out) >= top_k:
                break
        return out


def _parse_remote_rerank_results(payload: object, candidate_count: int) -> list[tuple[int, float]]:
    if not isinstance(payload, dict):
        raise RuntimeError("rerank provider returned a non-object payload")
    raw = payload.get("results")
    if raw is None:
        raw = payload.get("data")
    if not isinstance(raw, list) or not raw:
        raise RuntimeError("rerank provider returned no results")
    parsed: list[tuple[int, float]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        index = item.get("index")
        score = item.get("relevance_score", item.get("score"))
        if not isinstance(index, int) or index < 0 or index >= candidate_count:
            continue
        if not isinstance(score, (int, float)):
            continue
        parsed.append((index, float(score)))
    if not parsed:
        raise RuntimeError("rerank provider returned no usable indexes")
    parsed.sort(key=lambda row: (-row[1], row[0]))
    return parsed


def _tokenize(text: str) -> set[str]:
    lowered = text.lower()
    tokens = {match.group(0).lower() for match in _EN_TOKEN.finditer(lowered)}
    tokens.update(match.group(0) for match in _CJK_RUN.finditer(text))
    return tokens


def _mock_rerank(query: str, chunks: list[RetrievedChunk], top_k: int) -> list[RetrievedChunk]:
    """Deterministic re-rank: original score plus token-boundary overlap.

    Keyword hits are not given a blanket boost; substring matches on short
    tokens (``in``, ``id``) do not count.
    """
    query_terms = _tokenize(query.replace(":", " ").replace(";", " "))

    def _overlap(chunk: RetrievedChunk) -> float:
        meta_bits = " ".join(
            str(chunk.metadata.get(key) or "")
            for key in ("technique_id", "technique_name", "case_id", "event_type", "aliases")
        )
        haystack_terms = _tokenize(f"{chunk.content} {meta_bits}")
        if not query_terms:
            return 0.0
        hits = sum(1 for term in query_terms if term in haystack_terms)
        return hits / len(query_terms)

    scored: list[tuple[float, RetrievedChunk]] = []
    for chunk in chunks:
        overlap = _overlap(chunk)
        new_score = 0.65 * chunk.score + 0.35 * overlap
        scored.append((new_score, chunk))

    scored.sort(key=lambda x: x[0], reverse=True)
    top = scored[:top_k]

    if not top:
        return []

    max_score = top[0][0]
    min_score = top[-1][0]
    score_range = max_score - min_score if max_score != min_score else 1.0

    result: list[RetrievedChunk] = []
    for score, chunk in top:
        normalized = (score - min_score) / score_range if score_range > 0 else 1.0
        result.append(
            RetrievedChunk(
                chunk_id=chunk.chunk_id,
                kb_name=chunk.kb_name,
                content=chunk.content,
                metadata=chunk.metadata,
                score=normalized,
                retrieval_method="reranked",
                raw_rrf_score=chunk.raw_rrf_score,
            )
        )
    return result


class MockReranker(Reranker):
    """Explicit mock reranker for use when mode is known at construction time."""

    def __init__(self) -> None:
        self._settings = Settings(RERANK_MODE="mock", EMBEDDING_MODE="mock")
        self._mode = "mock"
        self._http = None
