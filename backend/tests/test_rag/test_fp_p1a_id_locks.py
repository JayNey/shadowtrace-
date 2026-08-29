"""P1a §1.6 FP champion-id locks via RAGAgent (in-memory store, no load-kb)."""

from __future__ import annotations

import json
import math
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.agents.rag_agent import RAGAgent
from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.knowledge.org_context_seed import mock_org_context_records, records_to_chunks
from app.models.agent_io import RAGAgentInput, TriageResult
from app.models.case import FalsePositiveCase, fp_case_metadata, fp_case_to_text, make_chunk_id
from app.models.entities import AccountEntity, EntitySet, HostEntity
from app.models.enums import EventType, Severity
from app.models.knowledge import (
    GLOBAL_KB_TENANT_ID,
    KnowledgeChunk,
    ListedKnowledgeChunk,
    RetrievedChunk,
)
from app.rag.hybrid_retriever import HybridRetriever
from app.rag.pipeline import RetrievalPipeline
from app.rag.reranker import MockReranker

REPO_ROOT = Path(__file__).resolve().parents[3]
FP_FILE = REPO_ROOT / "data" / "knowledge" / "fp_cases.json"
_FIXTURE_OCCURRED_AT = datetime(2024, 6, 15, 9, 0, tzinfo=UTC)
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class _MockBoundWorkingMemory:
    def __init__(self, writer_name: str = "RAGAgent") -> None:
        self.writer_name = writer_name
        self._store: dict[str, object] = {}

    def for_writer(self, writer: str) -> _MockBoundWorkingMemory:
        return _MockBoundWorkingMemory(writer_name=writer)

    async def write(self, event_id: str, key: str, value: object) -> None:
        del event_id
        self._store[key] = value


class _EchoRewriter:
    async def rewrite(self, query: str, *, context: object) -> list[str]:
        del context
        return [query]


class _InMemoryKbStore:
    """Minimal store: list_chunks + vector/keyword search for RAGAgent catalog and Hybrid."""

    def __init__(self, embed: EmbeddingService) -> None:
        self._embed = embed
        self._rows: dict[str, tuple[KnowledgeChunk, list[float], datetime]] = {}

    async def upsert_chunks(self, kb_name: str, chunks: list[KnowledgeChunk]) -> None:
        del kb_name
        if not chunks:
            return
        vectors = await self._embed.embed_texts([chunk.content for chunk in chunks])
        stamped = datetime(2024, 6, 15, 9, 0, tzinfo=UTC)
        for chunk, vector in zip(chunks, vectors, strict=True):
            self._rows[chunk.chunk_id] = (chunk, vector, stamped)

    def _kb_rows(self, kb_name: str) -> list[tuple[KnowledgeChunk, list[float], datetime]]:
        return [row for row in self._rows.values() if row[0].kb_name == kb_name]

    async def list_chunks(
        self,
        *,
        kb_name: str | None = None,
        page: int = 1,
        page_size: int = 20,
        tenant_id: str | None = None,
    ) -> list[ListedKnowledgeChunk]:
        del tenant_id
        rows = [
            row
            for row in self._rows.values()
            if kb_name is None or row[0].kb_name == kb_name
        ]
        rows.sort(key=lambda item: (item[0].kb_name, item[0].chunk_id))
        start = max(page - 1, 0) * page_size
        page_rows = rows[start : start + page_size]
        return [
            ListedKnowledgeChunk(
                chunk_id=chunk.chunk_id,
                kb_name=chunk.kb_name,
                content=chunk.content,
                metadata=chunk.metadata,
                created_at=created_at,
            )
            for chunk, _vector, created_at in page_rows
        ]

    async def vector_search(
        self,
        kb_name: str,
        query_embedding: list[float],
        top_k: int = 10,
        **_kwargs: object,
    ) -> list[RetrievedChunk]:
        scored: list[tuple[float, KnowledgeChunk]] = []
        for chunk, vector, _created in self._kb_rows(kb_name):
            scored.append((_cosine(query_embedding, vector), chunk))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            RetrievedChunk(
                chunk_id=chunk.chunk_id,
                kb_name=chunk.kb_name,
                content=chunk.content,
                metadata=chunk.metadata,
                score=max(0.0, min(1.0, (score + 1.0) / 2.0)),
                retrieval_method="vector",
            )
            for score, chunk in scored[:top_k]
        ]

    async def keyword_search(
        self,
        kb_name: str,
        query_text: str,
        top_k: int = 10,
        **_kwargs: object,
    ) -> list[RetrievedChunk]:
        needles = [token.lower() for token in _TOKEN_RE.findall(query_text) if len(token) >= 2]
        if not needles:
            return []
        scored: list[tuple[int, KnowledgeChunk]] = []
        for chunk, _vector, _created in self._kb_rows(kb_name):
            haystack = chunk.content.lower()
            hits = sum(1 for token in needles if token in haystack)
            if hits <= 0:
                continue
            scored.append((hits, chunk))
        scored.sort(key=lambda item: item[0], reverse=True)
        denom = max(len(needles), 1)
        return [
            RetrievedChunk(
                chunk_id=chunk.chunk_id,
                kb_name=chunk.kb_name,
                content=chunk.content,
                metadata=chunk.metadata,
                score=hits / denom,
                retrieval_method="keyword",
            )
            for hits, chunk in scored[:top_k]
        ]


def _cosine(left: list[float], right: list[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    return sum(a * b for a, b in zip(left, right, strict=True)) / (
        math.sqrt(sum(a * a for a in left)) * math.sqrt(sum(b * b for b in right)) or 1.0
    )


async def _seeded_agent() -> RAGAgent:
    settings = Settings(
        app_env="development",
        source_mode="mock_xdr",
        embedding_mode="mock",
        rerank_mode="mock",
        retrieval_default_tenant_id="local",
    )
    embed = EmbeddingService(settings)
    store = _InMemoryKbStore(embed)
    await store.upsert_chunks("org_context_kb", records_to_chunks(mock_org_context_records()))
    fp_chunks: list[KnowledgeChunk] = []
    for raw in json.loads(FP_FILE.read_text(encoding="utf-8")):
        case = FalsePositiveCase.model_validate(raw)
        fp_chunks.append(
            KnowledgeChunk(
                chunk_id=make_chunk_id("fp_case_kb", case.case_id),
                kb_name="fp_case_kb",
                content=fp_case_to_text(case),
                metadata={**fp_case_metadata(case), "tenant_id": GLOBAL_KB_TENANT_ID},
            )
        )
    await store.upsert_chunks("fp_case_kb", fp_chunks)
    pipeline = RetrievalPipeline(
        rewriter=_EchoRewriter(),  # type: ignore[arg-type]
        retriever=HybridRetriever(store, embed),
        reranker=MockReranker(),
        settings=settings,
    )
    return RAGAgent(
        working_memory=_MockBoundWorkingMemory(),
        pipeline=pipeline,
        settings=settings,
    )


def _triage(
    *,
    event_type: EventType,
    severity: Severity,
    account: str,
    host: str,
) -> TriageResult:
    return TriageResult(
        event_type=event_type,
        severity=severity,
        need_investigation=True,
        entities=EntitySet(
            accounts=[AccountEntity(entity_id="acct-1", username=account)],
            hosts=[HostEntity(entity_id="host-1", hostname=host)],
        ),
        reasoning="",
    )


async def _champion(
    agent: RAGAgent,
    *,
    event_type: EventType,
    severity: Severity,
    account: str,
    host: str,
    event_id: str,
) -> tuple[str | None, float, object]:
    output = await agent._run(
        RAGAgentInput(
            event_id=event_id,
            tenant_id="local",
            principal="investigation:p1a-lock",
            occurred_at=_FIXTURE_OCCURRED_AT,
            triage_result=_triage(
                event_type=event_type,
                severity=severity,
                account=account,
                host=host,
            ),
        )
    )
    fp = output.fp_similarity
    return fp.matched_case_id, fp.max_score, output


@pytest.mark.asyncio
async def test_p1a_fp_id_locks_via_rag_agent_path() -> None:
    agent = await _seeded_agent()
    results: dict[str, str | None] = {}

    change_id, change_score, change_out = await _champion(
        agent,
        event_type=EventType.ACCOUNT_ANOMALY,
        severity=Severity.LOW,
        account="ops-change-bot",
        host="PC-OPS-JUMP-01",
        event_id="evt-p1a-account-low",
    )
    del change_score
    assert any(
        match.kind in {"account_role", "allowed_source", "time_window"}
        for match in change_out.org_context_matches
    )
    assert change_id == "case-00000001"
    results["account_anomaly_fp/low"] = change_id

    for severity in (Severity.HIGH, Severity.MEDIUM):
        case_id, _score, _out = await _champion(
            agent,
            event_type=EventType.SUSPICIOUS_DOMAIN,
            severity=severity,
            account="office-user-014",
            host="PC-OFFICE-014",
            event_id=f"evt-p1a-domain-{severity.value}",
        )
        assert case_id != "case-00000001"
        assert case_id != "case-0000000e"
        results[f"suspicious_domain_access/{severity.value}"] = case_id

    insider_id, _score, _out = await _champion(
        agent,
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        account="zhangsan",
        host="PC-FIN-023",
        event_id="evt-p1a-insider-critical",
    )
    assert insider_id != "case-00000001"
    assert insider_id != "case-0000000d"
    results["insider_data_exfiltration/critical"] = insider_id

    for severity in (Severity.HIGH, Severity.MEDIUM):
        case_id, _score, _out = await _champion(
            agent,
            event_type=EventType.HOST_COMPROMISE,
            severity=severity,
            account="svc-beacon-007",
            host="WKS-HOST-007",
            event_id=f"evt-p1a-host-{severity.value}",
        )
        assert case_id != "case-00000001"
        results[f"host_compromise/{severity.value}"] = case_id

    for severity in (Severity.HIGH, Severity.MEDIUM):
        case_id, _score, _out = await _champion(
            agent,
            event_type=EventType.INSIDER_THREAT,
            severity=severity,
            account="svc-admin-abuse",
            host="SRV-ADMIN-003",
            event_id=f"evt-p1a-priv-{severity.value}",
        )
        assert case_id != "case-00000001"
        results[f"insider_privilege_abuse/{severity.value}"] = case_id

    mp_id, _score, _out = await _champion(
        agent,
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        account="dev-user-012",
        host="DEV-WKS-012",
        event_id="evt-p1a-mp-high",
    )
    assert mp_id != "case-00000001"
    assert mp_id not in {"case-0000000a", "case-0000000c"}
    results["malicious_process/high"] = mp_id

    lateral_id, _score, _out = await _champion(
        agent,
        event_type=EventType.LATERAL_MOVEMENT,
        severity=Severity.HIGH,
        account="ops-jump-001",
        host="JUMP-HOST-001",
        event_id="evt-p1a-lateral-high",
    )
    assert lateral_id != "case-00000001"
    results["lateral_movement/high"] = lateral_id

    for severity in (Severity.LOW, Severity.MEDIUM):
        case_id, max_score, _out = await _champion(
            agent,
            event_type=EventType.OTHER,
            severity=severity,
            account="general-user-099",
            host="WKS-GEN-099",
            event_id=f"evt-p1a-other-{severity.value}",
        )
        assert case_id != "case-00000001"
        assert 0.0 <= max_score <= 1.0
        results[f"other_unclassified/{severity.value}"] = case_id

    assert len(results) == 12
