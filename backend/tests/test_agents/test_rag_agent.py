"""Tests for RAGAgent, RAGQueryBuilder, and result assembly helpers (ISSUE-046)."""

from __future__ import annotations

import asyncio

import pydantic
import pytest

from app.agents.rag_agent import (
    RAGAgent,
    _aggregate_citations,
    _aggregate_degraded_steps,
    _aggregate_retrieval_metrics,
    _build_attack_techniques,
    _build_fp_similarity,
    _build_org_context_matches,
    _build_playbook_refs,
    _build_similar_cases,
    _merge_org_context_matches,
)
from app.agents.rag_query_builder import RAGQueryBuilder
from app.core.errors import (
    DependencyUnavailableError,
    GuardrailViolationError,
    ShadowTraceError,
)
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    FpSimilarity,
    RAGAgentInput,
    RAGOutput,
    TriageResult,
)
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    HostEntity,
    IPEntity,
    ProcessEntity,
)
from app.models.enums import EventType, EvidenceSource, Severity
from app.models.evidence import Evidence
from app.models.knowledge import RetrievalMetrics, RetrievalResult, RetrievedChunk
from app.models.knowledge_release import KnowledgeRelease
from app.models.workflow import FP_LOW_THRESHOLD
from app.rag.entity_rrf import EntityToken
from tests.test_support.production_settings import production_settings

# --------------------------------------------------------------------------- #
# Mock helpers
# --------------------------------------------------------------------------- #


class _MockBoundWorkingMemory:
    """Minimal mock matching BoundWorkingMemory interface."""

    def __init__(self, writer_name: str = "RAGAgent") -> None:
        self.writer_name = writer_name
        self._store: dict[str, object] = {}
        self._memory = self

    def for_writer(self, writer: str) -> _MockBoundWorkingMemory:
        from app.services.working_memory import normalize_writer

        return _MockBoundWorkingMemory(writer_name=normalize_writer(writer))

    async def read(self, event_id: str, key: str) -> object:
        return self._store.get(key)

    async def write(self, event_id: str, key: str, value: object) -> None:
        self._store[key] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        pass

    async def read_scratchpad(self, event_id: str) -> list:
        return []


class _FailingWriteMockWM:
    """Mock WM that raises on write for a specific key."""

    def __init__(
        self,
        writer_name: str = "RAGAgent",
        *,
        fail_key: str | None = None,
        fail_error: Exception | None = None,
    ) -> None:
        self.writer_name = writer_name
        self._store: dict[str, object] = {}
        self._fail_key = fail_key
        self._fail_error = fail_error or DependencyUnavailableError("wm unavailable")
        self._memory = self

    def for_writer(self, writer: str) -> _FailingWriteMockWM:
        from app.services.working_memory import normalize_writer

        return _FailingWriteMockWM(
            writer_name=normalize_writer(writer),
            fail_key=self._fail_key,
            fail_error=self._fail_error,
        )

    async def read(self, event_id: str, key: str) -> object:
        return self._store.get(key)

    async def write(self, event_id: str, key: str, value: object) -> None:
        if self._fail_key is not None and key == self._fail_key:
            raise self._fail_error
        self._store[key] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        pass

    async def read_scratchpad(self, event_id: str) -> list:
        return []


class _MockPipeline:
    """Configurable mock pipeline whose retrieve() returns preset results per KB."""

    def __init__(
        self,
        results: dict[str, RetrievalResult | Exception] | None = None,
    ) -> None:
        self._results = results or {}
        self.calls: list[dict] = []

    async def retrieve(
        self,
        query: str,
        kb_names: list[str],
        top_k: int = 5,
        *,
        context: object | None = None,
    ) -> RetrievalResult:
        self.calls.append(
            {"query": query, "kb_names": kb_names, "top_k": top_k, "context": context}
        )
        kb_name = kb_names[0] if kb_names else "unknown"
        if kb_name in self._results:
            item = self._results[kb_name]
            if isinstance(item, Exception):
                raise item
            return item
        return RetrievalResult(query=query)


# --------------------------------------------------------------------------- #
# Fixture helpers
# --------------------------------------------------------------------------- #


def _make_triage_result(
    event_type: EventType = EventType.DATA_EXFILTRATION,
    severity: Severity = Severity.HIGH,
) -> TriageResult:
    entities = EntitySet(
        ips=[
            IPEntity(entity_id="ip-1", entity_type="ip", address="45.153.12.88", scope="external"),
            IPEntity(entity_id="ip-2", entity_type="ip", address="10.0.0.5", scope="internal"),
        ],
        hosts=[
            HostEntity(entity_id="host-1", entity_type="host", hostname="web-server-01"),
        ],
        processes=[
            ProcessEntity(entity_id="proc-1", entity_type="process", name="curl.exe"),
        ],
    )
    return TriageResult(
        event_type=event_type,
        severity=severity,
        need_investigation=True,
        entities=entities,
        ioc_list=["45.153.12.88", "malware-c2.example.com"],
        reasoning=(
            "Data exfiltration detected: 500MB upload to external IP 45.153.12.88 via curl.exe"
        ),
    )


def _make_input(
    event_id: str = "evt-001",
    event_type: EventType = EventType.DATA_EXFILTRATION,
    severity: Severity = Severity.HIGH,
    evidence_output: EvidenceOutput | None = None,
) -> RAGAgentInput:
    return RAGAgentInput(
        event_id=event_id,
        triage_result=_make_triage_result(event_type=event_type, severity=severity),
        evidence_output=evidence_output,
    )


def _make_chunk(
    chunk_id: str,
    kb_name: str,
    content: str,
    score: float = 0.85,
    metadata: dict | None = None,
    retrieval_method: str = "reranked",
) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk_id,
        kb_name=kb_name,
        content=content,
        score=score,
        retrieval_method=retrieval_method,
        metadata=metadata or {},
    )


def _make_knowledge_citation(
    citation_id: str,
    chunk_id: str,
    kb_name: str,
    quoted_text: str = "relevant excerpt",
    relevance_score: float = 0.85,
):
    """Create a knowledge.Citation (with the pattern constraint on citation_id)."""
    from app.models.knowledge import Citation as KnowledgeCitation

    return KnowledgeCitation(
        citation_id=citation_id,
        chunk_id=chunk_id,
        kb_name=kb_name,
        quoted_text=quoted_text,
        relevance_score=relevance_score,
    )


# --------------------------------------------------------------------------- #
# Attack KB test data
# --------------------------------------------------------------------------- #

_ATTACK_CHUNKS = [
    _make_chunk(
        "atk-001",
        "attack_kb",
        "Technique: Exfiltration Over Web Service\nID: T1567\nTactics: exfiltration\n...",
        score=0.92,
        metadata={
            "technique_id": "T1567",
            "technique_name": "Exfiltration Over Web Service",
            "tactics": ["exfiltration"],
            "description": "Adversaries may exfiltrate data over web services.",
            "detection": "Monitor for large outbound transfers.",
        },
    ),
    _make_chunk(
        "atk-002",
        "attack_kb",
        "Technique: Exfiltration Over Alternative Protocol\nID: T1048\nTactics: exfiltration\n...",
        score=0.78,
        metadata={
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "tactics": ["exfiltration"],
            "description": "Adversaries may steal data by exfiltrating it over a different "
            "protocol.",
            "detection": "Monitor for unusual protocol usage.",
        },
    ),
    _make_chunk(
        "atk-003",
        "attack_kb",
        "Technique: Data Transfer Size Limits\nID: T1030\nTactics: exfiltration\n...",
        score=0.25,
        metadata={
            "technique_id": "T1030",
            "technique_name": "Data Transfer Size Limits",
            "tactics": ["exfiltration"],
        },
    ),
]

_ATTACK_CITATIONS = [
    _make_knowledge_citation(
        "cit-a1b2c3d4",
        "atk-001",
        "attack_kb",
        "exfiltrate data over web services",
        0.92,
    ),
    _make_knowledge_citation(
        "cit-e5f6a7b8",
        "atk-002",
        "attack_kb",
        "exfiltrating it over a different protocol",
        0.78,
    ),
]

_FP_CHUNKS = [
    _make_chunk(
        "fp-001",
        "fp_case_kb",
        "Pattern: Ops change window bulk login | ops_change_window_bulk_login | ...",
        score=0.88,
        metadata={
            "case_id": "case-fp00001",
            "pattern_summary": "Bulk login during scheduled ops change window",
            "alert_signature": "ops_change_window_bulk_login",
            "entity_pattern": "host=web-server-01; account=svc-ops",
            "fp_reason": "Scheduled maintenance window activity",
            "confirmed_by": "soc-analyst-1",
            "confirmed_at": "2026-01-15T10:00:00Z",
        },
    ),
]

_FP_CITATIONS = [
    _make_knowledge_citation(
        "cit-f0000001",
        "fp-001",
        "fp_case_kb",
        "ops change window bulk login",
        0.88,
    ),
]

_HISTORY_CHUNKS = [
    _make_chunk(
        "hist-001",
        "history_case_kb",
        "Case: Data exfiltration via Dropbox | key entities: 10.0.0.5; 45.153.12.88",
        score=0.82,
        metadata={
            "case_id": "case-h00001",
            "event_id": "evt-00001",
            "event_type": "data_exfiltration",
            "case_label": "true_positive",
            "summary": "Attacker exfiltrated 2GB of customer PII via Dropbox API.",
            "key_entities": "10.0.0.5; 45.153.12.88",
            "final_verdict": "true_positive",
            "risk_score": 85,
            "resolution": "Contained, endpoint isolated, credentials rotated.",
            "closed_at": "2026-02-20T08:00:00Z",
        },
    ),
    _make_chunk(
        "hist-002",
        "history_case_kb",
        "Case: FTP exfiltration after hours | key entities: 192.168.1.100; ftp.example.com",
        score=0.65,
        metadata={
            "case_id": "case-h00002",
            "event_id": "evt-00002",
            "event_type": "data_exfiltration",
            "case_label": "true_positive",
            "summary": "Sensitive documents uploaded to external FTP server.",
            "key_entities": "192.168.1.100; ftp.example.com",
            "final_verdict": "true_positive",
            "risk_score": 70,
            "resolution": "Firewall rule added, FTP blocked.",
            "closed_at": "2026-03-01T12:00:00Z",
        },
    ),
]

_HISTORY_CITATIONS = [
    _make_knowledge_citation(
        "cit-0a000001",
        "hist-001",
        "history_case_kb",
        "exfiltrated 2GB of customer PII",
        0.82,
    ),
    _make_knowledge_citation(
        "cit-0a000002",
        "hist-002",
        "history_case_kb",
        "uploaded to external FTP server",
        0.65,
    ),
]

_PLAYBOOK_RELEASE_META = {
    "release_id": "krel-test00000001",
    "release_version": "v1-test",
    "playbook_object_hash": "a" * 64,
    "bundle_content_hash": "b" * 64,
    "revision": 1,
}

_PLAYBOOK_CHUNKS = [
    _make_chunk(
        "pbk-001",
        "playbook_kb",
        "Playbook: Data Exfiltration Response\n"
        "Event Type: data_exfiltration\nMin Severity: high\n...",
        score=0.91,
        metadata={
            "playbook_id": "pb-a1b2c3d4",
            "playbook_name": "Data Exfiltration Response",
            "event_type": "data_exfiltration",
            "min_severity": "high",
            "description": "Isolate affected hosts, block external IPs, initiate DLP scan.",
            "steps": [],
            **_PLAYBOOK_RELEASE_META,
        },
    ),
    _make_chunk(
        "pbk-002",
        "playbook_kb",
        "Playbook: Generic Data Protection\n"
        "Event Type: data_exfiltration\nMin Severity: medium\n...",
        score=0.73,
        metadata={
            "playbook_id": "pb-b2c3d4e5",
            "playbook_name": "Generic Data Protection",
            "event_type": "data_exfiltration",
            "min_severity": "medium",
            "description": "Audit data access, review DLP policies.",
            "steps": [],
            **_PLAYBOOK_RELEASE_META,
        },
    ),
]

_PLAYBOOK_CITATIONS = [
    _make_knowledge_citation(
        "cit-0b000001",
        "pbk-001",
        "playbook_kb",
        "Isolate affected hosts",
        0.91,
    ),
    _make_knowledge_citation(
        "cit-0b000002",
        "pbk-002",
        "playbook_kb",
        "Audit data access",
        0.73,
    ),
]


_ORG_CONTEXT_CHUNKS = [
    _make_chunk(
        "org-001",
        "org_context_kb",
        "files.corp.internal is an approved internal file-server destination.",
        score=1.0,
        retrieval_method="exact",
        metadata={
            "kind": "allowed_destination",
            "domains": ["files.corp.internal"],
            "matched_value": "files.corp.internal",
            "match_type": "domain_exact",
        },
    ),
]

_ORG_CONTEXT_CITATIONS = [
    _make_knowledge_citation(
        "cit-0c000001",
        "org-001",
        "org_context_kb",
        "approved internal file-server destination",
        1.0,
    ),
]


def _make_full_results() -> dict[str, RetrievalResult]:
    return {
        "attack_kb": RetrievalResult(
            query="",
            chunks=_ATTACK_CHUNKS,
            citations=_ATTACK_CITATIONS,
        ),
        "fp_case_kb": RetrievalResult(
            query="",
            chunks=_FP_CHUNKS,
            citations=_FP_CITATIONS,
        ),
        "history_case_kb": RetrievalResult(
            query="",
            chunks=_HISTORY_CHUNKS,
            citations=_HISTORY_CITATIONS,
        ),
        "playbook_kb": RetrievalResult(
            query="",
            chunks=_PLAYBOOK_CHUNKS,
            citations=_PLAYBOOK_CITATIONS,
        ),
        "org_context_kb": RetrievalResult(
            query="",
            chunks=_ORG_CONTEXT_CHUNKS,
            citations=_ORG_CONTEXT_CITATIONS,
        ),
    }


# --------------------------------------------------------------------------- #
# Tests: RAGQueryBuilder
# --------------------------------------------------------------------------- #


class TestRAGQueryBuilder:
    def test_builds_five_queries(self):
        triage = _make_triage_result()
        queries = RAGQueryBuilder.build_queries(triage)
        assert set(queries.keys()) == {
            "attack_kb",
            "fp_case_kb",
            "history_case_kb",
            "playbook_kb",
            "org_context_kb",
        }
        for q in queries.values():
            assert isinstance(q, str) and len(q) > 0
        assert "IP:45.153.12.88" in queries["org_context_kb"]
        assert "Host:web-server-01" in queries["org_context_kb"]

    def test_attack_query_includes_event_type(self):
        triage = _make_triage_result(EventType.DATA_EXFILTRATION)
        queries = RAGQueryBuilder.build_queries(triage)
        assert "data_exfiltration" in queries["attack_kb"]
        assert "数据外泄" in queries["attack_kb"]
        assert "exfiltration" in queries["attack_kb"]

    def test_attack_query_includes_evidence_behaviors(self):
        triage = _make_triage_result()
        evidence = EvidenceOutput(
            evidence_list=[
                Evidence(
                    evidence_id="ev-001",
                    event_id="evt-001",
                    source=EvidenceSource.NETWORK_FLOW,
                    evidence_type="network_connection",
                    description=(
                        "Outbound connection to rare external IP 45.153.12.88 on port 443"
                    ),
                    confidence=0.9,
                ),
            ],
            collection_status=CollectionStatus.COMPLETED,
        )
        queries = RAGQueryBuilder.build_queries(triage, evidence)
        assert "45.153.12.88" in queries["attack_kb"]

    def test_fp_query_includes_event_type_and_severity(self):
        triage = _make_triage_result(EventType.DATA_EXFILTRATION, Severity.HIGH)
        queries = RAGQueryBuilder.build_queries(triage)
        assert "data_exfiltration" in queries["fp_case_kb"].lower()
        assert "high" in queries["fp_case_kb"].lower()

    def test_history_query_includes_entities(self):
        triage = _make_triage_result()
        queries = RAGQueryBuilder.build_queries(triage)
        assert "45.153.12.88" in queries["history_case_kb"]

    def test_history_and_fp_queries_include_account(self):
        triage = _make_triage_result()
        triage = triage.model_copy(
            update={
                "entities": triage.entities.model_copy(
                    update={
                        "accounts": [
                            AccountEntity(
                                entity_id="acct-1",
                                entity_type="account",
                                username="zhangsan",
                            )
                        ],
                        "domains": [
                            DomainEntity(
                                entity_id="dom-1",
                                entity_type="domain",
                                fqdn="files.corp.internal",
                            )
                        ],
                    }
                )
            }
        )
        queries = RAGQueryBuilder.build_queries(triage)
        assert "Account:zhangsan" in queries["history_case_kb"]
        assert "Account:zhangsan" in queries["fp_case_kb"]
        assert "Host:web-server-01" in queries["fp_case_kb"]
        assert queries["fp_case_kb"].index("Account:zhangsan") < queries["fp_case_kb"].index(
            "Host:web-server-01"
        )
        assert "files.corp.internal" not in queries["fp_case_kb"]
        assert "cdn.corp.internal" not in queries["fp_case_kb"]

    def test_playbook_query_includes_event_type_and_severity(self):
        triage = _make_triage_result(EventType.DATA_EXFILTRATION, Severity.HIGH)
        queries = RAGQueryBuilder.build_queries(triage)
        assert "data_exfiltration" in queries["playbook_kb"]
        assert "high" in queries["playbook_kb"]

    def test_host_compromise_query_does_not_use_valid_accounts(self):
        triage = _make_triage_result(EventType.HOST_COMPROMISE, Severity.HIGH)
        queries = RAGQueryBuilder.build_queries(triage)
        assert "valid accounts" not in queries["attack_kb"]
        assert "credential dumping" in queries["attack_kb"]
        assert "T1059" in queries["attack_kb"]


# --------------------------------------------------------------------------- #
# Tests: Result assembly helpers (pure functions)
# --------------------------------------------------------------------------- #


class TestBuildAttackTechniques:
    def test_extracts_techniques_above_threshold(self):
        result = RetrievalResult(
            query="",
            chunks=_ATTACK_CHUNKS,
            citations=_ATTACK_CITATIONS,
        )
        techniques = _build_attack_techniques(result)
        assert len(techniques) >= 2
        technique_ids = {t.technique_id for t in techniques}
        assert "T1567" in technique_ids or "T1048" in technique_ids

    def test_filters_below_03_threshold(self):
        result = RetrievalResult(
            query="",
            chunks=_ATTACK_CHUNKS,  # atk-003 has score 0.25
            citations=_ATTACK_CITATIONS,
        )
        techniques = _build_attack_techniques(result)
        technique_ids = {t.technique_id for t in techniques}
        assert "T1030" not in technique_ids

    def test_each_technique_has_citation_id(self):
        result = RetrievalResult(
            query="",
            chunks=_ATTACK_CHUNKS,
            citations=_ATTACK_CITATIONS,
        )
        techniques = _build_attack_techniques(result)
        for t in techniques:
            assert t.citation_id, f"Technique {t.technique_id} missing citation_id"

    def test_empty_result_returns_empty_list(self):
        assert _build_attack_techniques(None) == []
        assert _build_attack_techniques(RetrievalResult(query="")) == []

    def test_deduplicates_by_technique_id(self):
        meta = {"technique_id": "T1567", "technique_name": "X", "tactics": ["exfil"]}
        chunks = [
            _make_chunk("a-1", "attack_kb", "T1567 v1", score=0.9, metadata=meta),
            _make_chunk("a-2", "attack_kb", "T1567 v2", score=0.7, metadata=meta),
        ]
        citations = [
            _make_knowledge_citation("cit-11111111", "a-1", "attack_kb", "x", 0.9),
            _make_knowledge_citation("cit-22222222", "a-2", "attack_kb", "x", 0.7),
        ]
        result = RetrievalResult(query="", chunks=chunks, citations=citations)
        techniques = _build_attack_techniques(result)
        assert len(techniques) == 1
        assert techniques[0].match_confidence == 0.9

    def test_skips_chunks_without_technique_id(self):
        chunks = [
            _make_chunk(
                "a-1",
                "attack_kb",
                "no id",
                score=0.9,
                metadata={"technique_name": "X", "tactics": ["exfil"]},
            ),
        ]
        citations = [_make_knowledge_citation("cit-11111111", "a-1", "attack_kb", "x", 0.9)]
        result = RetrievalResult(query="", chunks=chunks, citations=citations)
        assert _build_attack_techniques(result) == []

    def test_skips_chunks_without_citation_mapping(self):
        meta = {"technique_id": "T1567", "technique_name": "X", "tactics": ["exfil"]}
        chunks = [_make_chunk("a-1", "attack_kb", "T1567", score=0.9, metadata=meta)]
        result = RetrievalResult(query="", chunks=chunks, citations=[])
        assert _build_attack_techniques(result) == []


class TestBuildFpSimilarity:
    def test_extracts_high_score_match(self):
        result = RetrievalResult(
            query="",
            chunks=_FP_CHUNKS,
            citations=_FP_CITATIONS,
        )
        fp = _build_fp_similarity(
            result,
            entities=(
                EntityToken("account", "svc-ops"),
                EntityToken("host", "web-server-01"),
            ),
        )
        assert fp.max_score >= FP_LOW_THRESHOLD
        assert fp.matched_case_id == "case-fp00001"
        assert fp.matched_pattern is not None

    def test_empty_result_returns_default(self):
        fp = _build_fp_similarity(None)
        assert fp.max_score == 0.0
        assert fp.matched_case_id is None
        assert fp.matched_pattern is None

    def test_empty_chunks_returns_default(self):
        fp = _build_fp_similarity(RetrievalResult(query=""))
        assert fp.max_score == 0.0

    def test_clips_score_to_0_1(self):
        chunk = _make_chunk(
            "fp-99",
            "fp_case_kb",
            "x",
            score=1.5,
            metadata={
                "case_id": "case-99",
                "pattern_summary": "test",
                "entity_pattern": "account=svc-ops",
            },
        )
        result = RetrievalResult(query="", chunks=[chunk], citations=[])
        fp = _build_fp_similarity(result, entities=(EntityToken("account", "svc-ops"),))
        assert 0.0 <= fp.max_score <= 1.0


class TestBuildSimilarCases:
    def test_extracts_case_summaries(self):
        result = RetrievalResult(
            query="",
            chunks=_HISTORY_CHUNKS,
            citations=_HISTORY_CITATIONS,
        )
        cases = _build_similar_cases(result)
        assert len(cases) == 2
        assert cases[0].case_id == "case-h00001"
        assert cases[0].event_type == EventType.DATA_EXFILTRATION
        assert cases[0].risk_score == 85

    def test_prefers_same_event_type_when_provided(self):
        mixed = [
            *_HISTORY_CHUNKS,
            _make_chunk(
                "hist-other",
                "history_case_kb",
                "unrelated host compromise",
                score=0.99,
                metadata={
                    "case_id": "case-h-other",
                    "event_type": "host_compromise",
                    "summary": "Emotet on another host",
                    "final_verdict": "confirmed_threat",
                    "risk_score": 92,
                },
            ),
        ]
        result = RetrievalResult(query="", chunks=mixed, citations=[])
        cases = _build_similar_cases(result, event_type=EventType.DATA_EXFILTRATION)
        assert {item.case_id for item in cases} == {"case-h00001", "case-h00002"}
        assert all(item.event_type is EventType.DATA_EXFILTRATION for item in cases)

    def test_empty_result_returns_empty(self):
        assert _build_similar_cases(None) == []

    def test_handles_invalid_enum_values(self):
        chunk = _make_chunk(
            "hist-99",
            "history_case_kb",
            "test",
            score=0.5,
            metadata={
                "case_id": "case-99",
                "event_type": "invalid_type",
                "final_verdict": "invalid_verdict",
                "summary": "test",
                "risk_score": 50,
            },
        )
        result = RetrievalResult(query="", chunks=[chunk], citations=[])
        cases = _build_similar_cases(result)
        assert len(cases) == 1
        assert cases[0].event_type is None
        assert cases[0].final_verdict is None


class TestBuildPlaybookRefs:
    def test_extracts_playbook_ids(self):
        result = RetrievalResult(
            query="",
            chunks=_PLAYBOOK_CHUNKS,
            citations=_PLAYBOOK_CITATIONS,
        )
        refs = _build_playbook_refs(result)
        assert len(refs) == 2
        ids = {ref.playbook_id for ref in refs}
        assert "pb-a1b2c3d4" in ids
        assert "pb-b2c3d4e5" in ids

    def test_deduplicates_playbook_ids(self):
        meta = {
            "playbook_id": "pb-a1b2c3d4",
            "release_id": "krel-test00000001",
            "release_version": "v1",
            "playbook_object_hash": "a" * 64,
            "bundle_content_hash": "b" * 64,
            "revision": 1,
        }
        chunks = [
            _make_chunk("p1", "playbook_kb", "v1", score=0.9, metadata=meta),
            _make_chunk("p2", "playbook_kb", "v2", score=0.7, metadata=dict(meta)),
        ]
        result = RetrievalResult(query="", chunks=chunks, citations=[])
        refs = _build_playbook_refs(result)
        assert len(refs) == 1
        assert refs[0].playbook_id == "pb-a1b2c3d4"

    def test_empty_result_returns_empty(self):
        assert _build_playbook_refs(None) == []


class TestBuildOrgContextMatches:
    def test_projects_exact_hits(self):
        result = RetrievalResult(
            query="",
            chunks=_ORG_CONTEXT_CHUNKS,
            citations=_ORG_CONTEXT_CITATIONS,
        )
        matches = _build_org_context_matches(result)
        assert len(matches) == 1
        assert matches[0].kind == "allowed_destination"
        assert matches[0].matched_value == "files.corp.internal"
        assert matches[0].match_type == "domain_exact"
        assert matches[0].citation_id == "cit-0c000001"

    def test_skips_unknown_kind(self):
        chunk = _make_chunk(
            "org-bad",
            "org_context_kb",
            "untyped note",
            metadata={"kind": "not_a_kind", "matched_value": "x"},
        )
        result = RetrievalResult(
            query="",
            chunks=[chunk],
            citations=[_make_knowledge_citation("cit-0c000099", "org-bad", "org_context_kb")],
        )
        assert _build_org_context_matches(result) == []

    def test_skips_keyword_guesses_even_with_kind_metadata(self):
        chunk = _make_chunk(
            "org-hyb",
            "org_context_kb",
            "files.corp.internal is an approved internal file-server destination.",
            retrieval_method="keyword",
            metadata={
                "kind": "allowed_destination",
                "domains": ["files.corp.internal"],
                "matched_value": "files.corp.internal",
                "match_type": "domain_exact",
            },
        )
        result = RetrievalResult(
            query="",
            chunks=[chunk],
            citations=[_make_knowledge_citation("cit-0c000088", "org-hyb", "org_context_kb")],
        )
        assert _build_org_context_matches(result) == []

    def test_hybrid_fallback_chunks_are_not_typed_matches(self):
        for method in ("vector", "reranked", "hybrid"):
            chunk = _make_chunk(
                f"org-{method}",
                "org_context_kb",
                "files.corp.internal is an approved internal file-server destination.",
                retrieval_method=method,
                metadata={
                    "kind": "allowed_destination",
                    "domains": ["files.corp.internal"],
                    "matched_value": "files.corp.internal",
                    "match_type": "domain_exact",
                },
            )
            result = RetrievalResult(
                query="",
                chunks=[chunk],
                citations=[
                    _make_knowledge_citation("cit-0c000077", chunk.chunk_id, "org_context_kb")
                ],
            )
            assert _build_org_context_matches(result) == []

    def test_empty_result_returns_empty(self):
        assert _build_org_context_matches(None) == []
        assert _build_org_context_matches(RetrievalResult(query="")) == []

    def test_projects_restricted_domain_hits(self):
        chunk = _make_chunk(
            "org-deny",
            "org_context_kb",
            "unknown-upload-example.com is not an approved destination.",
            retrieval_method="exact",
            metadata={
                "kind": "data_handling",
                "matched_value": "unknown-upload-example.com",
                "match_type": "restricted_domain",
            },
        )
        result = RetrievalResult(
            query="",
            chunks=[chunk],
            citations=[_make_knowledge_citation("cit-0c000066", "org-deny", "org_context_kb")],
        )
        matches = _build_org_context_matches(result)
        assert len(matches) == 1
        assert matches[0].kind == "data_handling"
        assert matches[0].match_type == "restricted_domain"
        assert matches[0].matched_value == "unknown-upload-example.com"

    def test_merge_prefers_catalog_then_fills_retrieved(self):
        from app.models.agent_io import OrgContextMatch

        catalog = [
            OrgContextMatch(
                kind="data_handling",
                matched_value="unknown-upload-example.com",
                explanation="not approved",
                citation_id="cit-catalog",
                chunk_id="chk-deny",
                match_type="restricted_domain",
            )
        ]
        retrieved = [
            OrgContextMatch(
                kind="data_handling",
                matched_value="unknown-upload-example.com",
                explanation="retrieved duplicate",
                citation_id="cit-retrieved",
                chunk_id="chk-deny",
                match_type="restricted_domain",
            ),
            OrgContextMatch(
                kind="allowed_destination",
                matched_value="files.corp.internal",
                explanation="approved",
                citation_id="cit-allow",
                chunk_id="chk-allow",
                match_type="domain_exact",
            ),
        ]
        merged = _merge_org_context_matches(catalog, retrieved)
        assert [m.chunk_id for m in merged] == ["chk-deny", "chk-allow"]
        assert merged[0].citation_id == "cit-catalog"


@pytest.mark.asyncio
async def test_catalog_overlay_fills_matches_when_hybrid_retrieval_has_none() -> None:
    from datetime import UTC, datetime

    from app.knowledge.org_context_seed import mock_org_context_records, records_to_chunks
    from app.models.entities import DomainEntity
    from app.models.knowledge import ListedKnowledgeChunk

    listed = [
        ListedKnowledgeChunk(
            chunk_id=chunk.chunk_id,
            kb_name=chunk.kb_name,
            content=chunk.content,
            metadata=chunk.metadata,
            created_at=datetime(2026, 8, 24, 15, 0, tzinfo=UTC),
        )
        for chunk in records_to_chunks(mock_org_context_records())
    ]

    class _Store:
        async def list_chunks(self, **kwargs):  # noqa: ANN003
            page = int(kwargs.get("page") or 1)
            return listed if page == 1 else []

    class _Retriever:
        _store = _Store()

    pipeline = _MockPipeline(results=_make_full_results())
    pipeline._retriever = _Retriever()  # type: ignore[attr-defined]
    wm = _MockBoundWorkingMemory()
    agent = RAGAgent(working_memory=wm, pipeline=pipeline)
    triage = _make_triage_result()
    triage = triage.model_copy(
        update={
            "entities": triage.entities.model_copy(
                update={
                    "domains": [
                        DomainEntity(entity_id="d1", fqdn="unknown-upload-example.com"),
                    ]
                }
            )
        }
    )
    output = await agent._run(
        RAGAgentInput(
            event_id="evt-org-overlay",
            triage_result=triage,
            tenant_id="tenant-demo",
        )
    )
    assert any(
        match.kind == "data_handling"
        and match.match_type == "restricted_domain"
        and match.matched_value == "unknown-upload-example.com"
        for match in output.org_context_matches
    )


class TestAggregateRetrievalMetrics:
    def test_wall_clock_is_max_and_rewrite_calls_are_summed(self):
        results = {
            "attack_kb": RetrievalResult(
                query="",
                retrieval_metrics=RetrievalMetrics(
                    rewrite_ms=40.0,
                    retrieve_ms=12.0,
                    rrf_ms=1.0,
                    rerank_ms=3.0,
                    total_ms=50.0,
                    llm_rewrite_calls=1,
                ),
            ),
            "org_context_kb": RetrievalResult(
                query="",
                retrieval_metrics=RetrievalMetrics(
                    rewrite_ms=0.0,
                    retrieve_ms=8.0,
                    rrf_ms=0.0,
                    rerank_ms=0.0,
                    total_ms=9.0,
                    llm_rewrite_calls=0,
                    org_context_exact_hit=True,
                ),
            ),
            "fp_case_kb": None,
        }
        metrics = _aggregate_retrieval_metrics(results)
        assert metrics.total_ms == 59.0
        assert metrics.rewrite_ms == 40.0
        assert metrics.retrieve_ms == 12.0
        assert metrics.llm_rewrite_calls == 1
        assert metrics.org_context_exact_hit is True
        assert metrics.constraint_channel is False

    def test_wall_clock_falls_back_to_max_without_org_key(self):
        results = {
            "attack_kb": RetrievalResult(
                query="",
                retrieval_metrics=RetrievalMetrics(total_ms=50.0, constraint_channel=True),
            ),
            "fp_case_kb": RetrievalResult(
                query="",
                retrieval_metrics=RetrievalMetrics(total_ms=12.0),
            ),
        }
        metrics = _aggregate_retrieval_metrics(results)
        assert metrics.total_ms == 50.0
        assert metrics.constraint_channel is True


class TestAggregateCitations:
    def test_aggregates_all_citations(self):
        results = {
            "attack_kb": RetrievalResult(query="", citations=_ATTACK_CITATIONS),
            "fp_case_kb": RetrievalResult(query="", citations=_FP_CITATIONS),
            "history_case_kb": RetrievalResult(query="", citations=_HISTORY_CITATIONS),
            "playbook_kb": RetrievalResult(query="", citations=_PLAYBOOK_CITATIONS),
            "org_context_kb": RetrievalResult(query="", citations=_ORG_CONTEXT_CITATIONS),
        }
        aggregated = _aggregate_citations(results)
        expected_count = (
            len(_ATTACK_CITATIONS)
            + len(_FP_CITATIONS)
            + len(_HISTORY_CITATIONS)
            + len(_PLAYBOOK_CITATIONS)
            + len(_ORG_CONTEXT_CITATIONS)
        )
        assert len(aggregated) == expected_count

    def test_deduplicates_by_citation_id(self):
        results = {
            "attack_kb": RetrievalResult(query="", citations=_ATTACK_CITATIONS),
            "fp_case_kb": RetrievalResult(query="", citations=_ATTACK_CITATIONS),
        }
        aggregated = _aggregate_citations(results)
        assert len(aggregated) == len(_ATTACK_CITATIONS)

    def test_handles_none_results(self):
        results: dict = {"attack_kb": None, "fp_case_kb": None}
        assert _aggregate_citations(results) == []

    def test_clips_relevance_score(self):
        c = _make_knowledge_citation("cit-99999999", "chk-1", "test_kb", "x", relevance_score=1.5)
        results = {"test_kb": RetrievalResult(query="", citations=[c])}
        aggregated = _aggregate_citations(results)
        assert 0.0 <= aggregated[0].relevance_score <= 1.0


# --------------------------------------------------------------------------- #
# Tests: RAGAgent
# --------------------------------------------------------------------------- #


class TestRAGAgentBasic:
    @pytest.mark.asyncio
    async def test_main_scenario_returns_attack_techniques(self):
        """Main scenario: RAGOutput has >= 2 attack techniques each with citation_id."""
        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        output = await agent._run(input_)

        assert isinstance(output, RAGOutput)
        assert len(output.attack_techniques) >= 2
        for t in output.attack_techniques:
            assert t.citation_id, f"Technique {t.technique_id} missing citation_id"
        assert output.degraded is False

    @pytest.mark.asyncio
    async def test_main_scenario_includes_t1567_or_t1048(self):
        """At least one of T1567 or T1048 must appear in attack_techniques."""
        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        output = await agent._run(input_)

        technique_ids = {t.technique_id for t in output.attack_techniques}
        assert ("T1567" in technique_ids) or ("T1048" in technique_ids), (
            f"Expected T1567 or T1048, got {technique_ids}"
        )

    @pytest.mark.asyncio
    async def test_fp_scenario_high_similarity(self):
        """FP scenario: fp_similarity.max_score >= 0.7 with matched case."""
        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        output = await agent._run(input_)

        assert output.fp_similarity.max_score >= FP_LOW_THRESHOLD, (
            f"Expected fp max_score >= {FP_LOW_THRESHOLD}, got {output.fp_similarity.max_score}"
        )
        assert output.fp_similarity.matched_case_id is not None

    @pytest.mark.asyncio
    async def test_similar_cases_and_playbook_refs(self):
        """RAGOutput contains similar_cases and playbook_refs."""
        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        output = await agent._run(input_)

        assert len(output.similar_cases) >= 1
        assert len(output.playbook_refs) >= 1
        assert len(output.org_context_matches) >= 1
        assert output.org_context_matches[0].kind == "allowed_destination"

    @pytest.mark.asyncio
    async def test_citations_aggregated(self):
        """RAGOutput citations are aggregated from all KBs."""
        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        output = await agent._run(input_)

        assert len(output.citations) >= 4

    @pytest.mark.asyncio
    async def test_writes_rag_output_to_event_context(self):
        """rag_output is persisted to working memory."""
        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        await agent._run(input_)

        stored = await wm.read("evt-001", "rag_output")
        assert stored is not None
        assert isinstance(stored, dict)
        assert "attack_techniques" in stored

    @pytest.mark.asyncio
    async def test_run_issues_five_retrieve_calls(self):
        """Each knowledge base is queried exactly once."""
        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        await agent._run(_make_input())

        assert len(pipeline.calls) == 5
        assert pipeline.calls[0]["kb_names"] == ["org_context_kb"]
        called_kbs = {call["kb_names"][0] for call in pipeline.calls}
        assert called_kbs == {
            "attack_kb",
            "fp_case_kb",
            "history_case_kb",
            "playbook_kb",
            "org_context_kb",
        }
        org_ctx = pipeline.calls[0]["context"]
        assert org_ctx.org_constraints == ()
        other_constraints = [call["context"].org_constraints for call in pipeline.calls[1:]]
        assert all(other_constraints)
        assert all(
            item.kind == "allowed_destination" and item.value == "files.corp.internal"
            for constraints in other_constraints
            for item in constraints
        )

    @pytest.mark.asyncio
    async def test_org_exact_hit_still_retrieves_attack_kb(self):
        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        results["org_context_kb"] = results["org_context_kb"].model_copy(
            update={
                "retrieval_metrics": RetrievalMetrics(
                    llm_rewrite_calls=0,
                    org_context_exact_hit=True,
                    total_ms=4.0,
                )
            }
        )
        for kb_name in ("attack_kb", "fp_case_kb", "history_case_kb", "playbook_kb"):
            results[kb_name] = results[kb_name].model_copy(
                update={"retrieval_metrics": RetrievalMetrics(llm_rewrite_calls=0, total_ms=10.0)}
            )
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        output = await agent._run(_make_input())

        called_kbs = {call["kb_names"][0] for call in pipeline.calls}
        assert "attack_kb" in called_kbs
        assert "org_context_kb" in called_kbs
        assert output.retrieval_metrics is not None
        assert output.retrieval_metrics.llm_rewrite_calls == 0
        assert output.retrieval_metrics.org_context_exact_hit is True
        assert output.retrieval_metrics.total_ms == 14.0
        assert output.org_context_matches
        assert output.attack_techniques

    @pytest.mark.asyncio
    async def test_conflict_raises_attack_top_k(self):
        wm = _MockBoundWorkingMemory()
        pipeline = _MockPipeline(results=_make_full_results())
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)
        evidence = EvidenceOutput(
            evidence_list=[
                Evidence(
                    evidence_id="evd-dlp-1",
                    event_id="evt-001",
                    source=EvidenceSource.DATA_SECURITY,
                    evidence_type="file_access",
                    description="dlp blocked sensitive upload",
                    confidence=0.9,
                    raw_data={"dlp_blocked": True},
                )
            ],
            collection_status=CollectionStatus.COMPLETED,
            overall_confidence=0.8,
            success_sources=["data_security"],
        )
        await agent._run(_make_input(evidence_output=evidence))
        attack_calls = [call for call in pipeline.calls if call["kb_names"] == ["attack_kb"]]
        assert attack_calls
        assert attack_calls[0]["top_k"] == 8
        assert all(call["context"].has_evidence_conflict for call in pipeline.calls)
        other = [call for call in pipeline.calls if call["kb_names"] != ["attack_kb"]]
        assert other
        assert all(call["top_k"] == 5 for call in other)

    @pytest.mark.asyncio
    async def test_run_propagates_retrieval_context(self):
        """RetrievalContext carries event/tenant/principal/trace into pipeline calls."""
        wm = _MockBoundWorkingMemory()
        pipeline = _MockPipeline(results=_make_full_results())
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input().model_copy(
            update={
                "tenant_id": "tenant-alpha",
                "principal": "investigation:super_agent",
                "trace_id": "trace-xyz",
            }
        )
        await agent._run(input_)

        contexts = [call["context"] for call in pipeline.calls]
        assert len(contexts) == 5
        assert all(ctx.event_id == "evt-001" for ctx in contexts)
        assert all(ctx.tenant_id == "tenant-alpha" for ctx in contexts)
        assert all(ctx.principal == "investigation:super_agent" for ctx in contexts)
        assert all(ctx.trace_id == "trace-xyz" for ctx in contexts)

    @pytest.mark.asyncio
    async def test_concurrent_runs_isolate_retrieval_context(self):
        """Concurrent RAG invocations must not cross-contaminate tenant/trace context."""
        wm = _MockBoundWorkingMemory()

        class _RecordingPipeline:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []

            async def retrieve(
                self,
                query: str,
                kb_names: list[str],
                top_k: int = 5,
                *,
                context: object,
            ) -> RetrievalResult:
                self.calls.append(
                    {
                        "query": query,
                        "kb_names": kb_names,
                        "context": context,
                    }
                )
                return RetrievalResult(query=query)

        pipeline_a = _RecordingPipeline()
        pipeline_b = _RecordingPipeline()
        agent_a = RAGAgent(working_memory=wm, pipeline=pipeline_a)
        agent_b = RAGAgent(working_memory=wm, pipeline=pipeline_b)

        input_a = _make_input().model_copy(
            update={
                "event_id": "evt-a",
                "tenant_id": "tenant-a",
                "trace_id": "trace-a",
            }
        )
        input_b = _make_input().model_copy(
            update={
                "event_id": "evt-b",
                "tenant_id": "tenant-b",
                "trace_id": "trace-b",
            }
        )
        await asyncio.gather(agent_a._run(input_a), agent_b._run(input_b))

        contexts_a = [call["context"] for call in pipeline_a.calls]
        contexts_b = [call["context"] for call in pipeline_b.calls]
        assert all(ctx.event_id == "evt-a" for ctx in contexts_a)
        assert all(ctx.tenant_id == "tenant-a" for ctx in contexts_a)
        assert all(ctx.trace_id == "trace-a" for ctx in contexts_a)
        assert all(ctx.event_id == "evt-b" for ctx in contexts_b)
        assert all(ctx.tenant_id == "tenant-b" for ctx in contexts_b)
        assert all(ctx.trace_id == "trace-b" for ctx in contexts_b)


class TestRAGAgentDegraded:
    @pytest.mark.asyncio
    async def test_single_kb_failure_does_not_interrupt(self):
        """When one KB fails, the other four return results normally."""
        wm = _MockBoundWorkingMemory()
        full = _make_full_results()
        results = {
            "attack_kb": full["attack_kb"],
            "fp_case_kb": RuntimeError("FP KB unavailable"),
            "history_case_kb": full["history_case_kb"],
            "playbook_kb": full["playbook_kb"],
        }
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        output = await agent._run(input_)

        # Attack techniques should still be present.
        assert len(output.attack_techniques) >= 2
        # FP similarity should be default (KB failed).
        assert output.fp_similarity.max_score == 0.0
        # Similar cases and playbook refs should be present.
        assert len(output.similar_cases) >= 1
        assert len(output.playbook_refs) >= 1
        # Not fully degraded (4 of 5 KBs succeeded).
        assert output.degraded is False

    @pytest.mark.asyncio
    async def test_all_kb_failure_degraded(self):
        """When all KBs fail, degraded=true with complete output structure."""
        wm = _MockBoundWorkingMemory()
        results: dict = {
            "attack_kb": RuntimeError("DB down"),
            "fp_case_kb": RuntimeError("DB down"),
            "history_case_kb": RuntimeError("DB down"),
            "playbook_kb": RuntimeError("DB down"),
            "org_context_kb": RuntimeError("DB down"),
        }
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        output = await agent._run(input_)

        assert output.degraded is True
        assert output.attack_techniques == []
        assert output.fp_similarity.max_score == 0.0
        assert output.similar_cases == []
        assert output.playbook_refs == []
        assert output.org_context_matches == []
        assert output.citations == []

    @pytest.mark.asyncio
    async def test_soft_time_limit_is_not_swallowed_as_empty_retrieval(self):
        """ISSUE-314: SoftTimeLimitExceeded must not degrade into empty RAG success."""
        from celery.exceptions import SoftTimeLimitExceeded

        wm = _MockBoundWorkingMemory()
        full = _make_full_results()
        results = {
            "attack_kb": SoftTimeLimitExceeded(),
            "fp_case_kb": full["fp_case_kb"],
            "history_case_kb": full["history_case_kb"],
            "playbook_kb": full["playbook_kb"],
        }
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        with pytest.raises(SoftTimeLimitExceeded):
            await agent._run(_make_input())

    @pytest.mark.asyncio
    async def test_no_pipeline_returns_degraded(self):
        """When no pipeline is provided, return degraded empty output."""
        wm = _MockBoundWorkingMemory()
        agent = RAGAgent(working_memory=wm, pipeline=None)

        input_ = _make_input()
        output = await agent._run(input_)

        assert output.degraded is True

    @pytest.mark.asyncio
    async def test_fixture_fallback_wiring_never_calls_pipeline(self):
        """Fixture-loaded resources attach pipeline=None; RAGAgent must not retrieve."""
        from app.core.config import Settings
        from app.rag.resources import (
            get_loaded_retrieval_resources,
            reset_loaded_retrieval_resources,
        )

        reset_loaded_retrieval_resources()
        settings = Settings(app_env="development", retrieval_fixture_fallback=True)
        loaded = get_loaded_retrieval_resources(settings=settings)
        assert loaded.pipeline is None

        wm = _MockBoundWorkingMemory()
        spy_pipeline = _MockPipeline(results=_make_full_results())
        agent = RAGAgent(working_memory=wm, pipeline=loaded.pipeline)
        output = await agent._run(_make_input())

        assert output.degraded is True
        assert len(spy_pipeline.calls) == 0


class TestRAGAgentPersistence:
    @pytest.mark.asyncio
    async def test_transient_write_failure_marks_degraded(self):
        """When wm.write raises DependencyUnavailableError, output.degraded=True."""
        wm = _FailingWriteMockWM(
            writer_name="RAGAgent",
            fail_key="rag_output",
            fail_error=DependencyUnavailableError("Redis down"),
        )
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        output = await agent._run(input_)
        assert output.degraded is True

    @pytest.mark.asyncio
    async def test_guardrail_violation_propagates(self):
        """GuardrailViolationError is propagated, not swallowed."""
        wm = _FailingWriteMockWM(
            writer_name="RAGAgent",
            fail_key="rag_output",
            fail_error=GuardrailViolationError(
                "ownership mismatch",
                error_code="working_memory_unauthorized_write",
                details={},
            ),
        )
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        with pytest.raises(GuardrailViolationError):
            await agent._run(input_)

    @pytest.mark.asyncio
    async def test_non_retryable_shadowtrace_error_raises(self):
        """Non-retryable ShadowTraceError propagates."""
        wm = _FailingWriteMockWM(
            writer_name="RAGAgent",
            fail_key="rag_output",
            fail_error=ShadowTraceError(
                "Schema mismatch",
                error_code="schema_error",
                retryable=False,
            ),
        )
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        with pytest.raises(ShadowTraceError) as exc_info:
            await agent._run(input_)
        assert exc_info.value.error_code == "schema_error"


class TestRAGAgentTrace:
    """Verify that execute() writes agent traces."""

    @pytest.mark.asyncio
    async def test_execute_writes_completed_trace(self):
        """When execute() succeeds, trace_service.log_trace is called with completed status."""
        from unittest.mock import AsyncMock, MagicMock

        trace_svc = MagicMock()
        trace_svc.log_trace = AsyncMock()

        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(
            working_memory=wm,
            pipeline=pipeline,
            trace_service=trace_svc,
        )

        input_ = _make_input()
        output = await agent.execute(input_)

        assert isinstance(output, RAGOutput)
        assert output.degraded is False
        trace_svc.log_trace.assert_called_once()
        call_kwargs = trace_svc.log_trace.call_args.kwargs
        assert call_kwargs["agent_name"] == "rag_agent"
        assert call_kwargs["status"] == "completed"
        assert call_kwargs["event_id"] == "evt-001"

    @pytest.mark.asyncio
    async def test_execute_writes_trace_after_pipeline_error(self):
        """When all KBs fail, execute() still records a completed trace."""
        from unittest.mock import AsyncMock, MagicMock

        trace_svc = MagicMock()
        trace_svc.log_trace = AsyncMock()

        wm = _MockBoundWorkingMemory()
        # All five KBs fail → degraded=true, agent completes normally.
        pipeline = _MockPipeline(
            results={
                "attack_kb": RuntimeError("DB crash"),
                "fp_case_kb": RuntimeError("DB crash"),
                "history_case_kb": RuntimeError("DB crash"),
                "playbook_kb": RuntimeError("DB crash"),
                "org_context_kb": RuntimeError("DB crash"),
            }
        )

        agent = RAGAgent(
            working_memory=wm,
            pipeline=pipeline,
            trace_service=trace_svc,
        )

        input_ = _make_input()
        output = await agent.execute(input_)

        assert output.degraded is True
        trace_svc.log_trace.assert_called_once()
        call_kwargs = trace_svc.log_trace.call_args.kwargs
        assert call_kwargs["agent_name"] == "rag_agent"
        assert call_kwargs["status"] == "completed"

    @pytest.mark.asyncio
    async def test_agent_name_and_input_type_match(self):
        """RAGAgent.agent_name maps to RAGAgentInput in AGENT_INPUT_BY_NAME."""
        from app.models.agent_io import AGENT_INPUT_BY_NAME

        assert AGENT_INPUT_BY_NAME.get("rag_agent") is RAGAgentInput

    @pytest.mark.asyncio
    async def test_execute_without_trace_service_does_not_crash(self):
        """Agent works fine without trace_service injected."""
        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        agent = RAGAgent(working_memory=wm, pipeline=pipeline)

        input_ = _make_input()
        output = await agent.execute(input_)
        assert isinstance(output, RAGOutput)
        assert output.degraded is False

    @pytest.mark.asyncio
    async def test_wrong_input_type_raises_typeerror(self):
        """execute() raises TypeError when input doesn't match agent name."""
        agent = RAGAgent()
        input_ = TriageResult(  # type: ignore[call-arg]
            event_type=EventType.DATA_EXFILTRATION,
            severity=Severity.HIGH,
            need_investigation=True,
        )
        with pytest.raises(TypeError, match="requires RAGAgentInput"):
            await agent.execute(input_)  # type: ignore[arg-type]


def _make_active_release(
    release_id: str = "krel-aaaaaaaaaaaaaaaa",
    *,
    vector_ready: bool = False,
    embedding_release_id: str | None = None,
) -> KnowledgeRelease:
    from datetime import UTC, datetime

    from app.models.knowledge_release import (
        ATTACK_CORPUS_ID,
        ATTACK_SOURCE_ID,
        KnowledgeImportStatus,
        KnowledgeRelease,
        KnowledgeReleaseLifecycleState,
        KnowledgeReleaseProvenance,
    )

    return KnowledgeRelease(
        release_id=release_id,
        corpus_id=ATTACK_CORPUS_ID,
        source_id=ATTACK_SOURCE_ID,
        release_version="v15.1",
        content_hash="a" * 64,
        provenance=KnowledgeReleaseProvenance(source_path="fixture://test"),
        import_status=KnowledgeImportStatus.VALIDATED,
        lifecycle_state=KnowledgeReleaseLifecycleState.ACTIVE,
        vector_ready=vector_ready,
        embedding_release_id=embedding_release_id,
        idempotency_key=f"{ATTACK_CORPUS_ID}:{'a' * 64}",
        activated_at=datetime.now(UTC),
    )


class TestRAGAgentReleasePinning:
    @pytest.mark.asyncio
    async def test_pins_query_plan_in_output_and_trace_context(self):
        from unittest.mock import AsyncMock, MagicMock

        from app.core.config import Settings

        release = _make_active_release("krel-pin-test01")
        release_service = MagicMock()
        release_service.get_active_release = AsyncMock(return_value=release)

        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        settings = Settings(
            APP_ENV="development",
            EMBEDDING_MODE="mock",
            EMBEDDING_RELEASE_ID="emb-test-release",
        )
        agent = RAGAgent(
            working_memory=wm,
            pipeline=pipeline,
            knowledge_release_service=release_service,
            settings=settings,
        )

        output = await agent._run(_make_input())

        assert output.knowledge_query_plan is not None
        assert output.knowledge_query_plan["attack_kb"]["active_release_id"] == "krel-pin-test01"
        assert (
            output.knowledge_query_plan["attack_kb"]["embedding_release_id"] == "emb-test-release"
        )
        attack_calls = [c for c in pipeline.calls if c["kb_names"] == ["attack_kb"]]
        assert attack_calls
        assert attack_calls[0]["context"].query_plan is not None
        assert attack_calls[0]["context"].query_plan.active_release_id == "krel-pin-test01"

    @pytest.mark.asyncio
    async def test_output_includes_attack_and_playbook_plans(self):
        from unittest.mock import AsyncMock, MagicMock

        from app.core.config import Settings
        from app.models.knowledge_release import (
            KnowledgeImportStatus,
            KnowledgeRelease,
            KnowledgeReleaseLifecycleState,
            KnowledgeReleaseProvenance,
        )
        from app.models.playbook_release import PLAYBOOK_CORPUS_ID, PLAYBOOK_SOURCE_ID

        attack_release = _make_active_release("krel-dual-test01")
        attack_service = MagicMock()
        attack_service.get_active_release = AsyncMock(return_value=attack_release)

        playbook_release = KnowledgeRelease(
            release_id="pbrel-dual-test01",
            corpus_id=PLAYBOOK_CORPUS_ID,
            source_id=PLAYBOOK_SOURCE_ID,
            release_version="v1-dual",
            content_hash="d" * 64,
            provenance=KnowledgeReleaseProvenance(source_path="fixture://playbook-dual"),
            import_status=KnowledgeImportStatus.VALIDATED,
            lifecycle_state=KnowledgeReleaseLifecycleState.ACTIVE,
            vector_ready=True,
            embedding_release_id="emb-test-release",
            idempotency_key=f"{PLAYBOOK_CORPUS_ID}:{'d' * 64}",
        )
        playbook_service = MagicMock()
        playbook_service.get_active_release = AsyncMock(return_value=playbook_release)

        wm = _MockBoundWorkingMemory()
        pipeline = _MockPipeline(results=_make_full_results())
        settings = Settings(
            APP_ENV="development",
            EMBEDDING_MODE="mock",
            EMBEDDING_RELEASE_ID="emb-test-release",
        )
        agent = RAGAgent(
            working_memory=wm,
            pipeline=pipeline,
            knowledge_release_service=attack_service,
            playbook_release_service=playbook_service,
            settings=settings,
        )

        output = await agent._run(_make_input())

        assert output.knowledge_query_plan is not None
        assert output.knowledge_query_plan["attack_kb"]["active_release_id"] == "krel-dual-test01"
        assert (
            output.knowledge_query_plan["playbook_kb"]["active_release_id"] == "pbrel-dual-test01"
        )

    @pytest.mark.asyncio
    async def test_playbook_query_plan_accepted_by_real_pipeline(self):
        from unittest.mock import AsyncMock, MagicMock

        from app.core.config import Settings
        from app.core.llm.base import InMemoryLLMCallAuditRecorder
        from app.core.llm.mock_client import MockLLMClient
        from app.models.knowledge_release import (
            KnowledgeImportStatus,
            KnowledgeRelease,
            KnowledgeReleaseLifecycleState,
            KnowledgeReleaseProvenance,
        )
        from app.models.playbook_release import (
            PLAYBOOK_CORPUS_ID,
            PLAYBOOK_KB_NAME,
            PLAYBOOK_SOURCE_ID,
        )
        from app.rag.context import RetrievalContext
        from app.rag.pipeline import RetrievalPipeline
        from app.rag.query_rewriter import QueryRewriter
        from app.rag.reranker import MockReranker

        class _SelectiveRetriever:
            async def retrieve(
                self,
                queries: list[str],
                kb_names: list[str],
                top_k: int = 5,
                *,
                context: RetrievalContext,
            ) -> list[list[RetrievedChunk]]:
                kb_name = kb_names[0] if kb_names else "unknown"
                if kb_name == PLAYBOOK_KB_NAME:
                    return [[_PLAYBOOK_CHUNKS[0]], [_PLAYBOOK_CHUNKS[0]]]
                return [[], []]

        settings = Settings(
            APP_ENV="development",
            EMBEDDING_MODE="mock",
            EMBEDDING_RELEASE_ID="emb-test-release",
        )
        playbook_release = KnowledgeRelease(
            release_id="pbrel-pin-test01",
            corpus_id=PLAYBOOK_CORPUS_ID,
            source_id=PLAYBOOK_SOURCE_ID,
            release_version="v1-test",
            content_hash="c" * 64,
            provenance=KnowledgeReleaseProvenance(source_path="fixture://playbook-test"),
            import_status=KnowledgeImportStatus.VALIDATED,
            lifecycle_state=KnowledgeReleaseLifecycleState.ACTIVE,
            vector_ready=True,
            embedding_release_id="emb-test-release",
            idempotency_key=f"{PLAYBOOK_CORPUS_ID}:{'c' * 64}",
        )
        playbook_release_service = MagicMock()
        playbook_release_service.get_active_release = AsyncMock(return_value=playbook_release)

        pipeline = RetrievalPipeline(
            rewriter=QueryRewriter(
                MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
                agent_name="RAGAgent",
            ),
            retriever=_SelectiveRetriever(),
            reranker=MockReranker(),
            settings=settings,
        )
        agent = RAGAgent(
            working_memory=_MockBoundWorkingMemory(),
            pipeline=pipeline,
            knowledge_release_service=None,
            playbook_release_service=playbook_release_service,
            settings=settings,
        )

        output = await agent._run(_make_input())

        assert len(output.playbook_refs) >= 1
        assert output.playbook_refs[0].playbook_id == "pb-a1b2c3d4"

    @pytest.mark.asyncio
    async def test_blocks_attack_kb_without_active_release_when_required(self):
        from unittest.mock import AsyncMock, MagicMock

        from app.core.config import Settings

        release_service = MagicMock()
        release_service.get_active_release = AsyncMock(return_value=None)

        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        settings = Settings(
            APP_ENV="development",
            EMBEDDING_MODE="mock",
            KNOWLEDGE_RELEASE_REQUIRE_ACTIVE=True,
        )
        agent = RAGAgent(
            working_memory=wm,
            pipeline=pipeline,
            knowledge_release_service=release_service,
            settings=settings,
        )

        output = await agent._run(_make_input())

        assert output.attack_techniques == []
        attack_calls = [c for c in pipeline.calls if c["kb_names"] == ["attack_kb"]]
        assert attack_calls == []
        assert len([c for c in pipeline.calls if c["kb_names"] != ["attack_kb"]]) == 4

    @pytest.mark.asyncio
    async def test_production_blocks_attack_kb_without_active_release(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        from unittest.mock import AsyncMock, MagicMock

        release_service = MagicMock()
        release_service.get_active_release = AsyncMock(return_value=None)

        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        settings = production_settings(monkeypatch)
        agent = RAGAgent(
            working_memory=wm,
            pipeline=pipeline,
            knowledge_release_service=release_service,
            settings=settings,
        )

        output = await agent._run(
            _make_input().model_copy(update={"tenant_id": "tenant-prod-test"})
        )

        assert output.attack_techniques == []
        attack_calls = [c for c in pipeline.calls if c["kb_names"] == ["attack_kb"]]
        assert attack_calls == []

    @pytest.mark.asyncio
    async def test_dev_allows_unpinned_attack_kb_without_release_service(self):

        from app.core.config import Settings

        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        settings = Settings(APP_ENV="development", EMBEDDING_MODE="mock")
        agent = RAGAgent(
            working_memory=wm,
            pipeline=pipeline,
            knowledge_release_service=None,
            settings=settings,
        )

        output = await agent._run(_make_input())

        assert len(output.attack_techniques) >= 2
        attack_calls = [c for c in pipeline.calls if c["kb_names"] == ["attack_kb"]]
        assert len(attack_calls) == 1
        assert attack_calls[0]["context"].query_plan is None

    @pytest.mark.asyncio
    async def test_dev_blocks_attack_kb_when_release_service_has_no_active_release(self):
        from unittest.mock import AsyncMock, MagicMock

        from app.core.config import Settings

        release_service = MagicMock()
        release_service.get_active_release = AsyncMock(return_value=None)

        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        settings = Settings(APP_ENV="development", EMBEDDING_MODE="mock")
        agent = RAGAgent(
            working_memory=wm,
            pipeline=pipeline,
            knowledge_release_service=release_service,
            settings=settings,
        )

        output = await agent._run(_make_input())

        assert output.attack_techniques == []
        attack_calls = [c for c in pipeline.calls if c["kb_names"] == ["attack_kb"]]
        assert attack_calls == []

    @pytest.mark.asyncio
    async def test_blocks_playbook_kb_without_active_release_when_required(self):
        from unittest.mock import AsyncMock, MagicMock

        from app.core.config import Settings

        playbook_release_service = MagicMock()
        playbook_release_service.get_active_release = AsyncMock(return_value=None)

        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        settings = Settings(
            APP_ENV="development",
            EMBEDDING_MODE="mock",
            PLAYBOOK_RELEASE_REQUIRE_ACTIVE=True,
        )
        agent = RAGAgent(
            working_memory=wm,
            pipeline=pipeline,
            playbook_release_service=playbook_release_service,
            settings=settings,
        )

        output = await agent._run(_make_input())

        assert output.playbook_refs == []
        playbook_calls = [c for c in pipeline.calls if c["kb_names"] == ["playbook_kb"]]
        assert playbook_calls == []
        assert len(output.similar_cases) >= 1

    @pytest.mark.asyncio
    async def test_production_blocks_playbook_kb_without_active_release(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        from unittest.mock import AsyncMock, MagicMock

        playbook_release_service = MagicMock()
        playbook_release_service.get_active_release = AsyncMock(return_value=None)

        wm = _MockBoundWorkingMemory()
        results = _make_full_results()
        pipeline = _MockPipeline(results=results)
        settings = production_settings(monkeypatch)
        agent = RAGAgent(
            working_memory=wm,
            pipeline=pipeline,
            playbook_release_service=playbook_release_service,
            settings=settings,
        )

        output = await agent._run(
            _make_input().model_copy(update={"tenant_id": "tenant-prod-test"})
        )

        assert output.playbook_refs == []
        playbook_calls = [c for c in pipeline.calls if c["kb_names"] == ["playbook_kb"]]
        assert playbook_calls == []


class TestRAGAgentInputValidation:
    def test_rag_agent_input_accepts_none_evidence(self):
        """RAGAgentInput should accept evidence_output=None."""
        input_ = RAGAgentInput(
            event_id="evt-001",
            triage_result=_make_triage_result(),
            evidence_output=None,
        )
        assert input_.evidence_output is None

    def test_rag_agent_input_extra_forbid(self):
        """RAGAgentInput rejects extra fields."""
        with pytest.raises(pydantic.ValidationError):
            RAGAgentInput(
                event_id="evt-001",
                triage_result=_make_triage_result(),
                unknown_field="should_reject",  # type: ignore[call-arg]
            )


class TestRAGOutputSchema:
    def test_default_rag_output_is_valid(self):
        output = RAGOutput()
        assert output.degraded is False
        assert output.attack_techniques == []
        assert output.fp_similarity.max_score == 0.0
        assert output.similar_cases == []
        assert output.playbook_refs == []
        assert output.org_context_matches == []
        assert output.citations == []
        assert output.knowledge_query_plan is None
        assert output.degraded_steps == []

    def test_aggregate_degraded_steps_unique_order(self) -> None:
        from app.models.knowledge import RetrievalResult

        results = {
            "attack_kb": RetrievalResult(
                query="q",
                degraded_steps=["keyword_unavailable", "reranker"],
            ),
            "fp_case_kb": RetrievalResult(
                query="q",
                degraded_steps=["keyword_unavailable"],
            ),
            "history_case_kb": None,
        }
        assert _aggregate_degraded_steps(results) == [
            "keyword_unavailable",
            "reranker",
        ]

    def test_fp_similarity_score_bounds(self):
        with pytest.raises(pydantic.ValidationError):
            FpSimilarity(max_score=1.5)

    def test_attack_technique_confidence_bounds(self):
        with pytest.raises(pydantic.ValidationError):
            from app.models.agent_io import AttackTechniqueMatch

            AttackTechniqueMatch(
                technique_id="T1234",
                technique_name="Test",
                match_confidence=1.5,
                citation_id="cit-12345678",
            )
