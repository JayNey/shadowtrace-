"""Entity exact-hit, L_E, dedupe, fp assemble, and fetch_k tests (RAG P0)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agents.rag_agent import _assemble_fp_similarity, _build_fp_similarity
from app.agents.rag_query_builder import RAGQueryBuilder
from app.models.agent_io import TriageResult
from app.models.entities import AccountEntity, DomainEntity, EntitySet, HostEntity, ProcessEntity
from app.models.enums import EventType, Severity
from app.models.knowledge import RetrievalResult, RetrievedChunk
from app.rag.context import RetrievalContext
from app.rag.entity_rrf import (
    EntityToken,
    dedupe_retrieved_chunks,
    entity_hits_chunk,
    extract_investigation_entities,
    project_entities_for_kb,
    promote_fp_exact_match,
)
from app.rag.hybrid_retriever import HybridRetriever, fetch_k_for_kb
from app.rag.keyword_aliases import keyword_queries_for_kb
from app.rag.rrf_fusion import rrf_fuse


def _chunk(
    chunk_id: str,
    *,
    kb_name: str = "fp_case_kb",
    content: str = "",
    score: float = 0.5,
    metadata: dict | None = None,
) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk_id,
        kb_name=kb_name,
        content=content,
        score=score,
        retrieval_method="hybrid",
        metadata=metadata or {},
    )


def _triage(
    *,
    event_type: EventType = EventType.ACCOUNT_ANOMALY,
    severity: Severity = Severity.LOW,
    account: str | None = "ops-change-bot",
    host: str | None = "PC-OPS-JUMP-01",
    process: str | None = None,
    domain: str | None = None,
) -> TriageResult:
    return TriageResult(
        event_type=event_type,
        severity=severity,
        need_investigation=True,
        entities=EntitySet(
            accounts=(
                [AccountEntity(entity_id="a1", entity_type="account", username=account)]
                if account
                else []
            ),
            hosts=([HostEntity(entity_id="h1", entity_type="host", hostname=host)] if host else []),
            processes=(
                [ProcessEntity(entity_id="p1", entity_type="process", name=process)]
                if process
                else []
            ),
            domains=(
                [DomainEntity(entity_id="d1", entity_type="domain", fqdn=domain)] if domain else []
            ),
        ),
    )


class TestExactHit:
    def test_field_exact_hits_account_and_host(self) -> None:
        chunk = _chunk(
            "fp-01",
            content="ops-change-bot rotated passwords on PC-OPS-JUMP-01",
            metadata={
                "case_id": "case-00000001",
                "entity_pattern": "account=ops-change-bot; host=PC-OPS-JUMP-01",
            },
        )
        assert entity_hits_chunk("ops-change-bot", chunk) is True
        assert entity_hits_chunk("PC-OPS-JUMP-01", chunk) is True

    def test_glob_never_hits(self) -> None:
        chunk = _chunk(
            "fp-0d",
            content="finance fileshare sync",
            metadata={
                "case_id": "case-0000000d",
                "entity_pattern": "host=PC-FIN-*; account=finance-*",
            },
        )
        assert entity_hits_chunk("PC-FIN-023", chunk) is False
        assert entity_hits_chunk("PC-FIN-*", chunk) is False

    def test_pc_fin_does_not_hit_pc_fin_023(self) -> None:
        chunk = _chunk(
            "fp-023",
            content="account=zhangsan host=PC-FIN-023 packed finance_report.zip",
            metadata={"entity_pattern": "host=PC-FIN-023; account=zhangsan"},
        )
        assert entity_hits_chunk("PC-FIN", chunk) is False
        assert entity_hits_chunk("PC-FIN-023", chunk) is True

    def test_token_bounded_hyphen_counterexample(self) -> None:
        """Lookaround includes '-' so this is the _token_bounded anti-case."""
        chunk = _chunk("x", kb_name="attack_kb", content="PC-FIN-023")
        assert entity_hits_chunk("PC-FIN", chunk) is False
        assert entity_hits_chunk("PC-FIN-023", chunk) is True

    def test_dotted_names_are_not_hyphen_bounded_substrings(self) -> None:
        exe = _chunk("atk-cmd", kb_name="attack_kb", content="spawned cmd.exe on host")
        assert entity_hits_chunk("cmd", exe) is False
        assert entity_hits_chunk("cmd.exe", exe) is True
        domain = _chunk(
            "atk-corp",
            kb_name="attack_kb",
            content="beacon to files.corp.internal",
        )
        assert entity_hits_chunk("corp", domain) is False
        assert entity_hits_chunk("files.corp.internal", domain) is True

    def test_fp_negation_process_in_reason_is_not_a_hit(self) -> None:
        """Loaded 0d says 没有 7z.exe; that must not exact-hit insider process."""
        chunk = _chunk(
            "fp-0d",
            content=(
                "财务主机向批准的内部文件服务器 files.corp.internal 同步报表，无 7z 外发 | "
                "account=finance-* type=employee; host=PC-FIN-*; domain=files.corp.internal | "
                "目标为集团批准内部文件服务器，不是 unknown-upload-example.com，"
                "也没有 7z.exe 打包外发"
            ),
            metadata={
                "case_id": "case-0000000d",
                "entity_pattern": (
                    "account=finance-* type=employee; host=PC-FIN-*; "
                    "domain=files.corp.internal; behavior=approved_fileshare_sync"
                ),
                "fp_reason": "也没有 7z.exe 打包外发",
            },
        )
        assert entity_hits_chunk("PC-FIN-023", chunk) is False
        assert entity_hits_chunk("zhangsan", chunk) is False
        assert entity_hits_chunk("7z.exe", chunk) is False
        attack = _chunk(
            "atk-t1560",
            kb_name="attack_kb",
            content="Alert on 7z.exe packing finance_report.zip on PC-FIN-023",
        )
        assert entity_hits_chunk("7z.exe", attack) is True
        assert entity_hits_chunk("PC-FIN-023", attack) is True


class TestFpAssemble:
    def test_promotes_exact_hit_and_lifts_score_to_list_max(self) -> None:
        chunk_0d = _chunk(
            "fp-0d",
            content="files.corp.internal fileshare",
            score=1.0,
            metadata={
                "case_id": "case-0000000d",
                "entity_pattern": "host=PC-FIN-*",
                "pattern_summary": "fileshare",
            },
        )
        chunk_01 = _chunk(
            "fp-01",
            content="ops-change-bot on PC-OPS-JUMP-01",
            score=0.35,
            metadata={
                "case_id": "case-00000001",
                "entity_pattern": "account=ops-change-bot; host=PC-OPS-JUMP-01",
                "pattern_summary": "change window",
            },
        )
        entities = (
            EntityToken("account", "ops-change-bot"),
            EntityToken("host", "PC-OPS-JUMP-01"),
        )
        result = RetrievalResult(query="q", chunks=[chunk_0d, chunk_01])
        fp, updated = _assemble_fp_similarity(result, entities=entities)
        assert updated is not None
        assert updated.chunks[0].metadata["case_id"] == "case-00000001"
        assert updated.citations
        assert updated.citations[0].chunk_id == "fp-01"
        assert fp.matched_case_id == "case-00000001"
        assert fp.max_score == pytest.approx(1.0)
        assert fp.max_score != pytest.approx(0.35)

    def test_glob_is_not_an_exact_hit(self) -> None:
        chunk_0d = _chunk(
            "fp-0d",
            score=1.0,
            metadata={
                "case_id": "case-0000000d",
                "entity_pattern": "host=PC-FIN-*",
            },
        )
        chunk_01 = _chunk(
            "fp-01",
            score=0.4,
            content="Account ops-change-bot Host PC-OPS-JUMP-01",
            metadata={
                "case_id": "case-00000001",
                "entity_pattern": "account=ops-change-bot; host=PC-OPS-JUMP-01",
            },
        )
        entities = (
            EntityToken("account", "ops-change-bot"),
            EntityToken("host", "PC-OPS-JUMP-01"),
        )
        promoted = promote_fp_exact_match([chunk_0d, chunk_01], entities)
        assert promoted[0].metadata["case_id"] == "case-00000001"
        assert promoted[0].score == pytest.approx(1.0)

    def test_no_exact_clears_id_and_score(self) -> None:
        chunk = _chunk(
            "fp-0d",
            score=1.0,
            metadata={"case_id": "case-0000000d", "entity_pattern": "host=PC-FIN-*"},
        )
        entities = (EntityToken("account", "zhangsan"), EntityToken("host", "PC-FIN-023"))
        fp = _build_fp_similarity(
            RetrievalResult(query="q", chunks=[chunk]),
            entities=entities,
        )
        assert fp.matched_case_id is None
        assert fp.max_score == 0.0

    def test_insider_pool_only_0d_clears(self) -> None:
        chunk_0d = _chunk(
            "fp-0d",
            content=(
                "财务主机向批准的内部文件服务器 files.corp.internal 同步报表，无 7z 外发 | "
                "也没有 7z.exe 打包外发"
            ),
            score=1.0,
            metadata={
                "case_id": "case-0000000d",
                "entity_pattern": "host=PC-FIN-*; account=finance-*",
                "fp_reason": "也没有 7z.exe 打包外发",
            },
        )
        entities = extract_investigation_entities(
            _triage(
                event_type=EventType.DATA_EXFILTRATION,
                severity=Severity.CRITICAL,
                account="zhangsan",
                host="PC-FIN-023",
                process="7z.exe",
            )
        )
        fp, updated = _assemble_fp_similarity(
            RetrievalResult(query="q", chunks=[chunk_0d]),
            entities=entities,
        )
        assert fp.matched_case_id is None
        assert fp.max_score == 0.0
        assert updated is not None
        assert updated.chunks[0].metadata["case_id"] == "case-0000000d"

    def test_empty_entities_clear_id_and_score(self) -> None:
        chunk = _chunk(
            "fp-01",
            score=0.88,
            metadata={"case_id": "case-00000001", "pattern_summary": "window"},
        )
        fp = _build_fp_similarity(RetrievalResult(query="q", chunks=[chunk]))
        assert fp.matched_case_id is None
        assert fp.max_score == 0.0

    def test_single_account_votes(self) -> None:
        chunk = _chunk(
            "fp-01",
            score=0.5,
            metadata={
                "case_id": "case-00000001",
                "entity_pattern": "account=ops-change-bot",
            },
        )
        entities = (EntityToken("account", "ops-change-bot"),)
        fp, updated = _assemble_fp_similarity(
            RetrievalResult(query="q", chunks=[chunk]),
            entities=entities,
        )
        assert fp.matched_case_id == "case-00000001"
        assert updated is not None
        assert updated.chunks[0].score == pytest.approx(0.5)


class TestQueryRewriteAndKeywordQueue:
    def test_fp_query_account_then_host_no_allowlist(self) -> None:
        triage = _triage(domain="files.corp.internal", process="net.exe")
        query = RAGQueryBuilder.build_queries(triage)["fp_case_kb"]
        assert "Account:ops-change-bot" in query
        assert "Host:PC-OPS-JUMP-01" in query
        account_at = query.index("Account:ops-change-bot")
        host_at = query.index("Host:PC-OPS-JUMP-01")
        process_at = query.index("Process:net.exe")
        assert account_at < host_at < process_at
        assert "files.corp.internal" not in query
        assert "cdn.corp.internal" not in query
        assert "carbonblack.corp.internal" not in query
        assert "Domain:" not in query
        assert "IP:" not in query

    def test_keyword_and_occupies_first_slot_for_change_window(self) -> None:
        triage = _triage()
        query = RAGQueryBuilder.build_queries(triage)["fp_case_kb"]
        roads = keyword_queries_for_kb("fp_case_kb", query, limit=2)
        assert any("ops-change-bot" in road and "PC-OPS-JUMP-01" in road for road in roads), roads
        first = roads[0]
        assert "ops-change-bot" in first
        assert "PC-OPS-JUMP-01" in first
        assert "net.exe" not in first
        assert "valid accounts" not in first or first != "valid accounts"

    def test_process_not_in_and_first_two_slots(self) -> None:
        triage = _triage(process="ransomware_stage.exe")
        query = RAGQueryBuilder.build_queries(triage)["fp_case_kb"]
        roads = keyword_queries_for_kb("fp_case_kb", query, limit=2)
        first = roads[0]
        assert "ops-change-bot" in first
        assert "PC-OPS-JUMP-01" in first
        assert "ransomware_stage.exe" not in first
        assert "Process:ransomware_stage.exe" in query

    def test_reasoning_host_label_does_not_steal_and_slots(self) -> None:
        triage = _triage()
        triage = triage.model_copy(
            update={
                "decision_summary": (
                    "Host:PC-FIN-011 Account:fileshare-ops synced to files.corp.internal"
                )
            }
        )
        query = RAGQueryBuilder.build_queries(triage)["fp_case_kb"]
        account_at = query.index("Account:ops-change-bot")
        analysis_at = query.index("Analysis:")
        assert account_at < analysis_at
        assert "Host:PC-FIN-011" not in query
        assert "Account:fileshare-ops" not in query
        roads = keyword_queries_for_kb("fp_case_kb", query, limit=2)
        first = roads[0]
        assert "ops-change-bot" in first
        assert "PC-OPS-JUMP-01" in first
        assert "PC-FIN-011" not in first
        assert "fileshare-ops" not in first

    def test_fp_and_fallback_excludes_process_and_domain(self) -> None:
        roads = keyword_queries_for_kb(
            "fp_case_kb",
            "malicious process ransomware_stage.exe on files.corp.internal",
            limit=2,
        )
        first = roads[0] if roads else ""
        assert "ransomware_stage.exe" not in first
        assert "files.corp.internal" not in first


class TestDedupeAndFetchK:
    def test_attack_dedupe_prefers_keywords_over_stix_score(self) -> None:
        json_seed = _chunk(
            "atk-json",
            kb_name="attack_kb",
            score=0.2,
            content="JUMP-HOST-001 mstsc.exe",
            metadata={
                "technique_id": "T1021",
                "keywords": ["lateral", "JUMP-HOST-001", "mstsc.exe"],
            },
        )
        stix = _chunk(
            "atk-stix",
            kb_name="attack_kb",
            score=0.99,
            content="Long STIX description of Remote Services without fixture hosts",
            metadata={"technique_id": "T1021", "object_id": "attack-pattern-1"},
        )
        entities = (EntityToken("host", "JUMP-HOST-001"), EntityToken("process", "mstsc.exe"))
        kept = dedupe_retrieved_chunks([stix, json_seed], entities)
        assert len(kept) == 1
        assert kept[0].chunk_id == "atk-json"

    def test_dedupe_after_fuse_collapses_cross_list_technique_id(self) -> None:
        json_seed = _chunk(
            "atk-json",
            kb_name="attack_kb",
            score=0.2,
            content="JUMP-HOST-001 mstsc.exe",
            metadata={
                "technique_id": "T1021",
                "keywords": ["lateral", "JUMP-HOST-001", "mstsc.exe"],
            },
        )
        stix = _chunk(
            "atk-stix",
            kb_name="attack_kb",
            score=0.99,
            content="Long STIX description of Remote Services without fixture hosts",
            metadata={"technique_id": "T1021", "object_id": "attack-pattern-1"},
        )
        entities = (EntityToken("host", "JUMP-HOST-001"), EntityToken("process", "mstsc.exe"))
        fused = rrf_fuse([[stix], [json_seed]], k=60)
        assert len(fused) == 2
        kept = dedupe_retrieved_chunks(fused, entities)
        assert len(kept) == 1
        assert kept[0].chunk_id == "atk-json"

    def test_fetch_k_fp_floor_16_others_double(self) -> None:
        assert fetch_k_for_kb("fp_case_kb", 5) == 16
        assert fetch_k_for_kb("attack_kb", 5) == 10
        assert fetch_k_for_kb("history_case_kb", 5) == 10
        assert fetch_k_for_kb("fp_case_kb", 10) == 20

    @pytest.mark.asyncio
    async def test_hybrid_passes_fp_fetch_k_to_store(self) -> None:
        store = MagicMock()
        store.vector_search = AsyncMock(return_value=[])
        store.keyword_search = AsyncMock(return_value=[])
        embed = MagicMock()
        embed.embed_query = AsyncMock(return_value=[0.0, 0.1])
        retriever = HybridRetriever(store, embed)
        ctx = RetrievalContext(
            tenant_id="local",
            principal="investigation:test",
            event_id="evt-fp-fetch",
            trace_id="evt:evt-fp-fetch",
        )
        await retriever.retrieve(
            ["False positive pattern for event type account_anomaly, severity low."],
            ["fp_case_kb"],
            top_k=5,
            context=ctx,
        )
        assert store.vector_search.await_args.kwargs["top_k"] >= 16
        await retriever.retrieve(
            ["Event type: lateral_movement."],
            ["attack_kb"],
            top_k=5,
            context=ctx,
        )
        attack_k = store.vector_search.await_args.kwargs["top_k"]
        assert attack_k == 10


class TestProject:
    def test_org_context_projects_empty(self) -> None:
        entities = (EntityToken("host", "PC-OPS-JUMP-01"),)
        assert project_entities_for_kb("org_context_kb", entities) == ()

    def test_fp_drops_allowlist_domain(self) -> None:
        entities = (
            EntityToken("account", "ops-change-bot"),
            EntityToken("domain", "files.corp.internal"),
        )
        projected = project_entities_for_kb("fp_case_kb", entities)
        assert [item.value for item in projected] == ["ops-change-bot"]

    def test_fp_query_strips_org_allow_domain_from_reasoning(self) -> None:
        triage = _triage()
        triage = triage.model_copy(
            update={"decision_summary": "sync to partner-cdn.example.net during change window"}
        )
        query = RAGQueryBuilder.build_queries(
            triage,
            extra_blocked_domains=("partner-cdn.example.net",),
        )["fp_case_kb"]
        assert "partner-cdn.example.net" not in query.lower()
        assert "Account:ops-change-bot" in query
        assert "Host:PC-OPS-JUMP-01" in query
