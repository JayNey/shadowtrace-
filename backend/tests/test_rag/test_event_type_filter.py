"""Playbook EventType storage filter (口径 E / G / K)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.enums import EventType
from app.models.knowledge_release import KnowledgeFilterKind, KnowledgeQueryPlan
from app.rag.context import RetrievalContext
from app.rag.event_type_filter import (
    EVENT_TYPE_FILTER_EMPTY,
    HISTORY_EVENT_TYPE_FILTER_OPENED,
    HISTORY_TYPE_FILTER_SMOKE,
    PLAYBOOK_RELEASE_PIN_EMPTY,
    playbook_empty_degraded_steps,
    storage_event_type_equals,
)
from app.rag.hybrid_retriever import HybridRetriever
from app.services.knowledge_store import KnowledgeStore
from app.services.knowledge_store_prefilter import event_type_equals_clause, typed_filter_clause


def _ctx(
    *,
    event_type: EventType | None = EventType.MALICIOUS_PROCESS,
    embedding_release_id: str | None = "emb-playbook-pin",
    kb_name: str = "playbook_kb",
) -> RetrievalContext:
    plan = None
    if embedding_release_id is not None:
        plan = KnowledgeQueryPlan(
            corpus_id="playbook_corpus",
            kb_name=kb_name,
            active_release_id="pbrel-test",
            embedding_release_id=embedding_release_id,
            trace_id="trace-pb-et",
            pinned_at=datetime.now(UTC),
        )
    return RetrievalContext(
        tenant_id="local",
        principal="investigation:test",
        event_id="evt-pb-et",
        trace_id="evt:evt-pb-et",
        query_plan=plan,
        event_type=event_type,
    )


class TestStorageEventTypeEquals:
    def test_playbook_concrete_type_injects(self) -> None:
        assert (
            storage_event_type_equals("playbook_kb", EventType.MALICIOUS_PROCESS)
            == "malicious_process"
        )

    def test_other_never_injects(self) -> None:
        assert storage_event_type_equals("playbook_kb", EventType.OTHER) is None
        assert storage_event_type_equals("playbook_kb", None) is None
        assert storage_event_type_equals("history_case_kb", EventType.OTHER) is None
        assert storage_event_type_equals("history_case_kb", None) is None

    def test_fp_attack_org_never_inject(self) -> None:
        for kb in ("fp_case_kb", "attack_kb", "org_context_kb"):
            assert storage_event_type_equals(kb, EventType.DATA_EXFILTRATION) is None
            assert storage_event_type_equals(kb, EventType.ACCOUNT_ANOMALY) is None

    def test_history_default_closed_does_not_inject(self) -> None:
        assert HISTORY_EVENT_TYPE_FILTER_OPENED == frozenset()
        assert storage_event_type_equals("history_case_kb", EventType.ACCOUNT_ANOMALY) is None
        assert storage_event_type_equals("history_case_kb", EventType.DATA_EXFILTRATION) is None
        assert storage_event_type_equals("history_case_kb", EventType.MALICIOUS_PROCESS) is None

    def test_history_opened_set_controls_injection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "app.rag.event_type_filter.HISTORY_EVENT_TYPE_FILTER_OPENED",
            frozenset({"account_anomaly"}),
        )
        assert (
            storage_event_type_equals("history_case_kb", EventType.ACCOUNT_ANOMALY)
            == "account_anomaly"
        )
        assert storage_event_type_equals("history_case_kb", EventType.DATA_EXFILTRATION) is None
        assert storage_event_type_equals("history_case_kb", EventType.OTHER) is None

    def test_history_opened_subset_of_recorded_smoke_not_other(self) -> None:
        """§2.2 gate 3: smoke scenario_id recorded before opening a type."""
        recorded = {
            event_type: scenario
            for scenario, event_type, _hits in HISTORY_TYPE_FILTER_SMOKE
        }
        assert recorded["account_anomaly"] == "account_anomaly_fp"
        assert "other" not in HISTORY_EVENT_TYPE_FILTER_OPENED
        assert HISTORY_EVENT_TYPE_FILTER_OPENED == frozenset()
        for opened in HISTORY_EVENT_TYPE_FILTER_OPENED:
            assert opened in recorded
            assert opened != "other"

    def test_not_added_to_knowledge_filter_kind(self) -> None:
        assert "event_type" not in {item.value for item in KnowledgeFilterKind}
        clause, params = typed_filter_clause(())
        assert clause == ""
        assert params == {}

    def test_opened_history_type_has_json_event_type_field(self) -> None:
        """§2.2 gate 1: true metadata field, not a word in summary."""
        path = Path(__file__).resolve().parents[3] / "data" / "knowledge" / "history_cases.json"
        rows = json.loads(path.read_text(encoding="utf-8"))
        for opened in HISTORY_EVENT_TYPE_FILTER_OPENED:
            typed = [row for row in rows if row.get("event_type") == opened]
            assert typed, f"history_cases.json missing event_type={opened}"
            assert "event_type" in typed[0]


class TestEventTypeEqualsClause:
    def test_bypasses_typed_filter_kind(self) -> None:
        clause, params = event_type_equals_clause("malicious_process")
        assert "metadata->>'event_type'" in clause
        assert params["event_type_equals"] == "malicious_process"
        sql = KnowledgeStore.compose_vector_search_sql(
            tenant_id="local",
            tenant_isolation_strict=False,
            release_id="pbrel-test",
            embedding_release_id="emb-playbook-pin",
            event_type_equals="malicious_process",
        )
        assert "metadata->>'event_type'" in sql
        assert "metadata->>'embedding_release_id'" in sql
        assert sql.index("metadata->>'embedding_release_id'") < sql.upper().index("ORDER BY")


class TestHybridRetrieverEventType:
    @pytest.mark.asyncio
    async def test_playbook_passes_event_type_fp_does_not(self) -> None:
        store = MagicMock()
        store.vector_search = AsyncMock(return_value=[])
        store.keyword_search = AsyncMock(return_value=[])
        embed = MagicMock()
        embed.embed_query = AsyncMock(return_value=[0.0, 0.1])
        retriever = HybridRetriever(store, embed)
        ctx = _ctx()
        await retriever.retrieve(
            ["SOAR playbook for event type malicious_process, severity high."],
            ["playbook_kb"],
            top_k=5,
            context=ctx,
        )
        assert store.vector_search.await_args.kwargs["event_type_equals"] == (
            "malicious_process"
        )
        await retriever.retrieve(
            ["False positive pattern for event type data_exfiltration."],
            ["fp_case_kb"],
            top_k=5,
            context=_ctx(event_type=EventType.DATA_EXFILTRATION, embedding_release_id=None),
        )
        assert store.vector_search.await_args.kwargs["event_type_equals"] is None

    @pytest.mark.asyncio
    async def test_history_opened_type_injects_and_does_not_unfilter(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "app.rag.event_type_filter.HISTORY_EVENT_TYPE_FILTER_OPENED",
            frozenset({"account_anomaly"}),
        )
        store = MagicMock()
        store.vector_search = AsyncMock(return_value=[])
        store.keyword_search = AsyncMock(return_value=[])
        embed = MagicMock()
        embed.embed_query = AsyncMock(return_value=[0.0, 0.1])
        retriever = HybridRetriever(store, embed)
        await retriever.retrieve(
            [
                "Historical case with event type account_anomaly. "
                "Entities: Host:PC-OPS-JUMP-01, Account:ops-change-bot"
            ],
            ["history_case_kb"],
            top_k=5,
            context=_ctx(event_type=EventType.ACCOUNT_ANOMALY, embedding_release_id=None),
        )
        injected = [
            call.kwargs["event_type_equals"] for call in store.vector_search.await_args_list
        ]
        injected += [
            call.kwargs["event_type_equals"] for call in store.keyword_search.await_args_list
        ]
        assert injected
        assert all(value == "account_anomaly" for value in injected)
        assert store.vector_search.await_count == 1

    @pytest.mark.asyncio
    async def test_history_unopened_and_other_do_not_inject(self) -> None:
        store = MagicMock()
        store.vector_search = AsyncMock(return_value=[])
        store.keyword_search = AsyncMock(return_value=[])
        embed = MagicMock()
        embed.embed_query = AsyncMock(return_value=[0.0, 0.1])
        retriever = HybridRetriever(store, embed)
        await retriever.retrieve(
            [
                "Historical case with event type data_exfiltration. "
                "Entities: Host:PC-FIN-023, Account:zhangsan"
            ],
            ["history_case_kb"],
            top_k=5,
            context=_ctx(event_type=EventType.DATA_EXFILTRATION, embedding_release_id=None),
        )
        assert store.vector_search.await_args.kwargs["event_type_equals"] is None
        await retriever.retrieve(
            [
                "Historical case with event type account_anomaly. "
                "Entities: Host:PC-OPS-JUMP-01, Account:ops-change-bot"
            ],
            ["history_case_kb"],
            top_k=5,
            context=_ctx(event_type=EventType.ACCOUNT_ANOMALY, embedding_release_id=None),
        )
        assert store.vector_search.await_args.kwargs["event_type_equals"] is None
        await retriever.retrieve(
            [
                "Historical case with event type other. "
                "Entities: Host:WKS-GEN-099, Account:general-user-099"
            ],
            ["history_case_kb"],
            top_k=5,
            context=_ctx(event_type=EventType.OTHER, embedding_release_id=None),
        )
        assert store.vector_search.await_args.kwargs["event_type_equals"] is None

    @pytest.mark.asyncio
    async def test_other_playbook_does_not_inject(self) -> None:
        store = MagicMock()
        store.vector_search = AsyncMock(return_value=[])
        store.keyword_search = AsyncMock(return_value=[])
        embed = MagicMock()
        embed.embed_query = AsyncMock(return_value=[0.0, 0.1])
        retriever = HybridRetriever(store, embed)
        await retriever.retrieve(
            ["SOAR playbook for event type other, severity low."],
            ["playbook_kb"],
            top_k=5,
            context=_ctx(event_type=EventType.OTHER),
        )
        assert store.vector_search.await_args.kwargs["event_type_equals"] is None

    @pytest.mark.asyncio
    async def test_malicious_process_does_not_query_exfil_type(self) -> None:
        """Filter equals malicious_process; do not assert playbook_refs[0] identity."""
        store = MagicMock()
        store.vector_search = AsyncMock(return_value=[])
        store.keyword_search = AsyncMock(return_value=[])
        embed = MagicMock()
        embed.embed_query = AsyncMock(return_value=[0.0, 0.1])
        retriever = HybridRetriever(store, embed)
        await retriever.retrieve(
            ["SOAR playbook for event type malicious_process, severity high."],
            ["playbook_kb"],
            top_k=5,
            context=_ctx(event_type=EventType.MALICIOUS_PROCESS),
        )
        injected = store.vector_search.await_args.kwargs["event_type_equals"]
        assert injected == "malicious_process"
        assert injected != "data_exfiltration"


class TestPlaybookEmptyTags:
    @pytest.mark.asyncio
    async def test_pin_empty_is_not_type_empty(self) -> None:
        store = MagicMock()
        store.count_chunks = AsyncMock(return_value=0)
        tags = await playbook_empty_degraded_steps(store, _ctx())
        assert PLAYBOOK_RELEASE_PIN_EMPTY in tags
        assert EVENT_TYPE_FILTER_EMPTY not in tags

    @pytest.mark.asyncio
    async def test_pin_ok_type_filter_empty(self) -> None:
        store = MagicMock()
        store.count_chunks = AsyncMock(return_value=4)
        tags = await playbook_empty_degraded_steps(store, _ctx())
        assert EVENT_TYPE_FILTER_EMPTY in tags
        assert PLAYBOOK_RELEASE_PIN_EMPTY not in tags

    @pytest.mark.asyncio
    async def test_other_empty_does_not_tag_type_filter(self) -> None:
        store = MagicMock()
        store.count_chunks = AsyncMock(return_value=3)
        tags = await playbook_empty_degraded_steps(
            store, _ctx(event_type=EventType.OTHER)
        )
        assert EVENT_TYPE_FILTER_EMPTY not in tags
        assert PLAYBOOK_RELEASE_PIN_EMPTY not in tags
