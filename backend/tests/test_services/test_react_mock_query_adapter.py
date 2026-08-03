"""React mock query adapter unit tests (ISSUE-135 / #641 Phase A)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import Settings
from app.core.embedding.release import build_embedding_release
from app.models.knowledge import RetrievalResult, RetrievedChunk
from app.models.knowledge_release import ATTACK_CORPUS_ID, ATTACK_KB_NAME, KnowledgeQueryPlan
from app.services.react_mock_query_adapter import ReactMockQueryAdapter, ReactMockQueryContext


def _ctx() -> ReactMockQueryContext:
    return ReactMockQueryContext(
        event_id="evt-adapter-test",
        tenant_id="tenant-a",
        principal="investigation:test",
        trace_id="trace-adapter",
        shadow_run_id="sr-adapter-test",
    )


@pytest.mark.asyncio
async def test_adapter_denies_cross_tenant_params() -> None:
    pipeline = MagicMock()
    adapter = ReactMockQueryAdapter(pipeline, knowledge_release_service=None, settings=Settings())
    result = await adapter.execute(
        {"query": "test", "tenant_id": "tenant-b"},
        ctx=_ctx(),
    )
    assert result["status"] == "denied"
    assert result["reason"] == "cross_tenant_denied"
    pipeline.retrieve.assert_not_called()


@pytest.mark.asyncio
async def test_adapter_degraded_without_active_release() -> None:
    release_service = MagicMock()
    release_service.get_active_release = AsyncMock(return_value=None)
    pipeline = MagicMock()
    adapter = ReactMockQueryAdapter(
        pipeline,
        knowledge_release_service=release_service,
        settings=Settings(EMBEDDING_MODE="mock"),
    )
    result = await adapter.execute({"query": "Valid Accounts"}, ctx=_ctx())
    assert result["status"] == "degraded"
    assert result["reason"] == "no_active_knowledge_release"


@pytest.mark.asyncio
async def test_adapter_returns_typed_retrieval_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(EMBEDDING_MODE="mock")
    active_emb = build_embedding_release(settings).release_id
    base_plan = KnowledgeQueryPlan(
        corpus_id=ATTACK_CORPUS_ID,
        kb_name=ATTACK_KB_NAME,
        active_release_id="krel-test",
        embedding_release_id=active_emb,
        trace_id="trace-adapter",
        pinned_at=datetime.now(UTC),
    )
    release_service = MagicMock()
    release_service.get_active_release = AsyncMock(return_value=MagicMock())

    pipeline = MagicMock()
    pipeline.retrieve = AsyncMock(
        return_value=RetrievalResult(
            query="Valid Accounts",
            chunks=[
                RetrievedChunk(
                    chunk_id="chk-001",
                    kb_name=ATTACK_KB_NAME,
                    content="Valid Accounts technique",
                    metadata={"source_id": "mitre_attack_stix", "tenant_id": "tenant-a"},
                    score=0.9,
                    retrieval_method="vector",
                )
            ],
        )
    )

    monkeypatch.setattr(
        "app.services.react_mock_query_adapter.resolve_active_knowledge_query_plan",
        AsyncMock(return_value=base_plan),
    )
    adapter = ReactMockQueryAdapter(
        pipeline,
        knowledge_release_service=release_service,
        settings=settings,
    )
    result = await adapter.execute(
        {"query": "Valid Accounts", "kb_names": [ATTACK_KB_NAME], "top_k": 1},
        ctx=_ctx(),
    )

    assert result["status"] == "success"
    assert result["data"]["chunk_count"] == 1
    assert result["data"]["plan_hash"]
    pipeline.retrieve.assert_awaited_once()
    assert pipeline.retrieve.await_args.args[1] == [ATTACK_KB_NAME]


@pytest.mark.asyncio
async def test_adapter_denies_multi_kb_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(EMBEDDING_MODE="mock")
    active_emb = build_embedding_release(settings).release_id
    base_plan = KnowledgeQueryPlan(
        corpus_id=ATTACK_CORPUS_ID,
        kb_name=ATTACK_KB_NAME,
        active_release_id="krel-test",
        embedding_release_id=active_emb,
        trace_id="trace-adapter",
        pinned_at=datetime.now(UTC),
    )
    release_service = MagicMock()
    release_service.get_active_release = AsyncMock(return_value=MagicMock())
    pipeline = MagicMock()
    monkeypatch.setattr(
        "app.services.react_mock_query_adapter.resolve_active_knowledge_query_plan",
        AsyncMock(return_value=base_plan),
    )
    adapter = ReactMockQueryAdapter(
        pipeline,
        knowledge_release_service=release_service,
        settings=settings,
    )
    result = await adapter.execute(
        {"query": "Valid Accounts", "kb_names": [ATTACK_KB_NAME, "fp_case_kb"]},
        ctx=_ctx(),
    )
    assert result["status"] == "denied"
    assert result["reason"] == "kb_scope_mismatch"
    pipeline.retrieve.assert_not_called()


@pytest.mark.asyncio
async def test_adapter_denies_when_pipeline_rejects_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(EMBEDDING_MODE="mock")
    active_emb = build_embedding_release(settings).release_id
    base_plan = KnowledgeQueryPlan(
        corpus_id=ATTACK_CORPUS_ID,
        kb_name=ATTACK_KB_NAME,
        active_release_id="krel-test",
        embedding_release_id=active_emb,
        trace_id="trace-adapter",
        pinned_at=datetime.now(UTC),
    )
    release_service = MagicMock()
    release_service.get_active_release = AsyncMock(return_value=MagicMock())
    pipeline = MagicMock()
    pipeline.retrieve = AsyncMock(
        return_value=RetrievalResult(
            query="Valid Accounts",
            chunks=[],
            degraded_steps=["knowledge_query_plan_rejected", "plan_kb_scope_mismatch"],
            knowledge_query_plan={
                "rejected_reasons": ["plan_kb_scope_mismatch"],
                "sanitized_plan_hash": "",
            },
        )
    )
    monkeypatch.setattr(
        "app.services.react_mock_query_adapter.resolve_active_knowledge_query_plan",
        AsyncMock(return_value=base_plan),
    )
    adapter = ReactMockQueryAdapter(
        pipeline,
        knowledge_release_service=release_service,
        settings=settings,
    )
    result = await adapter.execute(
        {"query": "Valid Accounts", "kb_names": [ATTACK_KB_NAME]},
        ctx=_ctx(),
    )
    assert result["status"] == "denied"
    assert result["reason"] == "plan_rejected"
    assert "plan_kb_scope_mismatch" in result["rejected_reasons"]
