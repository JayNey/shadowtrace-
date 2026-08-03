"""RetrievalPipeline DI wiring tests (ISSUE-138)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agents.rag_agent import RAGAgent
from app.api.v1 import deps
from app.core.config import Settings
from app.core.llm.base import InMemoryLLMCallAuditRecorder
from app.core.llm.mock_client import MockLLMClient
from app.rag.resources import reset_loaded_retrieval_resources


@pytest.mark.asyncio
async def test_build_investigation_agents_wires_retrieval_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RAGAgent must receive a real RetrievalPipeline in mock/dev wiring."""
    monkeypatch.setattr(
        deps,
        "get_settings",
        lambda: Settings(
            APP_ENV="development",
            LLM_MODE="mock",
            EMBEDDING_MODE="mock",
            ORCHESTRATION_MODE="graph",
            REACT_ENABLED=False,
        ),
    )
    monkeypatch.setattr(deps, "get_event_service", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "get_state_machine", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(
        deps,
        "_get_wm",
        AsyncMock(
            return_value=MagicMock(
                for_writer=MagicMock(return_value=MagicMock()),
            )
        ),
    )
    session_factory = MagicMock()
    monkeypatch.setattr(deps, "_get_session_factory", lambda: session_factory)
    monkeypatch.setattr(deps, "_get_redis", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_context_store", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_degraded_flags", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_event_bus", lambda: MagicMock())
    monkeypatch.setattr(deps, "get_graph_sync_service", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "_get_audit_log", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_decision_record_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_tool_call_log_service", lambda: MagicMock())

    monkeypatch.setattr(
        "app.core.llm.factory.get_llm_client",
        lambda **kwargs: MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
    )
    monkeypatch.setattr(
        "app.tools.executor.get_tool_executor",
        lambda: MagicMock(audit_service=MagicMock(), budget_service=None),
    )
    monkeypatch.setattr(
        "app.services.false_positive_matcher.FalsePositiveMatcher",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr(
        "app.services.profile_service.ProfileService",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr(
        "app.services.memory_governance.MemoryGovernance",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr("app.agents.memory_agent.MemoryAgent", lambda **_k: MagicMock())

    from app.playbook.resources import LoadedPlaybookResources

    mock_playbook_resources = LoadedPlaybookResources(
        status="ready",
        mode="test",
        playbook_kb_service=MagicMock(),
        playbook_release_service=MagicMock(),
        active_release_id="pbrel-test",
    )
    monkeypatch.setattr(
        "app.playbook.resources.get_loaded_playbook_resources",
        lambda **_kwargs: mock_playbook_resources,
    )
    monkeypatch.setattr(
        "app.playbook.resources.probe_playbook_resources",
        AsyncMock(return_value=mock_playbook_resources),
    )

    reset_loaded_retrieval_resources()
    deps.reset_deps()
    try:
        stack = await deps._build_investigation_agents()
    finally:
        deps.reset_deps()
        reset_loaded_retrieval_resources()

    rag = stack["rag"]
    assert isinstance(rag, RAGAgent)
    assert rag._pipeline is not None
    assert rag._knowledge_release_service is not None
