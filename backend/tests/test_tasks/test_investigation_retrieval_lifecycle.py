"""Celery retrieval lifecycle smoke tests (ISSUE-138)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import text

from app.core.config import Settings
from app.db.session_provider import (
    SessionProvider,
    init_worker_session_provider,
    reset_session_provider,
)
from app.rag.resources import reset_loaded_retrieval_resources


def _postgres_reachable() -> bool:
    from app.core.config import get_settings

    provider = SessionProvider(get_settings().database_url, pool="nullpool")
    try:
        return asyncio.run(provider.ping_postgres())
    except Exception:
        return False
    finally:
        asyncio.run(provider.dispose())


def test_celery_task_releases_resources_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from celery.app.task import Context

    release_mock = MagicMock()
    monkeypatch.setattr(
        "app.tasks.investigation_tasks._release_celery_task_loop_resources",
        release_mock,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks._run_investigation_body",
        AsyncMock(side_effect=RuntimeError("investigation failed")),
    )

    from app.tasks import investigation_tasks as tasks

    ctx = Context(id="task-release-failure", delivery_info={}, retries=0)
    tasks.run_investigation.request_stack.push(ctx)
    try:
        with pytest.raises(RuntimeError, match="investigation failed"):
            tasks.run_investigation.run("evt-failure-test")
    finally:
        tasks.run_investigation.request_stack.pop()
    release_mock.assert_called_once()


@pytest.mark.skipif(not _postgres_reachable(), reason="PostgreSQL not reachable")
def test_nullpool_provider_survives_consecutive_asyncio_runs() -> None:
    """Strategy B: consecutive asyncio.run calls must not reuse loop-bound pools."""
    reset_session_provider()
    reset_loaded_retrieval_resources()
    provider = init_worker_session_provider()

    async def _select_one() -> None:
        async with provider.engine().connect() as conn:
            await conn.execute(text("SELECT 1"))

    try:
        asyncio.run(_select_one())
        asyncio.run(_select_one())
    finally:
        asyncio.run(provider.dispose())
        reset_session_provider()
        reset_loaded_retrieval_resources()


@pytest.mark.skipif(not _postgres_reachable(), reason="PostgreSQL not reachable")
def test_celery_worker_child_lifecycle_smoke(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate Celery child init → pipeline attach → worker shutdown (ISSUE-138)."""
    from app.api.v1 import deps
    from app.core.celery_app import init_worker_telemetry, shutdown_worker_resources
    from app.core.llm.base import InMemoryLLMCallAuditRecorder
    from app.core.llm.mock_client import MockLLMClient
    from app.rag.resources import get_loaded_retrieval_resources, peek_loaded_retrieval_resources

    reset_session_provider()
    reset_loaded_retrieval_resources()
    deps.reset_deps()

    monkeypatch.setattr(
        "app.core.llm.factory.get_llm_client",
        lambda **kwargs: MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
    )
    monkeypatch.setattr(
        "app.tools.executor.get_tool_executor",
        lambda: MagicMock(audit_service=MagicMock(), budget_service=None),
    )

    init_worker_telemetry(sender=None)
    session_factory = deps._get_session_factory()
    from app.core.embedding.factory import get_embedding_client

    loaded = get_loaded_retrieval_resources(
        settings=Settings(),
        session_factory=session_factory,
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        embed_service=get_embedding_client(settings=Settings()),
    )
    assert loaded.pipeline is not None
    assert peek_loaded_retrieval_resources() is not None

    shutdown_worker_resources(sender=None)
    assert peek_loaded_retrieval_resources() is None

    deps.reset_deps()
    reset_session_provider()
    reset_loaded_retrieval_resources()
