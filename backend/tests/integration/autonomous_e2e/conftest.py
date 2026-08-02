"""Fixtures for ISSUE-110 autonomous E2E tests."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import get_approval_engine
from app.core.config import get_settings
from app.main import app
from tests.integration.autonomous_e2e.helpers import DEV_AUTH_TOKENS_JSON, build_approval_engine


@pytest.fixture(autouse=True)
def _isolate_mock_tool_provider() -> Iterator[None]:
    """Prevent singleton MockToolProvider state leaking between scenario tests."""
    import app.providers.tools.mock_provider as mock_provider_module

    mock_provider_module._default_provider = None
    mock_provider_module._execution_context.set(None)
    yield
    mock_provider_module._default_provider = None
    mock_provider_module._execution_context.set(None)


@pytest.fixture(autouse=True)
def _suppress_background_intent_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        lambda: None,
    )


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def approve_api_client(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    """TestClient wired to a real ApprovalEngine for RBAC contract tests."""
    monkeypatch.setenv("DEV_AUTH_TOKENS", DEV_AUTH_TOKENS_JSON)
    get_settings.cache_clear()

    engine_holder: dict[str, Any] = {}

    async def _engine() -> Any:
        if "engine" not in engine_holder:
            engine_holder["engine"] = await build_approval_engine(session_factory, redis_client)
        return engine_holder["engine"]

    app.dependency_overrides[get_approval_engine] = _engine
    client = TestClient(app)
    yield client
    app.dependency_overrides.pop(get_approval_engine, None)
    get_settings.cache_clear()
