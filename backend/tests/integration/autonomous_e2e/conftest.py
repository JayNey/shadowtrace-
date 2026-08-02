"""Fixtures for ISSUE-110 autonomous E2E tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from app.core.config import get_settings


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
