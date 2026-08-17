"""Tests for PlaybookKB production DI resources (ISSUE-139 / #645)."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.errors import ConfigurationError
from app.playbook.resources import get_loaded_playbook_resources
from tests.test_support.production_settings import production_settings


def test_production_settings_reject_playbook_fixture_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ConfigurationError, match="playbook_fixture_fallback"):
        production_settings(monkeypatch, playbook_fixture_fallback=True)


def test_playbook_fixture_fallback_marks_degraded() -> None:
    settings = Settings(app_env="development", playbook_fixture_fallback=True)
    loaded = get_loaded_playbook_resources(settings=settings)
    assert loaded.status == "degraded"
    assert loaded.mode == "fixture"
    assert "playbook_fixture_fallback_enabled" in loaded.reasons


@pytest.mark.asyncio
async def test_check_playbook_resources_unavailable_without_postgres() -> None:
    from app.playbook.resources import check_playbook_resources

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("app.playbook.resources.peek_session_provider", lambda: None)
        payload = await check_playbook_resources(Settings(app_env="development"))
    assert payload["status"] == "unavailable"
    assert "session_provider_missing" in payload["reasons"]


@pytest.mark.asyncio
async def test_probe_marks_unavailable_when_no_active_release_required() -> None:
    from unittest.mock import AsyncMock, MagicMock

    from app.playbook.resources import LoadedPlaybookResources, probe_playbook_resources
    from app.services.playbook_release_service import PlaybookReleaseService

    release_service = MagicMock(spec=PlaybookReleaseService)
    release_service.get_active_release = AsyncMock(return_value=None)
    loaded = LoadedPlaybookResources(
        status="ready",
        mode="production",
        playbook_kb_service=MagicMock(),
        playbook_release_service=release_service,
    )
    probed = await probe_playbook_resources(
        loaded,
        settings=Settings(app_env="development", playbook_release_require_active=True),
    )
    assert probed.status == "unavailable"
    assert "no_active_playbook_release" in probed.reasons
