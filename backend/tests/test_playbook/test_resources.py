"""Tests for PlaybookKB production DI resources (ISSUE-139 / #645)."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.errors import ConfigurationError
from app.playbook.resources import get_loaded_playbook_resources


def test_production_settings_reject_playbook_fixture_fallback() -> None:
    with pytest.raises(ConfigurationError, match="playbook_fixture_fallback"):
        Settings(
            app_env="production",
            simulation_enabled=False,
            source_mode="live_xdr",
            tool_mode="live",
            disposition_mode="live_xdr",
            disposition_adapter_kind="live",
            llm_mode="openai_compatible",
            embedding_mode="remote",
            playbook_fixture_fallback=True,
        )


def test_playbook_fixture_fallback_marks_degraded() -> None:
    settings = Settings(app_env="development", playbook_fixture_fallback=True)
    loaded = get_loaded_playbook_resources(settings=settings)
    assert loaded.status == "degraded"
    assert loaded.mode == "fixture"
    assert "playbook_fixture_fallback_enabled" in loaded.reasons
