"""ISSUE-363: production helper must not inherit host DEV_AUTH_TOKENS."""

from __future__ import annotations

import os

import pytest

from app.core.config import Settings
from app.core.errors import ConfigurationError
from tests.test_support.production_settings import apply_production_env, production_settings

_PROBE_DEV_AUTH_TOKENS = '{"probe-token": {"subject": "probe", "roles": ["admin"]}}'


def test_production_settings_ignores_host_dev_auth_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _PROBE_DEV_AUTH_TOKENS)
    settings = production_settings(monkeypatch)
    assert settings.is_production()
    assert settings.production_fail_closed_violations() == []


def test_apply_production_env_clears_host_dev_auth_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _PROBE_DEV_AUTH_TOKENS)
    apply_production_env(monkeypatch)
    assert os.environ.get("DEV_AUTH_TOKENS", "").strip() == ""
    settings = Settings()
    assert settings.is_production()
    assert settings.production_fail_closed_violations() == []


def test_production_settings_field_override_replaces_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ConfigurationError, match="embedding_mode=mock"):
        production_settings(monkeypatch, embedding_mode="mock")


def test_production_settings_still_rejects_volatile_task_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ConfigurationError, match="task_mode=background"):
        production_settings(monkeypatch, TASK_MODE="background")
