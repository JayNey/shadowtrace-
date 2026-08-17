"""Shared production Settings kwargs for fail-closed acceptance tests (ISSUE-363).

Production fail-closed (ISSUE-217) rejects default ``TASK_MODE=background``; any
test that constructs ``Settings`` or monkeypatches ``APP_ENV=production`` must
also supply celery execution and live-shaped runtime modes so unrelated gates do
not mask the assertion under test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.config import Settings

if TYPE_CHECKING:
    from pytest import MonkeyPatch


def _alias_key(key: str) -> str:
    field = Settings.model_fields.get(key)
    alias = getattr(field, "alias", None) if field is not None else None
    return str(alias) if alias else key


def production_settings_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "APP_ENV": "production",
        "SOURCE_MODE": "live_edr",
        "TOOL_MODE": "live",
        "DISPOSITION_MODE": "live_xdr",
        "DISPOSITION_ADAPTER_KIND": "http",
        "LLM_MODE": "openai_compatible",
        "EMBEDDING_MODE": "remote",
        "SIMULATION_ENABLED": False,
        "SOCKETIO_CORS_ALLOWED_ORIGINS": "https://app.example",
        "TASK_MODE": "celery",
    }
    for key, value in overrides.items():
        kwargs[_alias_key(key)] = value
    return kwargs


def production_settings(monkeypatch: MonkeyPatch, **overrides: object) -> Settings:
    """Build a production Settings that can pass fail-closed (ISSUE-363).

    ``production_fail_closed_violations`` reads ``DEV_AUTH_TOKENS`` from
    ``os.environ``, so kwargs cannot cover a host/autouse token. Clear it
    through ``monkeypatch`` (never write a real token into the helper).
    """
    monkeypatch.delenv("DEV_AUTH_TOKENS", raising=False)
    return Settings(**production_settings_kwargs(**overrides))


def apply_production_env(monkeypatch: MonkeyPatch, **overrides: object) -> None:
    """Monkeypatch env vars for API tests that exercise production auth gates."""
    for key, value in production_settings_kwargs(**overrides).items():
        monkeypatch.setenv(key, str(value))
    if "DEV_AUTH_TOKENS" not in overrides:
        monkeypatch.setenv("DEV_AUTH_TOKENS", "")
