"""LLM diagnostics, URL helpers, and probe tests (ISSUE-106 / #609)."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from app.core.config import Settings
from app.core.errors import LLMError
from app.core.llm.base import (
    LLMAuthError,
    LLMProviderError,
    LLMRateLimitedError,
    LLMTimeoutError,
)
from app.core.llm.diagnostics import (
    build_llm_provider_health,
    classify_llm_error,
    probe_llm_provider,
    reset_llm_probe_cache,
    validate_openai_compatible_config,
)
from app.core.llm.url_utils import normalize_llm_base_url, redact_base_url
from app.models.llm_provider import LLMCallLogAggregate, LLMProviderMode


@pytest.fixture(autouse=True)
def _clear_probe_cache() -> None:
    reset_llm_probe_cache()


def test_normalize_llm_base_url_strips_chat_completions_suffix() -> None:
    assert (
        normalize_llm_base_url("https://ark.cn-beijing.volces.com/api/v3/chat/completions")
        == "https://ark.cn-beijing.volces.com/api/v3"
    )
    assert normalize_llm_base_url("https://llm.example/v1/") == "https://llm.example/v1"


def test_redact_base_url_hides_path_and_secrets() -> None:
    assert redact_base_url("https://ark.cn-beijing.volces.com/api/v3") == (
        "https://ark.cn-beijing.volces.com"
    )
    assert redact_base_url("") == ""
    assert redact_base_url("not-a-url") == "[invalid-url]"


@pytest.mark.parametrize(
    ("exc", "expected_class"),
    [
        (LLMAuthError("auth"), "auth"),
        (LLMRateLimitedError("rate"), "rate_limit"),
        (LLMTimeoutError("timeout"), "timeout"),
        (LLMProviderError("provider"), "provider"),
        (LLMError("generic"), "provider"),
    ],
)
def test_classify_llm_error_from_exception(exc: Exception, expected_class: str) -> None:
    error_class, error_code = classify_llm_error(exc=exc)
    assert error_class == expected_class
    assert error_code == getattr(exc, "error_code", None)


def test_validate_openai_compatible_config_requires_base_url_and_model() -> None:
    settings = Settings(
        LLM_MODE="openai_compatible",
        LLM_API_BASE_URL="",
        LLM_PRIMARY_MODEL="",
    )
    assert validate_openai_compatible_config(settings) == "llm_config_error"

    ok = Settings(
        LLM_MODE="openai_compatible",
        LLM_API_BASE_URL="https://llm.example/v1",
        LLM_PRIMARY_MODEL="model-a",
    )
    assert validate_openai_compatible_config(ok) is None


@pytest.mark.asyncio
async def test_probe_mock_mode_skips_without_outbound() -> None:
    settings = Settings(LLM_MODE="mock")
    with respx.mock(assert_all_called=False) as router:
        probe = await probe_llm_provider(settings, force=True)
        assert probe.status == "skipped"
        assert router.calls.call_count == 0


@pytest.mark.asyncio
async def test_probe_disabled_by_default_skips_outbound() -> None:
    settings = Settings(
        LLM_MODE="openai_compatible",
        LLM_API_BASE_URL="https://llm.example/v1",
        LLM_PRIMARY_MODEL="primary-model",
        LLM_PROBE_ENABLED=False,
    )
    with respx.mock(assert_all_called=False) as router:
        probe = await probe_llm_provider(settings, force=False)
        assert probe.status == "skipped"
        assert router.calls.call_count == 0


@respx.mock
@pytest.mark.asyncio
async def test_probe_chat_success(respx_mock: respx.MockRouter) -> None:
    respx_mock.post("https://llm.example/v1/chat/completions").respond(
        200,
        json={
            "model": "primary-model",
            "choices": [{"message": {"content": "pong"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        },
    )
    settings = Settings(
        LLM_MODE="openai_compatible",
        LLM_API_BASE_URL="https://llm.example/v1",
        LLM_API_KEY="secret-key",
        LLM_PRIMARY_MODEL="primary-model",
        LLM_PROBE_ENABLED=True,
    )
    probe = await probe_llm_provider(settings, force=True)
    assert probe.status == "ok"
    assert probe.probe_method == "chat"
    assert probe.latency_ms is not None
    assert "secret" not in str(probe.model_dump())


@respx.mock
@pytest.mark.asyncio
async def test_probe_chat_classifies_401(respx_mock: respx.MockRouter) -> None:
    respx_mock.post("https://llm.example/v1/chat/completions").respond(401)
    settings = Settings(
        LLM_MODE="openai_compatible",
        LLM_API_BASE_URL="https://llm.example/v1",
        LLM_PRIMARY_MODEL="primary-model",
        LLM_PROBE_ENABLED=True,
    )
    probe = await probe_llm_provider(settings, force=True)
    assert probe.status == "error"
    assert probe.error_class == "auth"


@respx.mock
@pytest.mark.asyncio
async def test_probe_chat_classifies_429(respx_mock: respx.MockRouter) -> None:
    respx_mock.post("https://llm.example/v1/chat/completions").respond(429)
    settings = Settings(
        LLM_MODE="openai_compatible",
        LLM_API_BASE_URL="https://llm.example/v1",
        LLM_PRIMARY_MODEL="primary-model",
        LLM_PROBE_ENABLED=True,
    )
    probe = await probe_llm_provider(settings, force=True)
    assert probe.status == "error"
    assert probe.error_class == "rate_limit"


@respx.mock
@pytest.mark.asyncio
async def test_probe_timeout_classified(respx_mock: respx.MockRouter) -> None:
    async def _timeout(_: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.05)
        raise httpx.TimeoutException("timeout")

    respx_mock.post("https://llm.example/v1/chat/completions").mock(side_effect=_timeout)
    settings = Settings(
        LLM_MODE="openai_compatible",
        LLM_API_BASE_URL="https://llm.example/v1",
        LLM_PRIMARY_MODEL="primary-model",
        LLM_PROBE_ENABLED=True,
        LLM_TIMEOUT_SECONDS=1,
    )
    probe = await probe_llm_provider(settings, force=True)
    assert probe.status == "error"
    assert probe.error_class == "timeout"


@pytest.mark.asyncio
async def test_probe_cache_respects_ttl() -> None:
    from app.models.llm_provider import LLMProbeStatus

    settings = Settings(
        LLM_MODE="openai_compatible",
        LLM_API_BASE_URL="https://llm.example/v1",
        LLM_PRIMARY_MODEL="primary-model",
        LLM_PROBE_ENABLED=True,
        LLM_PROBE_TTL_SECONDS=300,
    )
    expected = LLMProbeStatus(status="ok", probe_method="chat", latency_ms=1.0)
    with patch(
        "app.core.llm.diagnostics._run_openai_probe",
        new_callable=AsyncMock,
        return_value=expected,
    ) as run_probe:
        first = await probe_llm_provider(settings, force=True)
        second = await probe_llm_provider(settings, force=False)
    assert run_probe.await_count == 1
    assert second.model_dump() == first.model_dump()


@pytest.mark.asyncio
async def test_build_llm_provider_health_mock_is_ok() -> None:
    settings = Settings(LLM_MODE=LLMProviderMode.MOCK.value)
    session_factory = AsyncMock()

    async def _aggregate(*_args: Any, **_kwargs: Any) -> LLMCallLogAggregate:
        return LLMCallLogAggregate(window_minutes=60, total_calls=0, success_calls=0)

    with patch("app.core.llm.diagnostics._aggregate_llm_call_log", side_effect=_aggregate):
        health = await build_llm_provider_health(settings, session_factory)

    assert health.status == "ok"
    assert health.mode == "mock"
    assert health.last_probe_status.status == "skipped"
    assert "secret" not in health.model_dump_json().lower()


@pytest.mark.asyncio
async def test_build_llm_provider_health_mock_survives_audit_db_failure() -> None:
    settings = Settings(LLM_MODE=LLMProviderMode.MOCK.value)
    session_factory = AsyncMock()

    with patch(
        "app.core.llm.diagnostics._aggregate_llm_call_log",
        new_callable=AsyncMock,
        side_effect=RuntimeError("postgres unavailable"),
    ):
        health = await build_llm_provider_health(settings, session_factory)

    assert health.status == "ok"
    assert health.mode == "mock"
    assert health.audit is None


@pytest.mark.asyncio
async def test_build_llm_provider_health_openai_missing_config_is_degraded() -> None:
    settings = Settings(
        LLM_MODE=LLMProviderMode.OPENAI_COMPATIBLE.value,
        LLM_API_BASE_URL="",
        LLM_PRIMARY_MODEL="",
    )
    session_factory = AsyncMock()

    async def _aggregate(*_args: Any, **_kwargs: Any) -> LLMCallLogAggregate:
        return LLMCallLogAggregate(window_minutes=60, total_calls=0, success_calls=0)

    with patch("app.core.llm.diagnostics._aggregate_llm_call_log", side_effect=_aggregate):
        health = await build_llm_provider_health(settings, session_factory)

    assert health.status == "degraded"
    assert health.mode == "openai_compatible"
    assert health.last_probe_status.status == "error"
    assert health.last_probe_status.error_code == "llm_config_error"


@respx.mock
@pytest.mark.asyncio
async def test_probe_models_success(respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://llm.example/v1/models").respond(200, json={"data": []})
    settings = Settings(
        LLM_MODE="openai_compatible",
        LLM_API_BASE_URL="https://llm.example/v1",
        LLM_PRIMARY_MODEL="primary-model",
        LLM_PROBE_ENABLED=True,
        LLM_PROBE_METHOD="models",
    )
    probe = await probe_llm_provider(settings, force=True)
    assert probe.status == "ok"
    assert probe.probe_method == "models"
    assert probe.latency_ms is not None


@respx.mock
@pytest.mark.asyncio
async def test_probe_models_classifies_401(respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://llm.example/v1/models").respond(401)
    settings = Settings(
        LLM_MODE="openai_compatible",
        LLM_API_BASE_URL="https://llm.example/v1",
        LLM_PRIMARY_MODEL="primary-model",
        LLM_PROBE_ENABLED=True,
        LLM_PROBE_METHOD="models",
    )
    probe = await probe_llm_provider(settings, force=True)
    assert probe.status == "error"
    assert probe.probe_method == "models"
    assert probe.error_class == "auth"


@pytest.mark.asyncio
async def test_check_llm_provider_preserves_mode_on_unexpected_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.llm import diagnostics as diagnostics_module

    settings = Settings(LLM_MODE=LLMProviderMode.MOCK.value)

    async def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("unexpected health assembly failure")

    monkeypatch.setattr(diagnostics_module, "build_llm_provider_health", _boom)

    payload = await diagnostics_module.check_llm_provider(settings)
    assert payload["status"] == "error"
    assert payload["mode"] == "mock"
    assert payload["primary_model"] == settings.llm_primary_model
