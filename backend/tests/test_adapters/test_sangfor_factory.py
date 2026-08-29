"""Layer 7 adapter factory: one assembly point, Demo stays Mock."""

from __future__ import annotations

import inspect

import pytest

from app.adapters.disposition.http_adapter import HttpDispositionAdapter
from app.adapters.factory import (
    HTTP_PROVIDER,
    MOCK_XDR_PROVIDER,
    SANGFOR_PROVIDER,
    build_disposition_adapter_registry,
    build_source_adapter,
    disposition_provider_name,
    live_auth_failed,
    probe_sangfor_auth,
    source_adapter_component,
)
from app.adapters.mock_xdr import MockXDRDispositionAdapter, MockXDRSourceAdapter
from app.adapters.sangfor.disposition import SangforDispositionAdapter
from app.api.v1 import deps
from app.core.config import Settings
from app.core.errors import ConfigurationError
from app.models.enums import ConnectorStatus
from app.services.action_execution_service import ActionExecutionService
from app.tasks import action_execution_tasks
from tests.test_support.production_settings import production_settings_kwargs


def _sangfor_settings(**overrides: object) -> Settings:
    kwargs: dict[str, object] = {
        "APP_ENV": "staging",
        "SOURCE_MODE": "sangfor_xdr",
        "DISPOSITION_MODE": "live_xdr",
        "DISPOSITION_ADAPTER_KIND": "sangfor_xdr",
        "TOOL_MODE": "live",
        "SIMULATION_ENABLED": False,
        "ALLOW_LIVE_SIDE_EFFECTS": True,
        "SANGFOR_XDR_BASE_URL": "https://xdr.example.invalid",
        "SANGFOR_ACCESS_KEY": "test-ak-01xxxxxx",
        "SANGFOR_SECRET_KEY": "test-sk-01-not-prod",
        "SHARED_CREDENTIAL_SCOPE_VERIFIED": True,
    }
    kwargs.update(overrides)
    return Settings(**kwargs)


def test_default_factory_registers_only_mock_xdr() -> None:
    settings = Settings(
        APP_ENV="development",
        SOURCE_MODE="mock_xdr",
        DISPOSITION_MODE="mock_xdr",
        DISPOSITION_ADAPTER_KIND="mock",
        TOOL_MODE="mock",
        SIMULATION_ENABLED=True,
    )
    registry = build_disposition_adapter_registry(settings)
    assert registry.list_names() == [MOCK_XDR_PROVIDER]
    adapter = registry.get(MOCK_XDR_PROVIDER)
    assert isinstance(adapter, MockXDRDispositionAdapter)
    assert disposition_provider_name(settings) == MOCK_XDR_PROVIDER


def test_factory_registers_sangfor_for_live_xdr_kind() -> None:
    settings = _sangfor_settings()
    registry = build_disposition_adapter_registry(settings)
    assert registry.list_names() == [SANGFOR_PROVIDER]
    assert isinstance(registry.get(SANGFOR_PROVIDER), SangforDispositionAdapter)
    assert disposition_provider_name(settings) == SANGFOR_PROVIDER


def test_factory_registers_http_kind() -> None:
    settings = Settings(
        APP_ENV="staging",
        DISPOSITION_MODE="live_xdr",
        DISPOSITION_ADAPTER_KIND="http",
        DISPOSITION_BASE_URL="https://example.invalid/disposition",
        SIMULATION_ENABLED=False,
        TOOL_MODE="live",
    )
    registry = build_disposition_adapter_registry(settings)
    assert registry.list_names() == [HTTP_PROVIDER]
    assert isinstance(registry.get(HTTP_PROVIDER), HttpDispositionAdapter)
    assert disposition_provider_name(settings) == HTTP_PROVIDER


def test_factory_rejects_unknown_kind() -> None:
    settings = Settings(
        APP_ENV="staging",
        DISPOSITION_MODE="live_xdr",
        DISPOSITION_ADAPTER_KIND="crowdstrike",
        SIMULATION_ENABLED=False,
        TOOL_MODE="live",
    )
    with pytest.raises(ConfigurationError, match="unknown DISPOSITION_ADAPTER_KIND"):
        build_disposition_adapter_registry(settings)


def test_factory_rejects_disposition_mode_live() -> None:
    with pytest.raises(ConfigurationError, match="disposition_mode=live"):
        Settings(APP_ENV="development", DISPOSITION_MODE="live")


def test_factory_rejects_sangfor_kind_with_mock_disposition_mode() -> None:
    settings = _sangfor_settings(DISPOSITION_MODE="mock_xdr")
    with pytest.raises(ConfigurationError, match="live_xdr"):
        build_disposition_adapter_registry(settings)


def test_factory_rejects_sangfor_without_credentials() -> None:
    settings = _sangfor_settings(
        SANGFOR_ACCESS_KEY="",
        SANGFOR_SECRET_KEY="",
        SANGFOR_AUTH_CODE="",
    )
    with pytest.raises(ConfigurationError, match="SANGFOR_AUTH_CODE"):
        build_disposition_adapter_registry(settings)


def test_source_factory_mock_and_sangfor() -> None:
    mock_adapter = build_source_adapter(
        Settings(
            APP_ENV="development",
            SOURCE_MODE="mock_xdr",
            SIMULATION_ENABLED=True,
        )
    )
    assert isinstance(mock_adapter, MockXDRSourceAdapter)
    sangfor = build_source_adapter(_sangfor_settings())
    assert sangfor.name == "sangfor_xdr"
    assert not isinstance(sangfor, MockXDRSourceAdapter)


def test_production_and_celery_share_the_same_assembly_function() -> None:
    deps_src = inspect.getsource(deps._get_adapter_registry)
    worker_src = inspect.getsource(action_execution_tasks._build_execution_service)
    assert "build_disposition_adapter_registry" in deps_src
    assert "build_disposition_adapter_registry" in worker_src
    assert "DispositionAdapterRegistry()" not in worker_src
    tool_src = inspect.getsource(action_execution_tasks._tool_registry_for_settings)
    assert "settings.tool_mode" in tool_src
    assert 'tool_mode="mock"' not in tool_src
    assert 'tool_mode="mock"' not in worker_src


def test_action_execution_provider_name_follows_kind_not_hardcoded_literals() -> None:
    xdr_src = inspect.getsource(ActionExecutionService._execute_xdr_managed)
    tool_src = inspect.getsource(ActionExecutionService._execute_direct_tool)
    assert "self._xdr_job_provider_name()" in xdr_src
    assert 'provider_name="mock_xdr"' not in xdr_src
    assert "self._direct_tool_job_provider_name" in tool_src
    assert 'provider_name="mock_tool_provider"' not in tool_src
    assert disposition_provider_name(
        Settings(
            APP_ENV="development",
            SOURCE_MODE="mock_xdr",
            DISPOSITION_MODE="mock_xdr",
            DISPOSITION_ADAPTER_KIND="mock",
            TOOL_MODE="mock",
            SIMULATION_ENABLED=True,
        )
    ) == MOCK_XDR_PROVIDER


def test_production_tool_mode_mock_still_fails() -> None:
    with pytest.raises(ConfigurationError):
        Settings(**production_settings_kwargs(TOOL_MODE="mock"))


def test_development_tool_mode_mock_still_succeeds() -> None:
    settings = Settings(
        APP_ENV="development",
        TOOL_MODE="mock",
        SOURCE_MODE="mock_xdr",
        DISPOSITION_MODE="mock_xdr",
        DISPOSITION_ADAPTER_KIND="mock",
        SIMULATION_ENABLED=True,
    )
    assert settings.tool_mode == "mock"
    assert settings.runtime_adapter_fail_closed_violations() == []


@pytest.mark.asyncio
async def test_sangfor_auth_probe_401_is_offline() -> None:
    class _Result:
        http_status = 401

    class _Client:
        async def request(self, *args: object, **kwargs: object) -> _Result:
            return _Result()

        async def aclose(self) -> None:
            return None

    settings = _sangfor_settings()
    status = await probe_sangfor_auth(settings, client=_Client())
    assert status is ConnectorStatus.OFFLINE
    assert await live_auth_failed(settings, client=_Client()) is True


@pytest.mark.asyncio
async def test_live_auth_skips_http_when_credentials_missing() -> None:
    class _MustNotCall:
        async def request(self, *args: object, **kwargs: object) -> object:
            raise AssertionError("live eval must not HTTP without Sangfor credentials")

        async def aclose(self) -> None:
            return None

    settings = _sangfor_settings(
        SANGFOR_ACCESS_KEY="",
        SANGFOR_SECRET_KEY="",
        SANGFOR_AUTH_CODE="",
    )
    assert settings.sangfor_access_key == ""
    from app.adapters.factory import sangfor_credentials_configured

    assert sangfor_credentials_configured(settings) is False
    assert await live_auth_failed(settings, client=_MustNotCall()) is True


@pytest.mark.asyncio
async def test_mock_health_skips_sangfor_auth_probe() -> None:
    settings = Settings(
        APP_ENV="development",
        SOURCE_MODE="mock_xdr",
        DISPOSITION_MODE="mock_xdr",
        DISPOSITION_ADAPTER_KIND="mock",
        TOOL_MODE="mock",
        SIMULATION_ENABLED=True,
    )
    assert await live_auth_failed(settings) is False
    component = source_adapter_component(settings)
    assert component["status"] == "ok"
    assert component["mode"] == "mock_xdr"


def test_missing_sangfor_credentials_mark_source_component_error() -> None:
    settings = _sangfor_settings(
        SANGFOR_ACCESS_KEY="",
        SANGFOR_SECRET_KEY="",
        SANGFOR_AUTH_CODE="",
        SANGFOR_XDR_BASE_URL="",
    )
    component = source_adapter_component(settings)
    assert component["status"] == "error"
    assert component["mode"] == "sangfor_xdr"
    assert "credential" not in str(component).lower()


def test_worker_empty_registry_construction_is_gone() -> None:
    src = inspect.getsource(action_execution_tasks)
    assert "DispositionAdapterRegistry()" not in src
    assert "build_disposition_adapter_registry" in src


def test_factory_keeps_http_kind_and_does_not_implement_crowdstrike() -> None:
    import app.adapters.factory as factory_mod

    factory_src = inspect.getsource(factory_mod)
    assert "KIND_HTTP" in factory_src
    assert "generic_http_disposition" in factory_src or "HttpDispositionAdapter" in factory_src
    assert "adapters.crowdstrike" not in factory_src


def test_shared_credential_flag_is_not_applied_to_mock() -> None:
    from app.adapters._util import require_separated_credentials

    with pytest.raises(ValueError, match="separated"):
        require_separated_credentials(read_token="same", write_token="same")
    settings = _sangfor_settings(SHARED_CREDENTIAL_SCOPE_VERIFIED=True)
    registry = build_disposition_adapter_registry(settings)
    assert registry.list_names() == [SANGFOR_PROVIDER]
