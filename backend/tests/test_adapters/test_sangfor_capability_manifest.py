"""Sangfor CapabilityManifest + KIND gate for ResponseAgent (Layer 8a)."""

from __future__ import annotations

from app.adapters.sangfor.capability_manifest import (
    build_sangfor_capability_manifest,
    response_agent_overrides_for_kind,
)
from app.adapters.sangfor.capability_overlay import SANGFOR_ADAPTER_KIND
from app.core.config import Settings
from app.models.enums import CapabilityState, ExecutionOwner


def _empty_sangfor_settings() -> Settings:
    return Settings(
        APP_ENV="staging",
        SOURCE_MODE="sangfor_xdr",
        DISPOSITION_MODE="live_xdr",
        DISPOSITION_ADAPTER_KIND="sangfor_xdr",
        TOOL_MODE="live",
        SIMULATION_ENABLED=False,
        ALLOW_LIVE_SIDE_EFFECTS=True,
    )


def test_sangfor_manifest_keeps_isolate_and_is_not_mock() -> None:
    manifest = build_sangfor_capability_manifest()
    assert manifest.provider_name == "sangfor_xdr"
    assert manifest.supports_concurrency_control is False
    assert manifest.supports_fencing is False
    assert "isolate_host" in manifest.allowed_operations
    assert "disable_account" in manifest.allowed_operations
    assert "query_account_login" not in manifest.allowed_operations
    assert manifest.source_read is CapabilityState.UNKNOWN


def test_overrides_empty_for_mock_kind() -> None:
    assert response_agent_overrides_for_kind("mock") == {}
    assert response_agent_overrides_for_kind("MOCK") == {}
    assert response_agent_overrides_for_kind("http") == {}
    assert response_agent_overrides_for_kind("") == {}


def test_overrides_apply_overlay_only_for_sangfor_kind() -> None:
    overrides = response_agent_overrides_for_kind(
        SANGFOR_ADAPTER_KIND,
        _empty_sangfor_settings(),
    )
    assert set(overrides) == {"tool_index", "capability_manifest"}
    isolate = overrides["tool_index"]["isolate_host"]
    assert list(isolate.supported_execution_owners) == []
    assert isolate.executable is True
    disable = overrides["tool_index"]["disable_account"]
    assert ExecutionOwner.XDR_MANAGED not in disable.supported_execution_owners
    assert ExecutionOwner.DIRECT_TOOL not in disable.supported_execution_owners
    manifest = overrides["capability_manifest"]
    assert manifest.provider_name == "sangfor_xdr"
    assert "isolate_host" in manifest.allowed_operations
