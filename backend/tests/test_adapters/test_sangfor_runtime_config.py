"""Sangfor Settings overlay/block parse must feed both ResponseAgent and factory."""

from __future__ import annotations

import json

import pytest

from app.adapters.factory import build_disposition_adapter_registry
from app.adapters.sangfor.capability_manifest import response_agent_overrides_for_kind
from app.adapters.sangfor.capability_overlay import SANGFOR_ADAPTER_KIND
from app.adapters.sangfor.disposition import SangforDispositionAdapter
from app.adapters.sangfor.runtime_config import (
    block_config_from_settings,
    overlay_config_from_settings,
)
from app.core.config import Settings
from app.core.errors import ConfigurationError
from app.models.enums import ExecutionOwner


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


def test_empty_settings_keep_block_scan_ticket_ownerless() -> None:
    settings = _sangfor_settings()
    overlay = overlay_config_from_settings(settings)
    assert overlay.devices == ()
    assert overlay.ticket_template_id is None
    index = response_agent_overrides_for_kind(SANGFOR_ADAPTER_KIND, settings)["tool_index"]
    for name in (
        "block_ip",
        "block_domain",
        "scan_host_for_virus",
        "create_ticket",
        "isolate_host",
        "disable_account",
        "notify_security_team",
    ):
        assert list(index[name].supported_execution_owners) == []
    adapter = build_disposition_adapter_registry(settings).get("sangfor_xdr")
    assert isinstance(adapter, SangforDispositionAdapter)
    assert adapter._block.devices == ()


def test_one_af_wires_block_scan_but_ticket_needs_assignees() -> None:
    settings = _sangfor_settings(
        SANGFOR_DEVICES=json.dumps(
            [{"deviceId": "af-1", "deviceType": "AF", "deviceName": "AF_011"}]
        ),
    )
    index = response_agent_overrides_for_kind(SANGFOR_ADAPTER_KIND, settings)["tool_index"]
    assert index["block_ip"].supported_execution_owners == [ExecutionOwner.XDR_MANAGED]
    assert index["block_domain"].supported_execution_owners == [ExecutionOwner.XDR_MANAGED]
    assert index["scan_host_for_virus"].supported_execution_owners == [
        ExecutionOwner.XDR_MANAGED
    ]
    assert list(index["create_ticket"].supported_execution_owners) == []
    assert list(index["isolate_host"].supported_execution_owners) == []
    assert list(index["disable_account"].supported_execution_owners) == []
    assert list(index["notify_security_team"].supported_execution_owners) == []
    adapter = build_disposition_adapter_registry(settings).get("sangfor_xdr")
    assert isinstance(adapter, SangforDispositionAdapter)
    assert adapter._usable_devices()[0]["devId"] == "af-1"
    assert adapter._usable_devices()[0]["devType"] == "AF"


def test_ticket_ready_only_with_template_and_assignees() -> None:
    settings = _sangfor_settings(
        SANGFOR_DEVICES=json.dumps([{"deviceId": "af-1", "deviceType": "AF"}]),
        SANGFOR_TICKET_TEMPLATE_ID="incidentBulletin",
        SANGFOR_TICKET_ASSIGNEE_IDS="user-1,user-2",
    )
    index = response_agent_overrides_for_kind(SANGFOR_ADAPTER_KIND, settings)["tool_index"]
    assert index["create_ticket"].supported_execution_owners == [ExecutionOwner.XDR_MANAGED]
    block = block_config_from_settings(settings)
    assert block.process_template_id == "incidentBulletin"
    assert block.next_assignee_ids == ("user-1", "user-2")


def test_kind_mock_overrides_ignore_sangfor_devices() -> None:
    settings = Settings(
        APP_ENV="development",
        SOURCE_MODE="mock_xdr",
        DISPOSITION_MODE="mock_xdr",
        DISPOSITION_ADAPTER_KIND="mock",
        TOOL_MODE="mock",
        SIMULATION_ENABLED=True,
        SANGFOR_DEVICES=json.dumps([{"deviceId": "af-1", "deviceType": "AF"}]),
    )
    assert response_agent_overrides_for_kind("mock", settings) == {}


def test_invalid_devices_json_fails_closed() -> None:
    settings = _sangfor_settings(SANGFOR_DEVICES="{not-json")
    with pytest.raises(ConfigurationError, match="SANGFOR_DEVICES"):
        overlay_config_from_settings(settings)
