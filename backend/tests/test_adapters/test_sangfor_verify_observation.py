"""Sangfor Verify observation (Layer 8b). Never Mock file state; never isolate create."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.adapters.sangfor.verify_observation import (
    BLOCK_DETAIL_PATH,
    ISOLATE_LIST_PATH,
    observe_sangfor_verification,
)
from app.models.tool_meta import ToolResultStatus
from app.tools.verify._common import execute_verification_tool

_VERIFY_OBS_SRC = (
    Path(__file__).resolve().parents[2] / "app" / "adapters" / "sangfor" / "verify_observation.py"
)
_VERIFY_AGENT_SRC = Path(__file__).resolve().parents[2] / "app" / "agents" / "verify_agent.py"
_ISOLATE_CREATE_INVENTED = "/api/xdr/v1/responses/host/isolate"


class _FakeClient:
    def __init__(self, data: Any, *, path_data: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.data = data
        self.path_data = path_data or {}

    async def request(self, method: str, path: str, **kwargs: Any) -> SimpleNamespace:
        self.calls.append((method, path, kwargs))
        payload = self.path_data.get(path, self.data)
        return SimpleNamespace(
            http_status=200,
            business_code="Success",
            data=payload,
            message="ok",
        )


def test_verify_observation_does_not_invent_isolate_create() -> None:
    text = _VERIFY_OBS_SRC.read_text(encoding="utf-8")
    assert ISOLATE_LIST_PATH in text
    assert _ISOLATE_CREATE_INVENTED + "/list" in text
    assert f'"{_ISOLATE_CREATE_INVENTED}"' not in text
    assert f"'{_ISOLATE_CREATE_INVENTED}'" not in text


def test_verify_agent_has_no_vendor_uri() -> None:
    text = _VERIFY_AGENT_SRC.read_text(encoding="utf-8")
    assert "/api/xdr/" not in text
    assert "isolate/list" not in text


def test_verify_tools_do_not_import_sangfor_package() -> None:
    src = (
        Path(__file__).resolve().parents[2] / "app" / "tools" / "verify" / "_common.py"
    )
    text = src.read_text(encoding="utf-8")
    assert "adapters.sangfor" not in text
    assert "observe_sangfor_verification" not in text


@pytest.mark.asyncio
async def test_isolate_list_one_row_is_not_confirmed() -> None:
    client = _FakeClient(
        {
            "item": [
                {
                    "id": "isolate-1",
                    "hostIp": "10.20.30.23",
                    "isolateStatus": "isolated",
                }
            ]
        }
    )
    result = await observe_sangfor_verification(
        "check_host_isolation_status",
        {"target_type": "host", "target": "10.20.30.23"},
        client=client,
    )
    assert result["status"] == ToolResultStatus.UNKNOWN.value
    assert result["data"].get("is_verified") is not True
    assert any(path == ISOLATE_LIST_PATH for _method, path, _kwargs in client.calls)


@pytest.mark.asyncio
async def test_account_status_does_not_invent_query() -> None:
    client = _FakeClient({"item": []})
    result = await observe_sangfor_verification(
        "check_account_status",
        {"target_type": "account", "target": "svc-backup"},
        client=client,
    )
    assert result["status"] == ToolResultStatus.UNKNOWN.value
    assert result["data"].get("is_verified") is not True
    assert client.calls == []


@pytest.mark.asyncio
async def test_block_ip_verified_on_block_success_literal() -> None:
    client = _FakeClient(
        {
            "item": [
                {
                    "id": "rule-1",
                    "status": "block success",
                    "blockIpRule": {"type": "DST_IP"},
                }
            ]
        }
    )
    result = await observe_sangfor_verification(
        "check_ip_block_status",
        {
            "target_type": "ip",
            "target": "203.0.113.50",
            "parameters": {"job_id": "rule-1"},
        },
        client=client,
    )
    assert result["status"] == ToolResultStatus.SUCCESS.value
    assert result["data"]["is_verified"] is True
    assert any(path == BLOCK_DETAIL_PATH for _method, path, _kwargs in client.calls)


@pytest.mark.asyncio
async def test_domain_block_requires_dns_type() -> None:
    client = _FakeClient(
        {
            "item": [
                {
                    "id": "rule-dns",
                    "status": "block success",
                    "blockIpRule": {"type": "DST_IP"},
                }
            ]
        }
    )
    result = await observe_sangfor_verification(
        "check_domain_block_status",
        {
            "target_type": "domain",
            "target": "evil.example",
            "parameters": {"job_id": "rule-dns"},
        },
        client=client,
    )
    assert result["status"] == ToolResultStatus.UNKNOWN.value
    assert result["data"].get("is_verified") is not True


class _BoomRuntime:
    async def execute(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError(f"MockVerificationRuntime must not run for {tool_name}")


@pytest.mark.asyncio
async def test_kind_sangfor_host_and_account_skip_mock_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.tools.verify._common.get_mock_verification_runtime",
        lambda: _BoomRuntime(),
    )
    monkeypatch.setattr(
        "app.core.config.get_settings",
        lambda: SimpleNamespace(disposition_adapter_kind="sangfor_xdr"),
    )
    isolate = await execute_verification_tool(
        "check_host_isolation_status",
        {"target_type": "host", "target": "PC-FIN-023"},
    )
    account = await execute_verification_tool(
        "check_account_status",
        {"target_type": "account", "target": "svc-backup"},
    )
    assert isolate["status"] == ToolResultStatus.UNKNOWN.value
    assert isolate["data"].get("is_verified") is not True
    assert account["status"] == ToolResultStatus.UNKNOWN.value
    assert account["data"].get("is_verified") is not True


@pytest.mark.asyncio
async def test_kind_sangfor_block_ip_does_not_read_mock_file_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.tools.verify._common.get_mock_verification_runtime",
        lambda: _BoomRuntime(),
    )
    monkeypatch.setattr(
        "app.core.config.get_settings",
        lambda: SimpleNamespace(disposition_adapter_kind="sangfor_xdr"),
    )
    result = await execute_verification_tool(
        "check_ip_block_status",
        {
            "target_type": "ip",
            "target": "203.0.113.50",
            "parameters": {"job_id": "job-block-1"},
        },
    )
    assert result["provider_name"] != "mock_observation"
    assert result["data"].get("is_verified") is not True


@pytest.mark.asyncio
async def test_kind_mock_still_uses_mock_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    class _Capture:
        async def execute(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
            seen.append(tool_name)
            return {
                "call_id": "call-mock",
                "tool_name": tool_name,
                "provider_name": "mock_observation",
                "status": ToolResultStatus.SUCCESS.value,
                "data": {"is_verified": True},
            }

    monkeypatch.setattr(
        "app.tools.verify._common.get_mock_verification_runtime",
        lambda: _Capture(),
    )
    monkeypatch.setattr(
        "app.core.config.get_settings",
        lambda: SimpleNamespace(disposition_adapter_kind="mock"),
    )
    result = await execute_verification_tool(
        "check_host_isolation_status",
        {"target_type": "host", "target": "PC-FIN-023"},
    )
    assert seen == ["check_host_isolation_status"]
    assert result["provider_name"] == "mock_observation"
    assert result["data"]["is_verified"] is True
