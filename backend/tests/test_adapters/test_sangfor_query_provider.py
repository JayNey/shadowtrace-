"""Layer 8b live Sangfor query provider. Mock query path must stay green."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from httpx import ASGITransport

from app.adapters.factory import build_sangfor_live_query_adapters
from app.adapters.sangfor.client import SangforXdrClient
from app.adapters.sangfor.query_provider import QUERY_TOOL_NAMES, build_sangfor_query_adapters
from app.adapters.sangfor.wire_mock import create_sangfor_wire_app
from app.core.config import Settings
from app.models.tool_meta import ToolResultStatus
from app.services.evidence_projection import (
    EvidenceQueryScope,
    bind_evidence_projection,
    bind_evidence_query_scope,
)
from app.tools.adapters.base import AdapterConfig, configure_tool_registry
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry

_REPO_ROOT = Path(__file__).resolve().parents[3]
_VECTORS = json.loads(
    (_REPO_ROOT / "contracts" / "vendor" / "sangfor_xdr" / "signing_vectors.json").read_text(
        encoding="utf-8"
    )
)
WINDOW = {
    "start": "2024-06-15T08:00:00Z",
    "end": "2024-06-15T10:00:00Z",
}
SCOPE = EvidenceQueryScope(
    source_tenant_id="test-tenant",
    connector_ids=frozenset({"sangfor-xdr"}),
    source_object_id="incident-wire-001",
)


def _sangfor_settings(**overrides: object) -> Settings:
    kwargs: dict[str, object] = {
        "APP_ENV": "staging",
        "SOURCE_MODE": "sangfor_xdr",
        "DISPOSITION_MODE": "live_xdr",
        "DISPOSITION_ADAPTER_KIND": "sangfor_xdr",
        "TOOL_MODE": "live",
        "SIMULATION_ENABLED": False,
        "ALLOW_LIVE_SIDE_EFFECTS": True,
        "SANGFOR_XDR_BASE_URL": "http://sangfor-wire",
        "SANGFOR_ACCESS_KEY": _VECTORS["ak"],
        "SANGFOR_SECRET_KEY": _VECTORS["sk"],
        "SHARED_CREDENTIAL_SCOPE_VERIFIED": True,
    }
    kwargs.update(overrides)
    return Settings(**kwargs)


@asynccontextmanager
async def _signed_client() -> AsyncIterator[SangforXdrClient]:
    app = create_sangfor_wire_app()
    http = httpx.AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://sangfor-wire",
    )
    client = SangforXdrClient(
        "http://sangfor-wire",
        access_key=_VECTORS["ak"],
        secret_key=_VECTORS["sk"],
        client=http,
    )
    try:
        yield client
    finally:
        await client.aclose()


async def _live_executor(client: SangforXdrClient) -> ToolExecutor:
    registry = ToolRegistry()
    adapters = build_sangfor_query_adapters(
        client,
        AdapterConfig(endpoint="http://sangfor-wire", auth_type="none", enabled=True),
    )
    await configure_tool_registry(
        registry,
        tool_mode="live",
        adapters=adapters,
        simulation_enabled=False,
        allow_live_side_effects=True,
    )
    return ToolExecutor(registry=registry)


async def _call(executor: ToolExecutor, tool_name: str, params: dict[str, Any]) -> Any:
    with bind_evidence_query_scope(SCOPE):
        return await executor.call(tool_name, params, "evt-sangfor-query")


def test_kind_mock_does_not_build_sangfor_query_adapters() -> None:
    settings = Settings(
        APP_ENV="development",
        SOURCE_MODE="mock_xdr",
        DISPOSITION_MODE="mock_xdr",
        DISPOSITION_ADAPTER_KIND="mock",
        TOOL_MODE="mock",
        SIMULATION_ENABLED=True,
    )
    assert build_sangfor_live_query_adapters(settings) == []


@pytest.mark.asyncio
async def test_live_registry_has_no_mock_query_providers() -> None:
    async with _signed_client() as client:
        executor = await _live_executor(client)
    names = {tool.tool_meta.tool_name for tool in executor.registry.list_registered_tools()}
    assert set(QUERY_TOOL_NAMES).issubset(names)
    for tool_name in QUERY_TOOL_NAMES:
        bindings = executor.registry.list_bindings(tool_name)
        assert bindings
        assert all(binding.provider_name.startswith("sangfor_xdr_query:") for binding in bindings)
        assert all("mock" not in binding.provider_name for binding in bindings)


@pytest.mark.asyncio
async def test_query_account_login_is_unavailable_on_live() -> None:
    async with _signed_client() as client:
        executor = await _live_executor(client)
        result = await _call(
            executor,
            "query_account_login",
            {"account": "alice", "time_range": WINDOW},
        )
    assert result.status is ToolResultStatus.UNSUPPORTED
    assert result.provider_code == "query_unavailable"
    assert "entities/account" in (result.error_detail or "")
    assert result.data["degraded"] is True


@pytest.mark.asyncio
async def test_query_edr_process_is_degraded_event_snapshot() -> None:
    async with _signed_client() as client:
        executor = await _live_executor(client)
        result = await _call(
            executor,
            "query_edr_process",
            {"host_id": "PC-FIN-023", "time_range": WINDOW},
        )
    assert result.status is ToolResultStatus.SUCCESS
    assert result.data["degraded"] is True
    assert result.data["records"]
    assert any("snapshot" in reason for reason in result.data["coverage"]["reasons"])


@pytest.mark.asyncio
async def test_query_file_access_is_degraded_not_account_audit() -> None:
    async with _signed_client() as client:
        executor = await _live_executor(client)
        result = await _call(
            executor,
            "query_file_access",
            {"account": "alice", "time_range": WINDOW},
        )
    assert result.status is ToolResultStatus.SUCCESS
    assert result.data["degraded"] is True
    assert any("audit" in reason for reason in result.data["coverage"]["reasons"])


@pytest.mark.asyncio
async def test_query_dns_and_network_flow_are_degraded() -> None:
    async with _signed_client() as client:
        executor = await _live_executor(client)
        dns = await _call(
            executor,
            "query_dns",
            {"domain": "10.20.30.23", "time_range": WINDOW},
        )
        flow = await _call(
            executor,
            "query_network_flow",
            {"src_ip": "10.20.30.23", "time_range": WINDOW},
        )
    assert dns.status is ToolResultStatus.SUCCESS
    assert flow.status is ToolResultStatus.SUCCESS
    assert dns.data["degraded"] is True
    assert flow.data["degraded"] is True
    assert flow.data["records"]


@pytest.mark.asyncio
async def test_query_asset_info_succeeds_against_inventory() -> None:
    class _AssetClient:
        async def request(self, method: str, path: str, **_kwargs: Any) -> Any:
            from app.adapters.sangfor.client import SangforHttpResult
            from app.adapters.sangfor.signing import AUTH_HEADER_KEY, SIGN_DATE_KEY, SignedRequest

            assert path == "/api/xdr/v1/assets/list"
            assert method == "POST"
            return SangforHttpResult(
                http_status=200,
                business_code="Success",
                message="OK",
                data={
                    "item": [
                        {"id": "asset-1", "hostIp": "10.20.30.23", "hostName": "PC-FIN-023"},
                    ]
                },
                raw_text="{}",
                signed=SignedRequest(
                    method="POST",
                    url="http://sangfor-wire/api/xdr/v1/assets/list",
                    headers={
                        AUTH_HEADER_KEY: (
                            "algorithm=HMAC-SHA256, Access=t, "
                            "SignedHeaders=sign-date, Signature=ab"
                        ),
                        SIGN_DATE_KEY: "20240101T000000Z",
                    },
                    payload="{}",
                    signature="ab",
                    signed_headers="sign-date",
                    canonical_request="",
                    payload_hash="",
                    canonical_query="",
                    access_key="test",
                ),
            )

        async def aclose(self) -> None:
            return None

    executor = await _live_executor(_AssetClient())  # type: ignore[arg-type]
    result = await _call(executor, "query_asset_info", {"ip": "10.20.30.23"})
    assert result.status is ToolResultStatus.SUCCESS
    assert result.data["degraded"] is False
    assert result.data["records"][0]["hostIp"] == "10.20.30.23"


@pytest.mark.asyncio
async def test_query_vuln_and_history_are_unavailable_on_live() -> None:
    async with _signed_client() as client:
        executor = await _live_executor(client)
        vuln = await _call(
            executor,
            "query_vuln_info",
            {"ip": "10.20.30.23", "time_range": WINDOW},
        )
        history = await _call(
            executor,
            "query_history_cases",
            {"pattern_description": "lateral rdp pivot", "time_range": WINDOW},
        )
    assert vuln.status is ToolResultStatus.UNSUPPORTED
    assert history.status is ToolResultStatus.UNSUPPORTED
    assert vuln.provider_code == "query_unavailable"
    assert history.provider_code == "query_unavailable"
    assert vuln.data["degraded"] is True
    assert history.data["degraded"] is True
    assert "mock" not in vuln.provider_name
    assert "mock" not in history.provider_name


@pytest.mark.asyncio
async def test_query_threat_intel_is_degraded_not_catalog() -> None:
    async with _signed_client() as client:
        executor = await _live_executor(client)
        result = await _call(
            executor,
            "query_threat_intel",
            {"indicator": "10.20.30.23", "time_range": WINDOW},
        )
    assert result.status is ToolResultStatus.SUCCESS
    assert result.data["degraded"] is True
    assert any("intel" in reason for reason in result.data["coverage"]["reasons"])
    assert "mock" not in result.provider_name


@pytest.mark.asyncio
async def test_mock_query_account_login_and_edr_still_succeed() -> None:
    from app.services.evidence_projection import EvidenceProjection
    from app.tools.query.fixture_loader import load_fixture_records

    registry = ToolRegistry()
    await registry.auto_discover_for_mode(tool_mode="mock", simulation_enabled=True)
    projection = EvidenceProjection.in_memory()
    loaded = await load_fixture_records(projection, _REPO_ROOT / "data" / "mock")
    assert loaded > 0

    class _Svc:
        async def get_evidence_query_scope(self, event_id: str) -> EvidenceQueryScope:
            return EvidenceQueryScope(
                source_tenant_id="test-tenant",
                connector_ids=frozenset({"fixture-evidence"}),
            )

    with bind_evidence_projection(projection):
        login = await registry.execute_event_query(
            "evt-query-test",
            "query_account_login",
            {"account": "zhangsan", "time_range": WINDOW},
            event_service=_Svc(),
        )
        edr = await registry.execute_event_query(
            "evt-query-test",
            "query_edr_process",
            {"host_id": "PC-FIN-023", "time_range": WINDOW},
            event_service=_Svc(),
        )
    assert login["status"] == "success"
    assert edr["status"] == "success"
    assert login["data"]["records"]
    assert edr["data"]["records"]
