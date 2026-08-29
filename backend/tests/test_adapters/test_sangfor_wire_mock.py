"""Sangfor vendor wire mock gates (alignment plan Layer 3).

This ASGI fixture is not the product Demo. Canonical Mock remains /mock-xdr/v1.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from httpx import ASGITransport

from app.adapters.sangfor.client import SangforXdrClient, apply_path_params
from app.adapters.sangfor.wire_mock import (
    SangforWireConfig,
    create_sangfor_wire_app,
    dealstatus_writeback_would_confirm,
    entity_write_would_confirm,
)
from app.api.v1 import deps
from app.core.config import Settings

_REPO_ROOT = Path(__file__).resolve().parents[3]
_VECTORS = json.loads(
    (_REPO_ROOT / "contracts" / "vendor" / "sangfor_xdr" / "signing_vectors.json").read_text(
        encoding="utf-8"
    )
)

_DEALSTATUS_WRITE = "/api/xdr/v1/incidents/dealstatus"
_DEALSTATUS_LIST = "/api/xdr/v1/incidents/dealstatus/list"
_INCIDENTS_LIST = "/api/xdr/v1/incidents/list"
_ISOLATE_CREATE_INVENTED = "/api/xdr/v1/responses/host/isolate"
_ISOLATE_LIST = "/api/xdr/v1/responses/host/isolate/list"


def _write_body(uuids: list[str] | None = None, deal_status: int = 70) -> dict[str, Any]:
    return {
        "uuIds": uuids or ["incident-wire-001"],
        "dealStatus": deal_status,
        "dealComment": "wire-mock",
    }


def _list_body(ids: list[str] | None = None) -> dict[str, Any]:
    return {"ids": ids or ["incident-wire-001"]}


def _confirm_from_pair(write: dict[str, Any], readback: dict[str, Any]) -> bool:
    data = write.get("data") if isinstance(write.get("data"), dict) else {}
    readback_data = readback.get("data") if isinstance(readback.get("data"), dict) else {}
    items = (readback_data or {}).get("item") or []
    list_status = items[0].get("dealStatus") if items else None
    return dealstatus_writeback_would_confirm(
        write_code=write.get("code"),
        succeeded_num=data.get("succeededNum"),
        total=data.get("total"),
        list_deal_status=list_status,
    )


@asynccontextmanager
async def _raw(config: SangforWireConfig | None = None) -> AsyncIterator[httpx.AsyncClient]:
    app = create_sangfor_wire_app(config=config)
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://sangfor-wire",
    ) as client:
        yield client


@asynccontextmanager
async def _signed(
    config: SangforWireConfig | None = None,
) -> AsyncIterator[SangforXdrClient]:
    app = create_sangfor_wire_app(config=config)
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


@pytest.mark.asyncio
async def test_write_70_then_dealstatus_list_returns_library_code_6() -> None:
    async with _raw() as client:
        write = (await client.post(_DEALSTATUS_WRITE, json=_write_body())).json()
        readback = (await client.post(_DEALSTATUS_LIST, json=_list_body())).json()
    assert write["code"] == "Success"
    assert write["data"]["succeededNum"] == write["data"]["total"] == 1
    assert readback["data"]["item"][0]["dealStatus"] == 6
    assert _confirm_from_pair(write, readback) is True


@pytest.mark.asyncio
async def test_misaligned_dealstatus_list_70_must_not_confirm() -> None:
    async with _raw(SangforWireConfig(dealstatus_list_status=70)) as client:
        write = (await client.post(_DEALSTATUS_WRITE, json=_write_body())).json()
        readback = (await client.post(_DEALSTATUS_LIST, json=_list_body())).json()
    assert write["code"] == "Success"
    assert readback["data"]["item"][0]["dealStatus"] == 70
    assert _confirm_from_pair(write, readback) is False
    assert (
        dealstatus_writeback_would_confirm(
            write_code="Success",
            succeeded_num=1,
            total=1,
            list_deal_status=70,
        )
        is False
    )


@pytest.mark.asyncio
async def test_incidents_list_echo_30_must_not_confirm_writeback() -> None:
    async with _raw() as client:
        await client.post(_DEALSTATUS_WRITE, json=_write_body())
        listing = (await client.post(_INCIDENTS_LIST, json={"page": 1, "pageSize": 5})).json()
        readback = (await client.post(_DEALSTATUS_LIST, json=_list_body())).json()
    item = listing["data"]["item"][0]
    assert item["dealStatus"] == 30
    assert readback["data"]["item"][0]["dealStatus"] == 6
    assert (
        dealstatus_writeback_would_confirm(
            write_code="Success",
            succeeded_num=1,
            total=1,
            list_deal_status=item["dealStatus"],
            used_incidents_list=True,
        )
        is False
    )


@pytest.mark.asyncio
async def test_partial_dealstatus_succeeded_num_must_not_confirm() -> None:
    async with _raw(SangforWireConfig(partial_dealstatus=True)) as client:
        write = (await client.post(_DEALSTATUS_WRITE, json=_write_body())).json()
        readback = (await client.post(_DEALSTATUS_LIST, json=_list_body())).json()
    assert write["data"]["succeededNum"] < write["data"]["total"]
    assert readback["data"]["item"][0]["dealStatus"] == 6
    assert _confirm_from_pair(write, readback) is False


@pytest.mark.asyncio
async def test_assets_list_http_200_business_invalid_parameter() -> None:
    async with _raw() as client:
        response = await client.post("/api/xdr/v1/assets/list", json={"page": 1})
    payload = response.json()
    assert response.status_code == 200
    assert payload["code"] == "InvalidParameter"
    assert payload["code"] != "Success"


@pytest.mark.asyncio
async def test_blockiprule_unblock_part_success_must_not_confirm() -> None:
    async with _raw() as client:
        response = await client.post(
            "/api/xdr/v1/responses/blockiprule/unblock",
            json={"ids": ["ok-1", "fail-1"]},
        )
    payload = response.json()
    assert response.status_code == 200
    assert payload["code"] == "Part Success"
    assert entity_write_would_confirm(code=payload["code"]) is False


@pytest.mark.asyncio
async def test_alerts_list_uses_alert_deal_status_not_deal_status() -> None:
    async with _raw() as client:
        payload = (await client.post("/api/xdr/v1/alerts/list", json={"page": 1})).json()
    item = payload["data"]["item"][0]
    assert "alertDealStatus" in item
    assert "dealStatus" not in item


@pytest.mark.asyncio
async def test_analysislog_list_has_no_total_and_count_matches_item_len() -> None:
    async with _raw() as client:
        listing = (
            await client.post("/api/xdr/v1/analysislog/networksecurity/list", json={"page": 1})
        ).json()
        counted = (
            await client.post("/api/xdr/v1/analysislog/networksecurity/count", json={})
        ).json()
    assert "total" not in listing["data"]
    items = listing["data"]["item"]
    assert counted["data"]["total"] == len(items) == 1


@pytest.mark.asyncio
async def test_invented_isolate_create_is_404_while_isolate_list_is_200() -> None:
    async with _raw() as client:
        created = await client.post(_ISOLATE_CREATE_INVENTED, json={"hostIp": "10.20.30.23"})
        listed = await client.post(_ISOLATE_LIST, json={"page": 1})
    assert created.status_code == 404
    assert listed.status_code == 200
    assert listed.json()["code"] == "Success"
    assert listed.json()["data"]["item"][0]["hostIp"] == "10.20.30.23"


@pytest.mark.asyncio
async def test_bigscreen_is_not_implemented() -> None:
    async with _raw() as client:
        response = await client.post("/api/xdr/v1/bigscreen/overview", json={})
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_p1_minimum_legal_payloads() -> None:
    async with _raw() as client:
        entities = await client.get("/api/xdr/v1/incidents/incident-wire-001/entities/host")
        proof = await client.get("/api/xdr/v1/incidents/incident-wire-001/proof")
        network = await client.post("/api/xdr/v1/responses/blockiprule/network", json={})
        endpoint = await client.post("/api/xdr/v1/responses/blockiprule/endpoint", json={})
        listed = await client.post("/api/xdr/v1/responses/blockiprule/list", json={})
        detail = await client.post("/api/xdr/v1/responses/blockiprule/detail", json={})
        reblock = await client.post("/api/xdr/v1/responses/blockiprule/reblock", json={})
        devices = await client.post("/api/xdr/v1/device/blockdevice/list", json={})
        scan = await client.post("/api/xdr/v1/responses/virusscantask", json={})
        status_path = apply_path_params(
            "/api/xdr/v1/responses/virusscantask/:taskId",
            {"taskId": "626664a025d603db019fd84c"},
        )
        scan_status = await client.get(status_path)
    assert entities.status_code == 200
    assert proof.status_code == 200
    for response in (network, endpoint, listed, detail, reblock):
        assert response.status_code == 200
        assert response.json()["code"] == "Success"
    device_item = devices.json()["data"]["item"][0]
    assert device_item["deviceId"] == 12346
    assert "devId" not in device_item
    assert scan.json()["code"] == ""
    assert scan.json()["data"]["taskId"]
    assert scan_status.json()["code"] == ""
    assert scan_status.json()["data"]["taskId"]


@pytest.mark.asyncio
async def test_signed_client_can_replay_dealstatus_without_real_network() -> None:
    async with _signed() as client:
        write = await client.request("POST", _DEALSTATUS_WRITE, json_body=_write_body())
        readback = await client.request("POST", _DEALSTATUS_LIST, json_body=_list_body())
    assert write.http_status == 200
    assert write.business_code == "Success"
    items = (readback.data or {}).get("item") or []
    assert items[0]["dealStatus"] == 6
    assert (
        dealstatus_writeback_would_confirm(
            write_code=write.business_code,
            succeeded_num=write.data["succeededNum"],
            total=write.data["total"],
            list_deal_status=items[0]["dealStatus"],
        )
        is True
    )


def test_wire_mock_is_not_disposition_adapter_kind_mock_factory() -> None:
    from app.adapters.factory import build_disposition_adapter_registry

    deps_source = inspect.getsource(deps._get_adapter_registry)
    assert "build_disposition_adapter_registry" in deps_source
    assert "wire_mock" not in deps_source
    assert "create_sangfor_wire_app" not in deps_source
    registry = build_disposition_adapter_registry(Settings())
    assert registry.list_names() == ["mock_xdr"]
    assert Settings.model_fields["disposition_adapter_kind"].default == "mock"

    import app.adapters as adapters_pkg
    import app.adapters.factory as factory_mod
    import app.adapters.mock_xdr as mock_xdr

    assert "create_sangfor_wire_app" not in adapters_pkg.__all__
    assert "wire_mock" not in inspect.getsource(mock_xdr)
    assert "create_sangfor_wire_app" not in inspect.getsource(factory_mod)
