"""Layer 10 first-contact script against the vendor wire mock (not live XDR)."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from httpx import ASGITransport

from app.adapters.sangfor.client import SangforHttpResult, SangforXdrClient
from app.adapters.sangfor.disposition import (
    dealstatus_readback_would_confirm,
    source_disposition_from_outbound_tmg,
)
from app.adapters.sangfor.signing import AUTH_HEADER_KEY, SIGN_DATE_KEY, SignedRequest
from app.adapters.sangfor.wire_mock import create_sangfor_wire_app
from app.models.enums import SourceDisposition

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "sangfor_xdr_first_contact.py"
_VECTORS = json.loads(
    (_REPO_ROOT / "contracts" / "vendor" / "sangfor_xdr" / "signing_vectors.json").read_text(
        encoding="utf-8"
    )
)
_ISOLATE_CREATE_INVENTED = "/api/xdr/v1/responses/host/isolate"


def _load_script():
    spec = importlib.util.spec_from_file_location("sangfor_xdr_first_contact", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


script = _load_script()


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


def _stub_signed(path: str) -> SignedRequest:
    return SignedRequest(
        method="POST",
        url=f"http://sangfor-wire{path}",
        headers={
            AUTH_HEADER_KEY: "algorithm=HMAC-SHA256, Access=test, SignedHeaders=sign-date, Signature=ab",
            SIGN_DATE_KEY: "20240101T000000Z",
        },
        payload="{}",
        signature="ab",
        signed_headers="sign-date",
        canonical_request="",
        payload_hash="",
        canonical_query="",
        access_key="test",
    )


class _EmptyDeviceClient:
    """Fake client: incidents/list ok, blockdevice/list item=[]. Does not change wire_mock."""

    def __init__(self) -> None:
        self.outbound: list[tuple[str, str, Any]] = []

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        **_kwargs: Any,
    ) -> SangforHttpResult:
        self.outbound.append((method, path, json_body))
        if path == script.INCIDENTS_LIST_PATH:
            data: dict[str, Any] = {
                "item": [{"uuId": "incident-wire-001", "dealStatus": 10}],
            }
        elif path == script.BLOCKDEVICE_LIST_PATH:
            data = {"item": []}
        else:
            data = {}
        return SangforHttpResult(
            http_status=200,
            business_code="Success",
            message="OK",
            data=data,
            raw_text=json.dumps({"code": "Success", "data": data}),
            signed=_stub_signed(path),
        )

    async def aclose(self) -> None:
        return None


def _paths(report: Any) -> list[str]:
    return [call.path for call in report.calls]


def _body_for(report: Any, path: str) -> dict[str, Any]:
    for call in report.calls:
        if call.path == path:
            assert isinstance(call.json_body, dict)
            return call.json_body
    raise AssertionError(f"no call recorded for {path}")


@pytest.mark.asyncio
async def test_default_probe_only_list_and_blockdevice_against_wire_mock(
    tmp_path: Path,
) -> None:
    async with _signed_client() as client:
        report = await script.run(client=client, artifacts_dir=tmp_path)
    assert report.exit_code == 0
    assert _paths(report) == [
        script.INCIDENTS_LIST_PATH,
        script.BLOCKDEVICE_LIST_PATH,
    ]
    assert script.DEALSTATUS_WRITE_PATH not in _paths(report)
    assert script.DEALSTATUS_LIST_PATH not in _paths(report)

    body = _body_for(report, script.INCIDENTS_LIST_PATH)
    for key in ("startTimestamp", "endTimestamp", "timeField", "page", "pageSize"):
        assert key in body
    assert body["timeField"] == "endTime"
    assert body["page"] == 1
    assert body["pageSize"] == 5
    assert "uuIds" not in body
    assert "severities" not in body
    assert "orders" not in body

    device_body = _body_for(report, script.BLOCKDEVICE_LIST_PATH)
    assert isinstance(device_body["type"], list)
    assert device_body["type"]
    assert "AF" in device_body["type"]
    assert "" not in device_body["type"]

    list_call = report.calls[0]
    assert AUTH_HEADER_KEY in list_call.headers
    assert SIGN_DATE_KEY in list_call.headers
    device_call = report.calls[1]
    assert AUTH_HEADER_KEY in device_call.headers
    assert SIGN_DATE_KEY in device_call.headers


@pytest.mark.asyncio
async def test_empty_blockdevice_list_is_success(tmp_path: Path) -> None:
    client = _EmptyDeviceClient()
    report = await script.run(client=client, artifacts_dir=tmp_path)
    assert report.exit_code == 0
    assert "no devices" in report.notes
    assert report.devices == []
    assert client.outbound[1][1] == script.BLOCKDEVICE_LIST_PATH
    assert script.DEALSTATUS_WRITE_PATH not in _paths(report)


@pytest.mark.asyncio
async def test_invented_isolate_create_is_404_and_absent_from_script() -> None:
    source = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert _ISOLATE_CREATE_INVENTED not in source
    app = create_sangfor_wire_app()
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://sangfor-wire",
    ) as client:
        created = await client.post(_ISOLATE_CREATE_INVENTED, json={"hostIp": "10.20.30.23"})
    assert created.status_code == 404


@pytest.mark.asyncio
async def test_write_same_status_never_writes_70_and_readback_uses_ids(
    tmp_path: Path,
) -> None:
    async with _signed_client() as client:
        report = await script.run(
            client=client,
            write_same_status=True,
            event_uuid="incident-wire-001",
            artifacts_dir=tmp_path,
        )
    assert report.exit_code == 0
    assert report.write_deal_status == 10
    assert report.write_deal_status != 70
    assert report.confirmed is False
    write_body = _body_for(report, script.DEALSTATUS_WRITE_PATH)
    assert write_body["dealStatus"] != 70
    assert write_body["dealStatus"] == 10
    assert write_body["uuIds"] == ["incident-wire-001"]
    readback_body = _body_for(report, script.DEALSTATUS_LIST_PATH)
    assert "ids" in readback_body
    assert "uuIds" not in readback_body
    assert readback_body["ids"] == ["incident-wire-001"]

    assert source_disposition_from_outbound_tmg(10) is SourceDisposition.PROCESSING
    assert (
        dealstatus_readback_would_confirm(
            write_code="Success",
            succeeded_num=1,
            total=1,
            list_deal_status=6,
            target=SourceDisposition.PROCESSING,
        )
        is False
    )
    assert (
        dealstatus_readback_would_confirm(
            write_code="Success",
            succeeded_num=1,
            total=1,
            list_deal_status=2,
            target=SourceDisposition.PROCESSING,
        )
        is True
    )
    assert (
        dealstatus_readback_would_confirm(
            write_code="Success",
            succeeded_num=1,
            total=1,
            list_deal_status=6,
            target=SourceDisposition.CONTAINED,
        )
        is True
    )


@pytest.mark.asyncio
async def test_missing_base_url_or_credentials_is_nonzero_with_no_outbound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outbound: list[Any] = []

    original = httpx.AsyncClient.request

    async def _tracked(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> httpx.Response:
        outbound.append((args, kwargs))
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "request", _tracked)

    missing_url = await script.run(env={})
    assert missing_url.exit_code != 0
    assert missing_url.calls == []

    missing_creds = await script.run(
        env={"SANGFOR_XDR_BASE_URL": "http://127.0.0.1:1", "APP_ENV": "staging"},
    )
    assert missing_creds.exit_code != 0
    assert missing_creds.calls == []

    production = await script.run(
        env={
            "APP_ENV": "production",
            "SANGFOR_XDR_BASE_URL": "http://127.0.0.1:1",
            "SANGFOR_ACCESS_KEY": "ak",
            "SANGFOR_SECRET_KEY": "sk",
        },
    )
    assert production.exit_code != 0
    assert production.calls == []
    assert outbound == []


def test_script_does_not_enable_writeback_env() -> None:
    source = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "ALLOW_XDR_WRITEBACK" not in source
    assert "os.environ[" not in source


def test_script_does_not_read_env_live() -> None:
    source = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "load_dotenv" not in source
    assert "dotenv" not in source
    assert ".env.live" not in source.replace("Does not read .env.live", "")
