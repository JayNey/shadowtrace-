"""Sangfor SourceAdapter incident-list gates (alignment plan Layer 4)."""

from __future__ import annotations

import inspect
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from httpx import ASGITransport

from app.adapters.sangfor.client import SangforXdrClient
from app.adapters.sangfor.source import (
    INCIDENT_ENTITY_KINDS,
    MOCK_QUERY_EVIDENCE_KEYS,
    SOURCE_PRODUCT,
    SangforSourceAdapter,
    alert_item_to_source,
    decode_incident_cursor,
    incident_entity_path,
    incident_has_more,
    incident_item_to_source,
)
from app.adapters.sangfor.wire_mock import create_sangfor_wire_app
from app.adapters.source.base import InMemoryDataQualityRecorder
from app.api.v1 import deps
from app.core.config import Settings
from app.core.errors import DependencyUnavailableError
from app.ingestion import ingestion_scheduler
from app.ingestion.source_ingester import source_to_ingestable
from app.models.enums import ConnectorStatus, Severity, SourceDisposition, SourceObjectKind
from app.models.source import SourceAlert, SourceAsset, SourceIncident, SourceLog

_REPO_ROOT = Path(__file__).resolve().parents[3]
_VECTORS = json.loads(
    (_REPO_ROOT / "contracts" / "vendor" / "sangfor_xdr" / "signing_vectors.json").read_text(
        encoding="utf-8"
    )
)

_NOW = datetime(2026, 4, 28, 11, 28, 37, tzinfo=UTC)
_WINDOW_END = int(_NOW.timestamp())
_WINDOW_START = _WINDOW_END - 24 * 3600


def _client(http: httpx.AsyncClient) -> SangforXdrClient:
    return SangforXdrClient(
        str(http.base_url),
        access_key=_VECTORS["ak"],
        secret_key=_VECTORS["sk"],
        client=http,
    )


@asynccontextmanager
async def _wire_adapter() -> AsyncIterator[SangforSourceAdapter]:
    app = create_sangfor_wire_app()
    http = httpx.AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://sangfor-wire",
    )
    adapter = SangforSourceAdapter(
        _client(http),
        connector_id="conn-wire",
        now_fn=lambda: _NOW,
    )
    try:
        yield adapter
    finally:
        await http.aclose()


def test_source_incident_still_has_no_description_field() -> None:
    assert "description" not in SourceIncident.model_fields
    assert SourceIncident.model_config.get("extra") == "forbid"


def test_deal_status_30_is_contained_and_unknown_stays_unknown() -> None:
    contained = incident_item_to_source(
        {"uuId": "incident-a", "dealStatus": 30, "name": "shielded"},
        connector_id="c1",
        source_tenant_id="t1",
    )
    assert contained is not None
    assert contained.reference.source_disposition is SourceDisposition.CONTAINED
    assert contained.reference.source_status_raw == "30"
    unknown = incident_item_to_source(
        {"uuId": "incident-b", "dealStatus": 99},
        connector_id="c1",
        source_tenant_id="t1",
    )
    assert unknown is not None
    assert unknown.reference.source_disposition is SourceDisposition.UNKNOWN
    assert unknown.reference.source_status_raw == "99"


def test_information_severity_projects_to_ingester_low() -> None:
    item = incident_item_to_source(
        {
            "uuId": "incident-info",
            "name": "info event",
            "description": "vendor description text",
            "incidentSeverity": -1,
            "dealStatus": 0,
            "gptResult": 115,
            "gptResultDescription": "主机失陷活动",
        },
        connector_id="c1",
        source_tenant_id="t1",
    )
    assert item is not None
    assert item.level == "information"
    assert item.gpt_verdict_label is None
    assert item.normalized["description"] == "vendor description text"
    assert item.raw_payload["incidentSeverity"] == -1
    assert item.raw_payload["gptResult"] == 115
    assert "gptResult" not in item.normalized
    ingested = source_to_ingestable(item, source_type="incident")
    assert ingested.severity is Severity.LOW
    assert ingested.description == "vendor description text"
    assert ingested.event_type.value == "other"


def test_has_more_uses_page_times_page_size_against_total() -> None:
    assert incident_has_more(page=1, page_size=5, total=12) is True
    assert incident_has_more(page=2, page_size=5, total=12) is True
    assert incident_has_more(page=3, page_size=5, total=12) is False
    assert incident_has_more(page=1, page_size=5, total=None) is False


@pytest.mark.asyncio
async def test_wire_mock_fixture_maps_description_and_keeps_gpt_verdict_none() -> None:
    async with _wire_adapter() as adapter:
        page = await adapter.list_objects([SourceObjectKind.INCIDENT], limit=5)
    assert len(page.items) == 1
    incident = page.items[0]
    assert isinstance(incident, SourceIncident)
    assert incident.gpt_verdict_label is None
    assert not hasattr(incident, "description") or "description" not in incident.model_dump()
    assert incident.normalized["description"] == "fixture incident for Sangfor wire mock"
    assert incident.title == "主机进程存在危险行为"
    assert incident.reference.source_object_id == "incident-wire-001"
    assert incident.reference.source_product == SOURCE_PRODUCT
    assert incident.reference.source_concurrency_token is None
    assert incident.level == "medium"
    assert incident.raw_payload["gptResult"] == 115
    assert incident.raw_payload["gptResultDescription"] == "主机失陷活动"
    assert incident.gpt_verdict_label is None
    ingested = source_to_ingestable(incident, source_type="incident")
    assert ingested.severity is Severity.MEDIUM
    assert ingested.description == "fixture incident for Sangfor wire mock"
    assert incident.normalized["vendor_entities"]["host"]["item"][0]["hostName"] == "PC-FIN-023"
    assert "vendor_proof" in incident.normalized


@pytest.mark.asyncio
async def test_list_posts_required_time_window_and_never_empty_body() -> None:
    captured: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(
            {
                "method": request.method,
                "path": request.url.path,
                "body": json.loads(request.content.decode("utf-8")) if request.content else {},
            }
        )
        return httpx.Response(
            200,
            json={
                "code": "Success",
                "message": "ok",
                "data": {"total": 1, "page": 1, "pageSize": 5, "item": []},
            },
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforSourceAdapter(_client(http), now_fn=lambda: _NOW)
    await adapter.list_objects([SourceObjectKind.INCIDENT], limit=5)
    await http.aclose()
    assert len(captured) == 1
    assert captured[0]["method"] == "POST"
    assert captured[0]["path"] == "/api/xdr/v1/incidents/list"
    body = captured[0]["body"]
    assert body != {}
    assert set(body) >= {
        "startTimestamp",
        "endTimestamp",
        "timeField",
        "page",
        "pageSize",
    }
    assert body["timeField"] == "endTime"
    assert body["page"] == 1
    assert body["pageSize"] == 5
    assert body["startTimestamp"] == _WINDOW_START
    assert body["endTimestamp"] == _WINDOW_END
    assert "uuIds" not in body
    assert "severities" not in body
    assert "dealStatus" not in body


@pytest.mark.asyncio
async def test_cursor_round_trip_keeps_time_window() -> None:
    captured: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        captured.append(body)
        page = int(body["page"])
        page_size = int(body["pageSize"])
        total = 12
        remaining = max(0, total - (page - 1) * page_size)
        count = min(page_size, remaining)
        items = [
            {"uuId": f"incident-p{page}-{idx}", "name": f"page-{page}", "dealStatus": 10}
            for idx in range(count)
        ]
        return httpx.Response(
            200,
            json={
                "code": "Success",
                "message": "ok",
                "data": {
                    "total": total,
                    "page": page,
                    "pageSize": page_size,
                    "item": items,
                },
            },
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforSourceAdapter(
        _client(http),
        now_fn=lambda: _NOW,
        fetch_incident_evidence=False,
    )
    first = await adapter.list_objects([SourceObjectKind.INCIDENT], limit=5)
    assert first.has_more is True
    assert first.next_cursor
    cursor = decode_incident_cursor(first.next_cursor)
    assert cursor["kind"] == "incidents"
    assert cursor["page"] == 2
    assert cursor["page_size"] == 5
    assert cursor["window_start"] == _WINDOW_START
    assert cursor["window_end"] == _WINDOW_END
    assert cursor["time_field"] == "endTime"

    second = await adapter.list_objects(
        [SourceObjectKind.INCIDENT],
        cursor=first.next_cursor,
        limit=5,
    )
    await http.aclose()
    assert len(captured) == 2
    assert captured[0]["startTimestamp"] == captured[1]["startTimestamp"] == _WINDOW_START
    assert captured[0]["endTimestamp"] == captured[1]["endTimestamp"] == _WINDOW_END
    assert captured[0]["timeField"] == captured[1]["timeField"] == "endTime"
    assert captured[1]["page"] == 2
    assert captured[1]["pageSize"] == 5
    assert second.has_more is True
    assert incident_has_more(page=2, page_size=5, total=12) is True


@pytest.mark.asyncio
async def test_invalid_parameter_does_not_emit_incidents() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"code": "InvalidParameter", "message": "bad", "data": None},
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    quality = InMemoryDataQualityRecorder()
    adapter = SangforSourceAdapter(_client(http), quality=quality, now_fn=lambda: _NOW)
    with pytest.raises(DependencyUnavailableError, match="business failure"):
        await adapter.list_objects([SourceObjectKind.INCIDENT], limit=5)
    await http.aclose()
    assert any(row["error_category"] == "business_failure" for row in quality.rows)


@pytest.mark.asyncio
async def test_non_incident_kind_does_not_call_vendor() -> None:
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500, json={"code": "Failed"})

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforSourceAdapter(_client(http), now_fn=lambda: _NOW)
    page = await adapter.list_objects([SourceObjectKind.CONNECTOR], limit=5)
    await http.aclose()
    assert called is False
    assert page.items == []
    assert page.has_more is False
    assert page.object_kind is SourceObjectKind.CONNECTOR


def test_scheduler_default_source_mode_is_still_mock_xdr() -> None:
    from app.adapters.factory import build_source_adapter
    from app.adapters.mock_xdr import MockXDRSourceAdapter

    scheduler_src = inspect.getsource(ingestion_scheduler)
    assert "build_source_adapter" in scheduler_src
    assert "wire_mock" not in scheduler_src
    deps_src = inspect.getsource(deps._get_adapter_registry)
    assert "build_disposition_adapter_registry" in deps_src
    assert "wire_mock" not in deps_src
    assert Settings.model_fields["source_mode"].default == "mock_xdr"
    adapter = build_source_adapter(Settings())
    assert isinstance(adapter, MockXDRSourceAdapter)
    assert not hasattr(SangforXdrClient, "list_incidents")
    assert not hasattr(SangforXdrClient, "list_alerts")
    assert not hasattr(SangforXdrClient, "list_assets")
    assert not hasattr(SangforXdrClient, "list_logs")
    assert not hasattr(SangforXdrClient, "get_proof")
    assert not hasattr(SangforXdrClient, "get_entities")


@pytest.mark.asyncio
async def test_wire_enrich_gets_proof_and_six_entities_without_account() -> None:
    captured: list[tuple[str, str, bytes]] = []

    async def _on_request(request: httpx.Request) -> None:
        captured.append((request.method, request.url.path, bytes(request.content or b"")))

    app = create_sangfor_wire_app()
    http = httpx.AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://sangfor-wire",
        event_hooks={"request": [_on_request]},
    )
    adapter = SangforSourceAdapter(
        _client(http),
        connector_id="conn-wire",
        now_fn=lambda: _NOW,
    )
    page = await adapter.list_objects([SourceObjectKind.INCIDENT], limit=5)
    evidence = await adapter.list_evidence_records()
    await http.aclose()

    assert len(page.items) == 1
    assert page.malformed_items == 0
    uu_id = "incident-wire-001"
    methods_paths = [(method, path) for method, path, _body in captured]
    assert ("POST", "/api/xdr/v1/incidents/list") in methods_paths
    assert ("GET", f"/api/xdr/v1/incidents/{uu_id}/proof") in methods_paths
    for kind in INCIDENT_ENTITY_KINDS:
        assert ("GET", f"/api/xdr/v1/incidents/{uu_id}/entities/{kind}") in methods_paths
    assert all(not path.endswith("/entities/account") for _method, path in methods_paths)
    assert all("/alerts/" not in path for _method, path in methods_paths)
    assert all(
        "/isolate" not in path or path.endswith("/isolate/list") for _method, path in methods_paths
    )
    gets = [item for item in captured if item[0] == "GET"]
    assert len(gets) == 7
    assert all(body == b"" for _method, _path, body in gets)

    incident = page.items[0]
    assert incident.gpt_verdict_label is None
    host_items = incident.normalized["vendor_entities"]["host"]["item"]
    assert host_items[0]["hostName"] == "PC-FIN-023"
    assert evidence is not None
    assert evidence.source_product == SOURCE_PRODUCT
    keys = set(evidence.records_by_source)
    assert "incident_proof" in keys
    assert {f"incident_entity_{kind}" for kind in INCIDENT_ENTITY_KINDS} <= keys
    assert keys.isdisjoint(MOCK_QUERY_EVIDENCE_KEYS)


@pytest.mark.asyncio
async def test_entity_http_failure_keeps_incident_and_records_quality() -> None:
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(f"{request.method} {request.url.path}")
        if request.method == "POST" and request.url.path.endswith("/incidents/list"):
            return httpx.Response(
                200,
                json={
                    "code": "Success",
                    "message": "ok",
                    "data": {
                        "total": 1,
                        "page": 1,
                        "pageSize": 5,
                        "item": [{"uuId": "incident-keep", "name": "keep-me", "dealStatus": 10}],
                    },
                },
            )
        if request.url.path.endswith("/proof"):
            return httpx.Response(
                200,
                json={"code": "InvalidParameter", "message": "bad", "data": None},
            )
        if request.url.path.endswith("/entities/host"):
            return httpx.Response(500, json={"code": "Failed", "message": "boom"})
        return httpx.Response(
            200,
            json={"code": "Success", "message": "ok", "data": {"item": []}},
        )

    quality = InMemoryDataQualityRecorder()
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforSourceAdapter(
        _client(http),
        quality=quality,
        now_fn=lambda: _NOW,
    )
    page = await adapter.list_objects([SourceObjectKind.INCIDENT], limit=5)
    evidence = await adapter.list_evidence_records()
    await http.aclose()

    assert len(page.items) == 1
    assert page.items[0].reference.source_object_id == "incident-keep"
    assert page.malformed_items == 0
    assert page.items[0].gpt_verdict_label is None
    assert "vendor_proof" not in page.items[0].normalized
    assert "host" not in page.items[0].normalized.get("vendor_entities", {})
    evidence_rows = [row for row in quality.rows if row["stage"] == "source_evidence"]
    assert any(row["error_category"] == "business_failure" for row in evidence_rows)
    assert "GET /api/xdr/v1/incidents/incident-keep/entities/dns" in captured
    assert "GET /api/xdr/v1/incidents/incident-keep/entities/process" in captured
    assert not any(path.endswith("/entities/account") for path in captured)
    assert evidence is not None
    assert "incident_entity_dns" in evidence.records_by_source
    assert "incident_proof" not in evidence.records_by_source
    assert set(evidence.records_by_source).isdisjoint(MOCK_QUERY_EVIDENCE_KEYS)


@pytest.mark.asyncio
async def test_alert_kind_does_not_fetch_proof_or_entities() -> None:
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(f"{request.method} {request.url.path}")
        if request.method == "POST" and request.url.path.endswith("/alerts/list"):
            return httpx.Response(
                200,
                json={
                    "code": "Success",
                    "message": "ok",
                    "data": {"total": 0, "page": 1, "pageSize": 5, "item": []},
                },
            )
        return httpx.Response(500, json={"code": "Failed"})

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforSourceAdapter(_client(http), now_fn=lambda: _NOW)
    page = await adapter.list_objects([SourceObjectKind.ALERT], limit=5)
    evidence = await adapter.list_evidence_records()
    await http.aclose()
    assert captured == ["POST /api/xdr/v1/alerts/list"]
    assert page.items == []
    assert evidence is None
    assert not any("/proof" in path for path in captured)
    assert not any("/entities/" in path for path in captured)


def test_incident_entity_path_rejects_account() -> None:
    with pytest.raises(ValueError, match="account"):
        incident_entity_path("account")
    assert "/account" not in incident_entity_path("host")


def test_source_alert_forbids_extra_fields_and_ignores_deal_status() -> None:
    assert SourceAlert.model_config.get("extra") == "forbid"
    mapped = alert_item_to_source(
        {
            "uuId": "alert-deal-mismatch",
            "name": "dealStatus must be ignored",
            "severity": 50,
            "alertDealStatus": 1,
            "dealStatus": 70,
            "hostIp": "10.20.30.23",
        },
        connector_id="c1",
        source_tenant_id="t1",
    )
    assert mapped is not None
    assert mapped.reference.source_disposition is SourceDisposition.PENDING
    assert mapped.reference.source_status_raw == "1"
    assert mapped.normalized["severity"] == "medium"
    assert mapped.normalized["title"] == "dealStatus must be ignored"
    assert mapped.source_ip == "10.20.30.23"
    assert mapped.raw_payload["severity"] == 50
    assert mapped.raw_payload["dealStatus"] == 70
    ingested = source_to_ingestable(mapped, source_type="alert")
    assert ingested.severity is Severity.MEDIUM


@pytest.mark.asyncio
async def test_wire_alerts_list_maps_deal_status_and_score_without_incident_evidence() -> None:
    captured: list[dict[str, Any]] = []

    async def _on_request(request: httpx.Request) -> None:
        captured.append(
            {
                "method": request.method,
                "path": request.url.path,
                "body": json.loads(request.content.decode("utf-8")) if request.content else {},
            }
        )

    app = create_sangfor_wire_app()
    http = httpx.AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://sangfor-wire",
        event_hooks={"request": [_on_request]},
    )
    adapter = SangforSourceAdapter(
        _client(http),
        connector_id="conn-wire",
        now_fn=lambda: _NOW,
    )
    page = await adapter.list_objects([SourceObjectKind.ALERT], limit=5)
    await http.aclose()

    assert len(captured) == 1
    assert captured[0]["method"] == "POST"
    assert captured[0]["path"] == "/api/xdr/v1/alerts/list"
    body = captured[0]["body"]
    assert body["timeField"] == "lastTime"
    assert body["page"] == 1
    assert body["pageSize"] == 5
    assert body["startTimestamp"] == _WINDOW_START
    assert body["endTimestamp"] == _WINDOW_END
    assert "dealStatus" not in body
    assert "alertDealStatus" not in body
    assert "uuIds" not in body
    assert all("/proof" not in row["path"] for row in captured)
    assert all("/entities/" not in row["path"] for row in captured)

    assert len(page.items) == 1
    alert = page.items[0]
    assert isinstance(alert, SourceAlert)
    assert alert.reference.source_object_id == "alert-wire-001"
    assert alert.reference.source_disposition is SourceDisposition.PENDING
    assert alert.reference.source_status_raw == "1"
    assert alert.normalized["title"] == "永恒之蓝"
    assert alert.normalized["severity"] == "medium"
    assert alert.source_ip == "10.20.30.23"
    assert alert.raw_payload["severity"] == 50
    assert alert.raw_payload["alertDealStatus"] == 1
    ingested = source_to_ingestable(alert, source_type="alert")
    assert ingested.severity is Severity.MEDIUM


@pytest.mark.asyncio
async def test_analysislog_uses_count_total_and_list_body_has_no_total() -> None:
    captured: list[dict[str, Any]] = []

    async def _on_request(request: httpx.Request) -> None:
        captured.append(
            {
                "method": request.method,
                "path": request.url.path,
                "body": json.loads(request.content.decode("utf-8")) if request.content else {},
            }
        )

    app = create_sangfor_wire_app()
    http = httpx.AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://sangfor-wire",
        event_hooks={"request": [_on_request]},
    )
    adapter = SangforSourceAdapter(_client(http), now_fn=lambda: _NOW)
    page = await adapter.list_objects([SourceObjectKind.LOG], limit=5)
    await http.aclose()

    paths = [row["path"] for row in captured]
    assert paths == [
        "/api/xdr/v1/analysislog/networksecurity/count",
        "/api/xdr/v1/analysislog/networksecurity/list",
    ]
    assert all(row["method"] == "POST" for row in captured)
    list_body = captured[1]["body"]
    assert "total" not in list_body
    assert list_body["page"] == 1
    assert list_body["pageSize"] == 5
    assert list_body["startTimestamp"] == _WINDOW_START
    assert list_body["endTimestamp"] == _WINDOW_END
    assert page.has_more is False
    assert len(page.items) == 1
    log = page.items[0]
    assert isinstance(log, SourceLog)
    assert log.reference.source_object_id == "network_security_log-wire-001"
    assert log.src_ip == "10.20.30.23"
    assert log.dst_ip == "203.0.113.88"
    assert log.device_source == "AF"
    assert log.raw_payload["recordTimestamp"] == 1647065958
    assert log.logged_at == datetime.fromtimestamp(1647065958, tz=UTC)
    fixture_path = (
        _REPO_ROOT / "contracts" / "vendor" / "sangfor_xdr" / "fixtures" / "analysislog_list.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert "total" not in fixture["data"]


@pytest.mark.asyncio
async def test_analysislog_count_5xx_still_lists_and_uses_page_length() -> None:
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(f"{request.method} {request.url.path}")
        if request.url.path.endswith("/analysislog/networksecurity/count"):
            return httpx.Response(500, json={"code": "Failed", "message": "boom"})
        if request.url.path.endswith("/analysislog/networksecurity/list"):
            body = json.loads(request.content.decode("utf-8"))
            assert "total" not in body
            items = [
                {
                    "uuId": f"network_security_log-full-{idx}",
                    "srcIp": "10.0.0.1",
                    "dstIp": "10.0.0.2",
                    "productType": "AF",
                    "recordTimestamp": _WINDOW_START,
                }
                for idx in range(int(body["pageSize"]))
            ]
            return httpx.Response(
                200,
                json={
                    "code": "Success",
                    "message": "ok",
                    "data": {"page": body["page"], "pageSize": body["pageSize"], "item": items},
                },
            )
        raise AssertionError(f"unexpected {request.method} {request.url.path}")

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforSourceAdapter(_client(http), now_fn=lambda: _NOW)
    page = await adapter.list_objects([SourceObjectKind.LOG], limit=5)
    await http.aclose()
    assert captured == [
        "POST /api/xdr/v1/analysislog/networksecurity/count",
        "POST /api/xdr/v1/analysislog/networksecurity/list",
    ]
    assert len(page.items) == 5
    assert page.has_more is True
    assert page.next_cursor
    cursor = decode_incident_cursor(page.next_cursor)
    assert cursor["kind"] == "analysislog"
    assert cursor["page"] == 2
    assert cursor["window_start"] == _WINDOW_START
    assert cursor["window_end"] == _WINDOW_END


@pytest.mark.asyncio
async def test_securitylog_injects_uuids_and_time_window() -> None:
    captured: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8")) if request.content else {}
        captured.append({"method": request.method, "path": request.url.path, "body": body})
        return httpx.Response(
            200,
            json={
                "code": "Success",
                "message": "ok",
                "data": {
                    "total": 1,
                    "page": 1,
                    "pageSize": 5,
                    "item": [
                        {
                            "uuId": "network_security_log-sec-001",
                            "srcIp": "10.1.1.1",
                            "dstIp": "10.2.2.2",
                            "productType": "EDR",
                            "recordTimestamp": _WINDOW_START,
                        }
                    ],
                },
            },
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforSourceAdapter(
        _client(http),
        now_fn=lambda: _NOW,
        security_log_uuids=("network_security_log-sec-001",),
    )
    page = await adapter.list_objects([SourceObjectKind.LOG], limit=5)
    await http.aclose()
    assert len(captured) == 1
    assert captured[0]["path"] == "/api/xdr/v1/securitylog/list"
    body = captured[0]["body"]
    assert body["uuIds"] == ["network_security_log-sec-001"]
    assert body["startTimestamp"] == _WINDOW_START
    assert body["endTimestamp"] == _WINDOW_END
    assert body["timeField"] == "recordTimestamp"
    assert len(page.items) == 1
    assert page.items[0].reference.source_object_id == "network_security_log-sec-001"


@pytest.mark.asyncio
async def test_wire_assets_invalid_parameter_is_empty_and_does_not_crash() -> None:
    captured: list[str] = []

    async def _on_request(request: httpx.Request) -> None:
        captured.append(f"{request.method} {request.url.path}")

    quality = InMemoryDataQualityRecorder()
    app = create_sangfor_wire_app()
    http = httpx.AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://sangfor-wire",
        event_hooks={"request": [_on_request]},
    )
    adapter = SangforSourceAdapter(
        _client(http),
        quality=quality,
        now_fn=lambda: _NOW,
    )
    with pytest.raises(DependencyUnavailableError, match="business failure"):
        await adapter.list_objects([SourceObjectKind.ASSET], limit=25)
    await http.aclose()
    assert captured == ["POST /api/xdr/v1/assets/list"]
    assert all(not row.startswith("DELETE") and not row.startswith("PUT") for row in captured)
    assert any(row["error_category"] == "business_failure" for row in quality.rows)


@pytest.mark.asyncio
async def test_assets_success_maps_source_asset() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/api/xdr/v1/assets/list"
        body = json.loads(request.content.decode("utf-8"))
        assert set(body) == {"page", "pageSize"}
        assert body["page"] == 1
        assert body["pageSize"] == 25
        return httpx.Response(
            200,
            json={
                "code": "Success",
                "message": "ok",
                "data": {
                    "total": 1,
                    "page": 1,
                    "pageSize": 25,
                    "item": [
                        {
                            "assetId": 111,
                            "name": "PC-FIN-023",
                            "ip": "10.20.30.23",
                            "hostName": "PC-FIN-023",
                            "magnitude": "core",
                        }
                    ],
                },
            },
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforSourceAdapter(_client(http), now_fn=lambda: _NOW)
    page = await adapter.list_objects([SourceObjectKind.ASSET], limit=25)
    await http.aclose()
    assert len(page.items) == 1
    asset = page.items[0]
    assert isinstance(asset, SourceAsset)
    assert asset.reference.source_object_id == "111"
    assert asset.numeric_asset_id == "111"
    assert asset.ip == "10.20.30.23"
    assert asset.hostname == "PC-FIN-023"
    assert asset.asset_name == "PC-FIN-023"
    assert asset.importance == "core"
    assert asset.raw_payload["assetId"] == 111
    assert page.has_more is False


@pytest.mark.asyncio
async def test_health_check_success_is_online() -> None:
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.url.path)
        return httpx.Response(
            200,
            json={"code": "Success", "message": "ok", "data": {"item": []}},
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforSourceAdapter(_client(http), now_fn=lambda: _NOW)
    try:
        assert await adapter.health_check() is ConnectorStatus.ONLINE
    finally:
        await http.aclose()
    assert captured == ["/api/xdr/v1/incidents/list"]


@pytest.mark.asyncio
async def test_health_check_business_failure_is_offline() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"code": "Fail", "message": "denied", "data": {}},
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforSourceAdapter(_client(http), now_fn=lambda: _NOW)
    try:
        assert await adapter.health_check() is ConnectorStatus.OFFLINE
    finally:
        await http.aclose()
