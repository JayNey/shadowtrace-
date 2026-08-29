"""Sangfor XDR SourceAdapter — incident/alert/asset/log lists (Layer 4c).

Wired when ``SOURCE_MODE=sangfor_xdr``. Agents must not import this module.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from app.adapters._util import sanitize_raw_result
from app.adapters.sangfor.client import SangforXdrClient
from app.adapters.source.base import (
    BaseSourceAdapter,
    DataQualityRecorder,
    InMemoryDataQualityRecorder,
    SourceEvidencePage,
    SourcePage,
)
from app.core.errors import DependencyUnavailableError
from app.models.enums import (
    CapabilityState,
    ConnectorCapability,
    ConnectorStatus,
    EventType,
    SourceDisposition,
    SourceObjectKind,
)
from app.models.source import SourceAlert, SourceAsset, SourceIncident, SourceLog, SourceReference

SOURCE_PRODUCT = "sangfor_xdr"
INCIDENTS_LIST_PATH = "/api/xdr/v1/incidents/list"
ALERTS_LIST_PATH = "/api/xdr/v1/alerts/list"
ASSETS_LIST_PATH = "/api/xdr/v1/assets/list"
ANALYSISLOG_LIST_PATH = "/api/xdr/v1/analysislog/networksecurity/list"
ANALYSISLOG_COUNT_PATH = "/api/xdr/v1/analysislog/networksecurity/count"
SECURITYLOG_LIST_PATH = "/api/xdr/v1/securitylog/list"
INCIDENT_PROOF_PATH = "/api/xdr/v1/incidents/:uuid/proof"
INCIDENT_ENTITY_KINDS: tuple[str, ...] = ("dns", "innerip", "ip", "host", "file", "process")
DEFAULT_TIME_FIELD = "endTime"
ALERT_TIME_FIELD = "lastTime"
SECURITYLOG_TIME_FIELD = "recordTimestamp"
DEFAULT_LOOKBACK = timedelta(hours=24)
PAGE_SIZE_MIN = 5
PAGE_SIZE_MAX = 200
ANALYSISLOG_PAGE_SIZE_DEFAULT = 5
ASSET_PAGE_SIZE_DEFAULT = 25
CURSOR_PREFIX = "s4."
MOCK_QUERY_EVIDENCE_KEYS = frozenset(
    {
        "edr_process",
        "account_login",
        "file_access",
        "dns",
        "network_flow",
        "asset_info",
        "threat_intel",
    }
)

_INCIDENT_KIND = "incidents"
_ALERT_KIND = "alerts"
_ASSET_KIND = "assets"
_ANALYSISLOG_KIND = "analysislog"
_SECURITYLOG_KIND = "securitylog"

_TMG_DISPOSITION: dict[int, SourceDisposition] = {
    0: SourceDisposition.PENDING,
    10: SourceDisposition.PROCESSING,
    20: SourceDisposition.COMPLETED,
    30: SourceDisposition.CONTAINED,
    40: SourceDisposition.COMPLETED,
    50: SourceDisposition.SUSPENDED,
    60: SourceDisposition.IGNORED,
    70: SourceDisposition.CONTAINED,
}

_SEVERITY_LEVEL: dict[int, str] = {
    -1: "information",
    0: "information",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}

_ALERT_DEAL_STATUS: dict[int, SourceDisposition] = {
    1: SourceDisposition.PENDING,
    2: SourceDisposition.PROCESSING,
    3: SourceDisposition.COMPLETED,
}


def clamp_page_size(limit: int) -> int:
    """Catalog incidents/list pageSize is 5–200."""
    if limit < PAGE_SIZE_MIN:
        return PAGE_SIZE_MIN
    if limit > PAGE_SIZE_MAX:
        return PAGE_SIZE_MAX
    return int(limit)


def encode_incident_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{CURSOR_PREFIX}{token}"


def decode_incident_cursor(cursor: str) -> dict[str, Any]:
    if not cursor.startswith(CURSOR_PREFIX):
        raise ValueError("unsupported sangfor incident cursor")
    token = cursor[len(CURSOR_PREFIX) :]
    padded = token + "=" * ((4 - len(token) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    if not isinstance(payload, dict):
        raise ValueError("sangfor incident cursor must be an object")
    return payload


def _unix_seconds(value: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return int(value.astimezone(UTC).timestamp())


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _as_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    seconds = _as_int(value)
    if seconds is not None and seconds > 10_000:
        return datetime.fromtimestamp(seconds, tz=UTC)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return None


def _event_type_hint(*values: Any) -> str | None:
    """Map vendor threat labels only when they already are kernel EventType values."""
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        lowered = text.lower().replace(" ", "_").replace("-", "_")
        try:
            return EventType(lowered).value
        except ValueError:
            continue
    return None


def incident_has_more(*, page: int, page_size: int, total: int | None) -> bool:
    """§2.1.2: page is 1-based; has_more iff page * pageSize < total."""
    if total is None:
        return False
    return page * page_size < total


def incident_entity_path(kind: str) -> str:
    """Catalog URI uses :uuid; entity kind is a path segment, never account."""
    if kind not in INCIDENT_ENTITY_KINDS:
        raise ValueError(f"unsupported incident entity kind: {kind}")
    return f"/api/xdr/v1/incidents/:uuid/entities/{kind}"


def evidence_record_key(kind: str) -> str:
    return f"incident_entity_{kind}"


def incident_item_to_source(
    item: dict[str, Any],
    *,
    connector_id: str,
    source_tenant_id: str,
) -> SourceIncident | None:
    """Map one open-list incidents/list item. gpt_verdict_label stays None."""
    object_id = item.get("uuId")
    if object_id is None or str(object_id).strip() == "":
        return None
    object_id = str(object_id)

    deal_status = _as_int(item.get("dealStatus"))
    disposition = (
        _TMG_DISPOSITION.get(deal_status, SourceDisposition.UNKNOWN)
        if deal_status is not None
        else SourceDisposition.UNKNOWN
    )
    severity_raw = _as_int(item.get("incidentSeverity"))
    if item.get("incidentSeverity") is not None and severity_raw is None:
        try:
            severity_raw = int(item["incidentSeverity"])
        except (TypeError, ValueError):
            severity_raw = None
    level = _SEVERITY_LEVEL.get(severity_raw) if severity_raw is not None else None

    description = item.get("description")
    normalized: dict[str, Any] = {}
    if description is not None and str(description).strip():
        normalized["description"] = str(description)
    if item.get("name") is not None:
        normalized["title"] = str(item.get("name"))
    if item.get("hostIp") is not None:
        normalized["host_ip"] = item.get("hostIp")
    if item.get("hostAssetId") is not None:
        normalized["host_asset_id"] = item.get("hostAssetId")
    if deal_status is not None:
        normalized["deal_status"] = deal_status
    if item.get("incidentSeverity") is not None:
        normalized["incident_severity"] = item.get("incidentSeverity")
    event_type = _event_type_hint(
        item.get("threatDefineName"),
        item.get("incidentThreatClass"),
        item.get("incidentThreatType"),
    )
    if event_type is not None:
        normalized["event_type"] = event_type

    occurred = _as_datetime(item.get("endTime")) or _as_datetime(item.get("startTime"))
    raw_payload = sanitize_raw_result(dict(item))
    if not isinstance(raw_payload, dict):
        raw_payload = {"value": raw_payload}

    related_alert_refs: list[SourceReference] = []
    alert_ids = item.get("alertIds")
    if isinstance(alert_ids, list):
        for alert_id in alert_ids:
            if alert_id is None or str(alert_id).strip() == "":
                continue
            related_alert_refs.append(
                SourceReference(
                    source_kind=SourceObjectKind.ALERT,
                    source_product=SOURCE_PRODUCT,
                    source_tenant_id=source_tenant_id,
                    connector_id=connector_id,
                    source_object_id=str(alert_id),
                    source_concurrency_token=None,
                )
            )

    title = str(item.get("name")).strip() if item.get("name") is not None else None
    return SourceIncident(
        reference=SourceReference(
            source_kind=SourceObjectKind.INCIDENT,
            source_product=SOURCE_PRODUCT,
            source_tenant_id=source_tenant_id,
            connector_id=connector_id,
            source_object_id=object_id,
            source_status_raw=None if deal_status is None else str(deal_status),
            source_disposition=disposition,
            source_concurrency_token=None,
            source_updated_at=occurred,
        ),
        raw_payload=raw_payload,
        normalized=normalized,
        title=title or None,
        level=level,
        gpt_verdict_label=None,
        related_alert_refs=related_alert_refs,
    )


def alert_score_to_level(score: int | None) -> str | None:
    """Map vendor 0–100 severity score to kernel four-tier labels.

    Intervals are (low, high]. Score 0 and values outside 1–100 stay unset so
    ingest falls back to Severity.LOW. The original score belongs in raw_payload.
    """
    if score is None:
        return None
    if 0 < score <= 30:
        return "low"
    if 30 < score <= 50:
        return "medium"
    if 50 < score <= 70:
        return "high"
    if 70 < score <= 100:
        return "critical"
    return None


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _sanitized_payload(item: dict[str, Any]) -> dict[str, Any]:
    raw_payload = sanitize_raw_result(dict(item))
    return raw_payload if isinstance(raw_payload, dict) else {"value": raw_payload}


def alert_item_to_source(
    item: dict[str, Any],
    *,
    connector_id: str,
    source_tenant_id: str,
) -> SourceAlert | None:
    """Map one alerts/list item. Read alertDealStatus only — never dealStatus."""
    object_id = _as_text(item.get("uuId"))
    if object_id is None:
        return None
    deal_status = _as_int(item.get("alertDealStatus"))
    disposition = (
        _ALERT_DEAL_STATUS.get(deal_status, SourceDisposition.UNKNOWN)
        if deal_status is not None
        else SourceDisposition.UNKNOWN
    )
    score = _as_int(item.get("severity"))
    if item.get("severity") is not None and score is None:
        try:
            score = int(item["severity"])
        except (TypeError, ValueError):
            score = None
    level = alert_score_to_level(score)
    normalized: dict[str, Any] = {}
    name = _as_text(item.get("name"))
    if name is not None:
        normalized["title"] = name
    if level is not None:
        normalized["severity"] = level
    host_ip = _as_text(item.get("hostIp"))
    occurred = _as_datetime(item.get("lastTime")) or _as_datetime(item.get("firstTime"))
    return SourceAlert(
        reference=SourceReference(
            source_kind=SourceObjectKind.ALERT,
            source_product=SOURCE_PRODUCT,
            source_tenant_id=source_tenant_id,
            connector_id=connector_id,
            source_object_id=object_id,
            source_status_raw=None if deal_status is None else str(deal_status),
            source_disposition=disposition,
            source_concurrency_token=None,
            source_updated_at=occurred,
        ),
        raw_payload=_sanitized_payload(item),
        normalized=normalized,
        source_ip=host_ip,
    )


def log_item_to_source(
    item: dict[str, Any],
    *,
    connector_id: str,
    source_tenant_id: str,
) -> SourceLog | None:
    object_id = _as_text(item.get("uuId"))
    if object_id is None:
        return None
    logged_at = _as_datetime(item.get("recordTimestamp"))
    return SourceLog(
        reference=SourceReference(
            source_kind=SourceObjectKind.LOG,
            source_product=SOURCE_PRODUCT,
            source_tenant_id=source_tenant_id,
            connector_id=connector_id,
            source_object_id=object_id,
            source_concurrency_token=None,
            source_updated_at=logged_at,
        ),
        raw_payload=_sanitized_payload(item),
        device_source=_as_text(item.get("productType")),
        logged_at=logged_at,
        src_ip=_as_text(item.get("srcIp")),
        dst_ip=_as_text(item.get("dstIp")),
        src_port=_as_int(item.get("srcPort")),
        dst_port=_as_int(item.get("dstPort")),
    )


def asset_item_to_source(
    item: dict[str, Any],
    *,
    connector_id: str,
    source_tenant_id: str,
) -> SourceAsset | None:
    object_id = _as_text(item.get("assetId") or item.get("uuId") or item.get("id"))
    if object_id is None:
        return None
    return SourceAsset(
        reference=SourceReference(
            source_kind=SourceObjectKind.ASSET,
            source_product=SOURCE_PRODUCT,
            source_tenant_id=source_tenant_id,
            connector_id=connector_id,
            source_object_id=object_id,
            source_concurrency_token=None,
            source_updated_at=_as_datetime(item.get("updateTime") or item.get("update_time")),
        ),
        raw_payload=_sanitized_payload(item),
        numeric_asset_id=object_id,
        ip=_as_text(item.get("ip") or item.get("hostIp")),
        hostname=_as_text(item.get("hostname") or item.get("hostName")),
        asset_name=_as_text(item.get("name") or item.get("assetName")),
        asset_group=_as_text(item.get("branchName") or item.get("assetGroup")),
        owner=_as_text(item.get("owner") or item.get("username")),
        business_system=_as_text(item.get("businessName") or item.get("businessSystem")),
        importance=_as_text(item.get("magnitude")),
        agent_status=_as_text(item.get("connectStatus")),
        first_seen_at=_as_datetime(item.get("firstTime") or item.get("first_time")),
        last_seen_at=_as_datetime(item.get("updateTime") or item.get("update_time")),
    )


def clamp_asset_page_size(limit: int) -> int:
    """assets/list pageSize is not the incident 5–200 enum; catalog example is 25."""
    if limit < 1:
        return ASSET_PAGE_SIZE_DEFAULT
    if limit > PAGE_SIZE_MAX:
        return PAGE_SIZE_MAX
    return int(limit)


class SangforSourceAdapter(BaseSourceAdapter):
    """Read-only Sangfor lists: incidents, alerts, analysislog/securitylog, assets."""

    name = SOURCE_PRODUCT

    def __init__(
        self,
        client: SangforXdrClient,
        *,
        connector_id: str = "sangfor-xdr",
        source_tenant_id: str = "default",
        lookback: timedelta = DEFAULT_LOOKBACK,
        time_field: str = DEFAULT_TIME_FIELD,
        quality: DataQualityRecorder | None = None,
        now_fn: Callable[[], datetime] | None = None,
        fetch_incident_evidence: bool = True,
        security_log_uuids: tuple[str, ...] = (),
        alert_uuids: tuple[str, ...] = (),
    ) -> None:
        self._client = client
        self._connector_id = connector_id
        self._source_tenant_id = source_tenant_id
        self._lookback = lookback
        self._time_field = time_field
        self._quality = quality or InMemoryDataQualityRecorder()
        self._now_fn = now_fn
        self._fetch_incident_evidence = fetch_incident_evidence
        self._security_log_uuids = tuple(item for item in security_log_uuids if str(item).strip())
        self._alert_uuids = tuple(item for item in alert_uuids if str(item).strip())
        self._evidence_buffer: dict[str, list[dict[str, Any]]] = {}

    def capabilities(self) -> dict[ConnectorCapability, CapabilityState]:
        return {
            ConnectorCapability.LOG_INGESTION: CapabilityState.SUPPORTED,
            ConnectorCapability.QUERY: CapabilityState.UNSUPPORTED,
            ConnectorCapability.EVENT_DISPOSITION: CapabilityState.UNSUPPORTED,
            ConnectorCapability.ENTITY_RESPONSE: CapabilityState.UNSUPPORTED,
        }

    def _now(self) -> datetime:
        current = self._now_fn() if self._now_fn is not None else datetime.now(UTC)
        if current.tzinfo is None:
            return current.replace(tzinfo=UTC)
        return current.astimezone(UTC)

    def _window(
        self,
        *,
        cursor: str | None,
        updated_after: datetime | None,
        limit: int,
        kind: str,
        time_field: str,
        page_size: int | None = None,
        with_time: bool = True,
    ) -> dict[str, Any]:
        resolved_size = clamp_page_size(limit) if page_size is None else int(page_size)
        if cursor:
            payload = decode_incident_cursor(cursor)
            if payload.get("kind") != kind:
                raise ValueError("cursor kind mismatch")
            decoded: dict[str, Any] = {
                "kind": kind,
                "page": int(payload["page"]),
                "page_size": int(payload.get("page_size") or resolved_size),
            }
            if with_time:
                decoded["window_start"] = int(payload["window_start"])
                decoded["window_end"] = int(payload["window_end"])
                decoded["time_field"] = str(payload.get("time_field") or time_field)
            return decoded
        now = self._now()
        window: dict[str, Any] = {
            "kind": kind,
            "page": 1,
            "page_size": resolved_size,
        }
        if with_time:
            window["window_end"] = _unix_seconds(now)
            if updated_after is not None:
                window["window_start"] = _unix_seconds(updated_after)
            else:
                window["window_start"] = _unix_seconds(now - self._lookback)
            window["time_field"] = time_field
        return window

    def _list_body(self, window: dict[str, Any]) -> dict[str, Any]:
        return {
            "startTimestamp": window["window_start"],
            "endTimestamp": window["window_end"],
            "timeField": window["time_field"],
            "page": window["page"],
            "pageSize": window["page_size"],
        }

    def _empty_page(
        self,
        kind: SourceObjectKind,
        scope: str,
        server_time: datetime,
        *,
        malformed: int = 0,
        schema_version: str | None = "1",
    ) -> SourcePage:
        return SourcePage(
            object_kind=kind,
            connector_id=scope,
            server_time=server_time,
            schema_version="1" if schema_version is None else schema_version,
            malformed_items=malformed,
        )

    def _encode_next_cursor(self, window: dict[str, Any], *, with_time: bool) -> str:
        payload: dict[str, Any] = {
            "kind": window["kind"],
            "page": int(window["page"]) + 1,
            "page_size": int(window["page_size"]),
        }
        if with_time:
            payload["window_start"] = window["window_start"]
            payload["window_end"] = window["window_end"]
            payload["time_field"] = window["time_field"]
        return encode_incident_cursor(payload)

    async def _post_json(
        self,
        path: str,
        body: dict[str, Any],
    ) -> Any:
        return await self._client.request(
            "POST",
            path,
            json_body=body,
            headers={"content-type": "application/json"},
        )

    def _append_evidence(self, key: str, record: dict[str, Any]) -> None:
        if key in MOCK_QUERY_EVIDENCE_KEYS:
            return
        self._evidence_buffer.setdefault(key, []).append(record)

    async def _get_incident_payload(
        self,
        path: str,
        uu_id: str,
        *,
        evidence_kind: str,
    ) -> dict[str, Any] | None:
        try:
            result = await self._client.request(
                "GET",
                path,
                path_params={"uuid": uu_id},
            )
        except Exception as exc:  # noqa: BLE001 — evidence must not crash poll
            self._quality.record(
                stage="source_evidence",
                error_category="transport_failure",
                detail={
                    "evidence_kind": evidence_kind,
                    "uuId": uu_id,
                    "path": path,
                    "type": type(exc).__name__,
                },
            )
            return None
        http_ok = 200 <= result.http_status < 300
        if not http_ok or result.business_code != "Success":
            self._quality.record(
                stage="source_evidence",
                error_category="business_failure",
                detail={
                    "evidence_kind": evidence_kind,
                    "uuId": uu_id,
                    "path": path,
                    "http_status": result.http_status,
                    "business_code": result.business_code,
                },
            )
            return None
        if result.data is None:
            self._quality.record(
                stage="source_evidence",
                error_category="malformed_payload",
                detail={
                    "evidence_kind": evidence_kind,
                    "uuId": uu_id,
                    "path": path,
                    "reason": "missing_data",
                },
            )
            return None
        raw = result.data if isinstance(result.data, dict) else {"value": result.data}
        sanitized = sanitize_raw_result(raw)
        return sanitized if isinstance(sanitized, dict) else {"value": sanitized}

    async def _enrich_incident(self, incident: SourceIncident) -> SourceIncident:
        uu_id = incident.reference.source_object_id
        normalized = dict(incident.normalized)
        entities: dict[str, Any] = {}
        proof = await self._get_incident_payload(
            INCIDENT_PROOF_PATH,
            uu_id,
            evidence_kind="proof",
        )
        if proof is not None:
            normalized["vendor_proof"] = proof
            self._append_evidence(
                "incident_proof",
                {"incident_uuId": uu_id, "data": proof},
            )
        for kind in INCIDENT_ENTITY_KINDS:
            payload = await self._get_incident_payload(
                incident_entity_path(kind),
                uu_id,
                evidence_kind=f"entities/{kind}",
            )
            if payload is not None:
                entities[kind] = payload
                self._append_evidence(
                    evidence_record_key(kind),
                    {"incident_uuId": uu_id, "entity_kind": kind, "data": payload},
                )
        if entities:
            normalized["vendor_entities"] = entities
        return incident.model_copy(update={"normalized": normalized})

    def _record_list_failure(
        self,
        *,
        path: str,
        error_category: str,
        detail: dict[str, Any],
    ) -> None:
        payload = {"path": path, **detail}
        self._quality.record(stage="source_list", error_category=error_category, detail=payload)

    def _map_vendor_items(
        self,
        raw_items: list[Any],
        mapper: Callable[..., Any],
        *,
        scope: str,
    ) -> tuple[list[Any], int]:
        items: list[Any] = []
        malformed = 0
        for raw_item in raw_items:
            if not isinstance(raw_item, dict):
                malformed += 1
                self._quality.record(
                    stage="source_list",
                    error_category="malformed_payload",
                    detail={"reason": "item_not_object"},
                )
                continue
            mapped = mapper(
                raw_item,
                connector_id=scope,
                source_tenant_id=self._source_tenant_id,
            )
            if mapped is None:
                malformed += 1
                self._quality.record(
                    stage="source_list",
                    error_category="malformed_payload",
                    detail={"reason": "missing_uuId"},
                )
                continue
            items.append(mapped)
        return items, malformed

    def _page_from_total(
        self,
        *,
        kind: SourceObjectKind,
        scope: str,
        server_time: datetime,
        items: list[Any],
        malformed: int,
        window: dict[str, Any],
        total: int | None,
        with_time: bool,
    ) -> SourcePage:
        page = int(window["page"])
        page_size = int(window["page_size"])
        has_more = incident_has_more(page=page, page_size=page_size, total=total)
        next_cursor = self._encode_next_cursor(window, with_time=with_time) if has_more else None
        return SourcePage(
            items=items,
            object_kind=kind,
            connector_id=scope,
            next_cursor=next_cursor,
            has_more=has_more,
            server_time=server_time,
            schema_version="1",
            malformed_items=malformed,
        )

    async def _list_success_data(
        self,
        path: str,
        body: dict[str, Any],
        *,
        kind: SourceObjectKind,
        scope: str,
        server_time: datetime,
    ) -> tuple[dict[str, Any] | None, SourcePage]:
        try:
            result = await self._post_json(path, body)
        except Exception as exc:  # noqa: BLE001 — poll must not crash on vendor IO
            self._record_list_failure(
                path=path,
                error_category="transport_failure",
                detail={"type": type(exc).__name__},
            )
            raise DependencyUnavailableError(
                "sangfor source list transport failure",
                details={"path": path, "type": type(exc).__name__},
            ) from exc
        http_ok = 200 <= result.http_status < 300
        if not http_ok or result.business_code != "Success":
            self._record_list_failure(
                path=path,
                error_category="business_failure",
                detail={
                    "http_status": result.http_status,
                    "business_code": result.business_code,
                },
            )
            raise DependencyUnavailableError(
                "sangfor source list business failure",
                details={
                    "path": path,
                    "http_status": result.http_status,
                    "business_code": result.business_code,
                },
            )
        data = result.data if isinstance(result.data, dict) else None
        if data is None or not isinstance(data.get("item"), list):
            self._record_list_failure(
                path=path,
                error_category="malformed_payload",
                detail={"reason": "missing_item_array"},
            )
            return None, self._empty_page(kind, scope, server_time, malformed=1)
        return data, self._empty_page(kind, scope, server_time)

    async def _analysislog_count_total(self, window: dict[str, Any]) -> int | None:
        body = {
            "startTimestamp": window["window_start"],
            "endTimestamp": window["window_end"],
        }
        try:
            result = await self._post_json(ANALYSISLOG_COUNT_PATH, body)
        except Exception as exc:  # noqa: BLE001 — count failure falls back to page length
            self._record_list_failure(
                path=ANALYSISLOG_COUNT_PATH,
                error_category="transport_failure",
                detail={"type": type(exc).__name__},
            )
            return None
        http_ok = 200 <= result.http_status < 300
        if not http_ok or result.business_code != "Success":
            self._record_list_failure(
                path=ANALYSISLOG_COUNT_PATH,
                error_category="business_failure",
                detail={
                    "http_status": result.http_status,
                    "business_code": result.business_code,
                },
            )
            return None
        data = result.data if isinstance(result.data, dict) else None
        if data is None:
            return None
        return _as_int(data.get("total"))

    async def _list_incidents(
        self,
        *,
        scope: str,
        server_time: datetime,
        cursor: str | None,
        updated_after: datetime | None,
        limit: int,
    ) -> SourcePage:
        if cursor is None:
            self._evidence_buffer = {}
        try:
            window = self._window(
                cursor=cursor,
                updated_after=updated_after,
                limit=limit,
                kind=_INCIDENT_KIND,
                time_field=self._time_field,
            )
        except (KeyError, TypeError, ValueError) as exc:
            self._quality.record(
                stage="source_list",
                error_category="malformed_cursor",
                detail={"reason": str(exc)},
            )
            return self._empty_page(SourceObjectKind.INCIDENT, scope, server_time, malformed=1)

        body = self._list_body(window)
        try:
            result = await self._client.request(
                "POST",
                INCIDENTS_LIST_PATH,
                json_body=body,
                headers={"content-type": "application/json"},
            )
        except Exception as exc:  # noqa: BLE001 — poll must not crash on vendor IO
            self._quality.record(
                stage="source_list",
                error_category="transport_failure",
                detail={"type": type(exc).__name__, "path": INCIDENTS_LIST_PATH},
            )
            raise DependencyUnavailableError(
                "sangfor incident list transport failure",
                details={"path": INCIDENTS_LIST_PATH, "type": type(exc).__name__},
            ) from exc
        http_ok = 200 <= result.http_status < 300
        if not http_ok or result.business_code != "Success":
            self._quality.record(
                stage="source_list",
                error_category="business_failure",
                detail={
                    "http_status": result.http_status,
                    "business_code": result.business_code,
                    "path": INCIDENTS_LIST_PATH,
                },
            )
            raise DependencyUnavailableError(
                "sangfor incident list business failure",
                details={
                    "http_status": result.http_status,
                    "business_code": result.business_code,
                    "path": INCIDENTS_LIST_PATH,
                },
            )
        data = result.data if isinstance(result.data, dict) else None
        if data is None or not isinstance(data.get("item"), list):
            self._quality.record(
                stage="source_list",
                error_category="malformed_payload",
                detail={"reason": "missing_item_array"},
            )
            return self._empty_page(SourceObjectKind.INCIDENT, scope, server_time, malformed=1)

        items: list[SourceIncident] = []
        malformed = 0
        for raw_item in data["item"]:
            if not isinstance(raw_item, dict):
                malformed += 1
                self._quality.record(
                    stage="source_list",
                    error_category="malformed_payload",
                    detail={"reason": "item_not_object"},
                )
                continue
            mapped = incident_item_to_source(
                raw_item,
                connector_id=scope,
                source_tenant_id=self._source_tenant_id,
            )
            if mapped is None:
                malformed += 1
                self._quality.record(
                    stage="source_list",
                    error_category="malformed_payload",
                    detail={"reason": "missing_uuId"},
                )
                continue
            if self._fetch_incident_evidence:
                mapped = await self._enrich_incident(mapped)
            items.append(mapped)

        return self._page_from_total(
            kind=SourceObjectKind.INCIDENT,
            scope=scope,
            server_time=server_time,
            items=items,
            malformed=malformed,
            window=window,
            total=_as_int(data.get("total")),
            with_time=True,
        )

    async def _list_alerts(
        self,
        *,
        scope: str,
        server_time: datetime,
        cursor: str | None,
        updated_after: datetime | None,
        limit: int,
    ) -> SourcePage:
        try:
            window = self._window(
                cursor=cursor,
                updated_after=updated_after,
                limit=limit,
                kind=_ALERT_KIND,
                time_field=ALERT_TIME_FIELD,
            )
        except (KeyError, TypeError, ValueError) as exc:
            self._quality.record(
                stage="source_list",
                error_category="malformed_cursor",
                detail={"reason": str(exc)},
            )
            return self._empty_page(SourceObjectKind.ALERT, scope, server_time, malformed=1)
        body = self._list_body(window)
        if self._alert_uuids:
            body["uuIds"] = list(self._alert_uuids)
        data, failed = await self._list_success_data(
            ALERTS_LIST_PATH,
            body,
            kind=SourceObjectKind.ALERT,
            scope=scope,
            server_time=server_time,
        )
        if data is None:
            return failed
        items, malformed = self._map_vendor_items(
            data["item"],
            alert_item_to_source,
            scope=scope,
        )
        return self._page_from_total(
            kind=SourceObjectKind.ALERT,
            scope=scope,
            server_time=server_time,
            items=items,
            malformed=malformed,
            window=window,
            total=_as_int(data.get("total")),
            with_time=True,
        )

    async def _list_analysis_logs(
        self,
        *,
        scope: str,
        server_time: datetime,
        cursor: str | None,
        updated_after: datetime | None,
        limit: int,
    ) -> SourcePage:
        try:
            window = self._window(
                cursor=cursor,
                updated_after=updated_after,
                limit=limit,
                kind=_ANALYSISLOG_KIND,
                time_field=SECURITYLOG_TIME_FIELD,
                page_size=ANALYSISLOG_PAGE_SIZE_DEFAULT,
            )
        except (KeyError, TypeError, ValueError) as exc:
            self._quality.record(
                stage="source_list",
                error_category="malformed_cursor",
                detail={"reason": str(exc)},
            )
            return self._empty_page(SourceObjectKind.LOG, scope, server_time, malformed=1)
        count_total = await self._analysislog_count_total(window)
        list_body = {
            "startTimestamp": window["window_start"],
            "endTimestamp": window["window_end"],
            "page": window["page"],
            "pageSize": window["page_size"],
        }
        data, failed = await self._list_success_data(
            ANALYSISLOG_LIST_PATH,
            list_body,
            kind=SourceObjectKind.LOG,
            scope=scope,
            server_time=server_time,
        )
        if data is None:
            return failed
        raw_items = data["item"]
        items, malformed = self._map_vendor_items(
            raw_items,
            log_item_to_source,
            scope=scope,
        )
        page = int(window["page"])
        resolved_size = int(window["page_size"])
        if count_total is not None:
            has_more = incident_has_more(page=page, page_size=resolved_size, total=count_total)
        else:
            has_more = len(raw_items) == resolved_size
        next_cursor = self._encode_next_cursor(window, with_time=True) if has_more else None
        return SourcePage(
            items=items,
            object_kind=SourceObjectKind.LOG,
            connector_id=scope,
            next_cursor=next_cursor,
            has_more=has_more,
            server_time=server_time,
            schema_version="1",
            malformed_items=malformed,
        )

    async def _list_security_logs(
        self,
        *,
        scope: str,
        server_time: datetime,
        cursor: str | None,
        updated_after: datetime | None,
        limit: int,
    ) -> SourcePage:
        try:
            window = self._window(
                cursor=cursor,
                updated_after=updated_after,
                limit=limit,
                kind=_SECURITYLOG_KIND,
                time_field=SECURITYLOG_TIME_FIELD,
            )
        except (KeyError, TypeError, ValueError) as exc:
            self._quality.record(
                stage="source_list",
                error_category="malformed_cursor",
                detail={"reason": str(exc)},
            )
            return self._empty_page(SourceObjectKind.LOG, scope, server_time, malformed=1)
        body = self._list_body(window)
        body["uuIds"] = list(self._security_log_uuids)
        data, failed = await self._list_success_data(
            SECURITYLOG_LIST_PATH,
            body,
            kind=SourceObjectKind.LOG,
            scope=scope,
            server_time=server_time,
        )
        if data is None:
            return failed
        items, malformed = self._map_vendor_items(
            data["item"],
            log_item_to_source,
            scope=scope,
        )
        return self._page_from_total(
            kind=SourceObjectKind.LOG,
            scope=scope,
            server_time=server_time,
            items=items,
            malformed=malformed,
            window=window,
            total=_as_int(data.get("total")),
            with_time=True,
        )

    async def _list_assets(
        self,
        *,
        scope: str,
        server_time: datetime,
        cursor: str | None,
        limit: int,
    ) -> SourcePage:
        try:
            window = self._window(
                cursor=cursor,
                updated_after=None,
                limit=limit,
                kind=_ASSET_KIND,
                time_field=DEFAULT_TIME_FIELD,
                page_size=clamp_asset_page_size(limit),
                with_time=False,
            )
        except (KeyError, TypeError, ValueError) as exc:
            self._quality.record(
                stage="source_list",
                error_category="malformed_cursor",
                detail={"reason": str(exc)},
            )
            return self._empty_page(SourceObjectKind.ASSET, scope, server_time, malformed=1)
        body = {
            "page": window["page"],
            "pageSize": window["page_size"],
        }
        data, failed = await self._list_success_data(
            ASSETS_LIST_PATH,
            body,
            kind=SourceObjectKind.ASSET,
            scope=scope,
            server_time=server_time,
        )
        if data is None:
            return failed
        items, malformed = self._map_vendor_items(
            data["item"],
            asset_item_to_source,
            scope=scope,
        )
        return self._page_from_total(
            kind=SourceObjectKind.ASSET,
            scope=scope,
            server_time=server_time,
            items=items,
            malformed=malformed,
            window=window,
            total=_as_int(data.get("total")),
            with_time=False,
        )

    async def list_objects(
        self,
        object_types: Sequence[SourceObjectKind | str],
        *,
        connector_id: str | None = None,
        cursor: str | None = None,
        updated_after: datetime | None = None,
        limit: int = 100,
    ) -> SourcePage:
        if len(object_types) != 1:
            raise ValueError("SourceAdapter.list_objects requires exactly one object kind")
        raw_kind = object_types[0]
        kind = (
            raw_kind if isinstance(raw_kind, SourceObjectKind) else SourceObjectKind(str(raw_kind))
        )
        scope = connector_id or self._connector_id
        server_time = self._now()
        if kind is SourceObjectKind.INCIDENT:
            return await self._list_incidents(
                scope=scope,
                server_time=server_time,
                cursor=cursor,
                updated_after=updated_after,
                limit=limit,
            )
        if kind is SourceObjectKind.ALERT:
            return await self._list_alerts(
                scope=scope,
                server_time=server_time,
                cursor=cursor,
                updated_after=updated_after,
                limit=limit,
            )
        if kind is SourceObjectKind.LOG:
            if self._security_log_uuids:
                return await self._list_security_logs(
                    scope=scope,
                    server_time=server_time,
                    cursor=cursor,
                    updated_after=updated_after,
                    limit=limit,
                )
            return await self._list_analysis_logs(
                scope=scope,
                server_time=server_time,
                cursor=cursor,
                updated_after=updated_after,
                limit=limit,
            )
        if kind is SourceObjectKind.ASSET:
            return await self._list_assets(
                scope=scope,
                server_time=server_time,
                cursor=cursor,
                limit=limit,
            )
        return self._empty_page(kind, scope, server_time)

    async def list_evidence_records(
        self,
        *,
        updated_after: datetime | None = None,
    ) -> SourceEvidencePage | None:
        del updated_after
        try:
            if not any(self._evidence_buffer.values()):
                return None
            copied = {
                key: [dict(record) for record in rows]
                for key, rows in self._evidence_buffer.items()
                if key not in MOCK_QUERY_EVIDENCE_KEYS and rows
            }
            if not copied:
                return None
            return SourceEvidencePage(
                records_by_source=copied,
                source_product=SOURCE_PRODUCT,
                source_tenant_id=self._source_tenant_id,
                connector_id=self._connector_id,
                schema_version="1",
            )
        except Exception:  # noqa: BLE001 — evidence page must not crash ingest
            return None

    async def health_check(self) -> ConnectorStatus:
        """Probe incidents list — the only vendor URI this layer already uses."""
        try:
            window = self._window(
                cursor=None,
                updated_after=None,
                limit=1,
                kind=_INCIDENT_KIND,
                time_field=self._time_field,
                page_size=1,
            )
            result = await self._client.request(
                "POST",
                INCIDENTS_LIST_PATH,
                json_body=self._list_body(window),
                headers={"content-type": "application/json"},
            )
        except Exception:  # noqa: BLE001 — health must never raise to callers
            return ConnectorStatus.OFFLINE
        http_ok = 200 <= result.http_status < 300
        if not http_ok or result.business_code != "Success":
            return ConnectorStatus.OFFLINE
        return ConnectorStatus.ONLINE
