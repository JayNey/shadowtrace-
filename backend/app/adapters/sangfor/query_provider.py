"""Layer 8b live Sangfor Evidence query provider.

Only registered for KIND=sangfor_xdr + TOOL_MODE=live + ALLOW_LIVE_SIDE_EFFECTS.
Never posts responses/ write URIs. Semantic mismatches are degraded or unavailable.
EvidenceAgent must not import this module.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.adapters.sangfor.client import SangforHttpResult, SangforXdrClient
from app.adapters.sangfor.source import (
    ANALYSISLOG_LIST_PATH,
    ASSET_PAGE_SIZE_DEFAULT,
    ASSETS_LIST_PATH,
    INCIDENT_PROOF_PATH,
    SOURCE_PRODUCT,
    clamp_asset_page_size,
    incident_entity_path,
)
from app.core.errors import GuardrailViolationError
from app.models.enums import CapabilityState, SourceObjectKind
from app.models.ids import new_call_id
from app.models.source import SourceReference
from app.models.tool_meta import (
    CapabilityManifest,
    ExecutionChannel,
    ToolResult,
    ToolResultStatus,
)
from app.services.evidence_projection import (
    CoverageState,
    DataFreshness,
    EvidenceCoverage,
    EvidenceQueryData,
    confidence_for_query_data,
    get_evidence_query_scope,
)
from app.tools.adapters.base import AdapterConfig, BaseToolAdapter
from app.tools.inputs import TOOL_INPUT_MODELS
from app.tools.query._common import query_tool_meta

QUERY_TOOL_NAMES: tuple[str, ...] = (
    "query_account_login",
    "query_edr_process",
    "query_file_access",
    "query_network_flow",
    "query_dns",
    "query_asset_info",
    "query_vuln_info",
    "query_threat_intel",
    "query_history_cases",
)

_UNAVAILABLE_REASONS: dict[str, str] = {
    "query_account_login": "sangfor open list has no /entities/account fleet login search",
    "query_vuln_info": "sangfor open list has no vulnerability query mapping",
    "query_history_cases": "sangfor open list has no history-case query mapping",
}

_DEGRADED_REASONS: dict[str, str] = {
    "query_edr_process": "incident process entities are an event snapshot, not fleet EDR search",
    "query_file_access": "incident file entities are not account file-access audit",
    "query_dns": "analysislog/networksecurity is threat log, not DNS history",
    "query_network_flow": "analysislog/networksecurity is threat log, not netflow",
    "query_threat_intel": "incident proof is not a dedicated threat-intel catalog",
}

_STALE_AFTER_SECONDS = 3600


def _unix_seconds(value: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return int(value.astimezone(UTC).timestamp())


def _items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    items = data.get("item")
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]
    return [data]


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip().lower()


def _connector_id(scope_connectors: frozenset[str]) -> str:
    return sorted(scope_connectors)[0]


class SangforQueryAdapter(BaseToolAdapter):
    """One live query tool. ``name`` is unique per tool; HTTP is shared."""

    simulated = False

    def __init__(
        self,
        config: AdapterConfig,
        *,
        client: SangforXdrClient,
        tool_name: str,
    ) -> None:
        self.name = f"sangfor_xdr_query:{tool_name}"
        self.tool_meta = query_tool_meta(tool_name)
        self._client = client
        self._tool_name = tool_name
        super().__init__(config)

    def capability_manifest(self) -> CapabilityManifest:
        unavailable = self._tool_name in _UNAVAILABLE_REASONS
        supported = CapabilityState.UNSUPPORTED if unavailable else CapabilityState.SUPPORTED
        return CapabilityManifest(
            provider_name=self.name,
            online=not unavailable,
            source_read=supported,
            entity_response=supported,
            allowed_operations=[self._tool_name],
            supports_idempotency=True,
            allowed_execution_channels=[ExecutionChannel.TOOL_PROVIDER],
        )

    async def health_check(self) -> bool:
        return self.config.enabled and bool(self.config.endpoint.strip())

    async def execute(self, params: dict[str, Any], idempotency_key: str) -> ToolResult:
        del idempotency_key
        parsed = TOOL_INPUT_MODELS[self._tool_name].model_validate(params)
        unavailable = _UNAVAILABLE_REASONS.get(self._tool_name)
        if unavailable is not None:
            return self._unavailable(unavailable)
        try:
            if self._tool_name == "query_asset_info":
                return await self._query_assets(parsed)
            if self._tool_name in {"query_dns", "query_network_flow"}:
                return await self._query_analysislog(parsed)
            if self._tool_name == "query_edr_process":
                return await self._query_entities("process")
            if self._tool_name == "query_file_access":
                return await self._query_entities("file")
            if self._tool_name == "query_threat_intel":
                return await self._query_proof()
        except GuardrailViolationError:
            return self._unavailable("evidence query requires trusted event scope")
        return self._unavailable(f"{self._tool_name} is not wired for live sangfor")

    def _unavailable(self, reason: str) -> ToolResult:
        data = _query_data(records=[], reasons=[reason], coverage="missing", degraded=True)
        return ToolResult(
            call_id=new_call_id(),
            tool_name=self._tool_name,
            provider_name=self.name,
            status=ToolResultStatus.UNSUPPORTED,
            data=data.model_dump(mode="json"),
            provider_code="query_unavailable",
            error_detail=reason,
            confidence=confidence_for_query_data(data),
        )

    def _failed(self, result: SangforHttpResult, *, path: str) -> ToolResult:
        reason = (
            f"sangfor {path} http_status={result.http_status} "
            f"business_code={result.business_code}"
        )
        data = _query_data(records=[], reasons=[reason], coverage="missing", degraded=True)
        return ToolResult(
            call_id=new_call_id(),
            tool_name=self._tool_name,
            provider_name=self.name,
            status=ToolResultStatus.REMOTE_ERROR,
            data=data.model_dump(mode="json"),
            provider_code=result.business_code,
            error_detail=reason,
            raw_result={"path": path, "http_status": result.http_status},
            confidence=confidence_for_query_data(data),
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        path_params: dict[str, Any] | None = None,
    ) -> SangforHttpResult | ToolResult:
        result = await self._client.request(
            method,
            path,
            json_body=json_body,
            path_params=path_params,
        )
        if result.http_status != 200 or result.business_code != "Success":
            return self._failed(result, path=path)
        return result

    async def _query_assets(self, parsed: Any) -> ToolResult:
        page_size = clamp_asset_page_size(int(getattr(parsed, "limit", ASSET_PAGE_SIZE_DEFAULT)))
        outcome = await self._request(
            "POST",
            ASSETS_LIST_PATH,
            json_body={"page": 1, "pageSize": page_size},
        )
        if isinstance(outcome, ToolResult):
            return outcome
        wanted_ip = _text(getattr(parsed, "ip", None))
        wanted_host = _text(getattr(parsed, "hostname", None))
        records = []
        for item in _items(outcome.data):
            ip = _text(item.get("ip") or item.get("hostIp"))
            hostname = _text(item.get("hostname") or item.get("hostName"))
            if wanted_ip and ip != wanted_ip:
                continue
            if wanted_host and hostname != wanted_host:
                continue
            records.append(item)
        return self._success(
            records,
            kind=SourceObjectKind.ASSET,
            degraded=False,
            reasons=[],
        )

    async def _query_analysislog(self, parsed: Any) -> ToolResult:
        time_range = parsed.time_range
        body = {
            "startTimestamp": _unix_seconds(time_range.start),
            "endTimestamp": _unix_seconds(time_range.end),
            "page": 1,
            "pageSize": 5,
        }
        outcome = await self._request("POST", ANALYSISLOG_LIST_PATH, json_body=body)
        if isinstance(outcome, ToolResult):
            return outcome
        records = _filter_analysislog(self._tool_name, parsed, _items(outcome.data))
        return self._success(
            records,
            kind=SourceObjectKind.LOG,
            degraded=True,
            reasons=[_DEGRADED_REASONS[self._tool_name]],
        )

    async def _query_entities(self, kind: str) -> ToolResult:
        uu_id = _incident_uuid()
        if uu_id is None:
            return self._unavailable("incident source_object_id is required for entity queries")
        outcome = await self._request(
            "GET",
            incident_entity_path(kind),
            path_params={"uuid": uu_id},
        )
        if isinstance(outcome, ToolResult):
            return outcome
        return self._success(
            _items(outcome.data),
            kind=SourceObjectKind.INCIDENT,
            degraded=True,
            reasons=[_DEGRADED_REASONS[self._tool_name]],
            object_id=uu_id,
        )

    async def _query_proof(self) -> ToolResult:
        uu_id = _incident_uuid()
        if uu_id is None:
            return self._unavailable("incident source_object_id is required for proof queries")
        outcome = await self._request(
            "GET",
            INCIDENT_PROOF_PATH,
            path_params={"uuid": uu_id},
        )
        if isinstance(outcome, ToolResult):
            return outcome
        records = _items(outcome.data)
        if not records and isinstance(outcome.data, dict):
            records = [outcome.data]
        return self._success(
            records,
            kind=SourceObjectKind.INCIDENT,
            degraded=True,
            reasons=[_DEGRADED_REASONS[self._tool_name]],
            object_id=uu_id,
        )

    def _success(
        self,
        records: list[dict[str, Any]],
        *,
        kind: SourceObjectKind,
        degraded: bool,
        reasons: list[str],
        object_id: str | None = None,
    ) -> ToolResult:
        scope = get_evidence_query_scope()
        connector = _connector_id(scope.connector_ids)
        references = [
            SourceReference(
                source_kind=kind,
                source_product=SOURCE_PRODUCT,
                source_tenant_id=scope.source_tenant_id,
                connector_id=connector,
                source_object_id=str(
                    object_id
                    or item.get("uuId")
                    or item.get("id")
                    or item.get("assetId")
                    or f"{self._tool_name}-{index}"
                ),
            )
            for index, item in enumerate(records)
        ]
        if degraded:
            coverage_state: CoverageState = "partial"
        elif records:
            coverage_state = "complete"
        else:
            coverage_state = "missing"
        data = _query_data(
            records=records,
            references=references,
            reasons=reasons,
            coverage=coverage_state,
            degraded=degraded,
        )
        return ToolResult(
            call_id=new_call_id(),
            tool_name=self._tool_name,
            provider_name=self.name,
            status=ToolResultStatus.SUCCESS,
            data=data.model_dump(mode="json"),
            confidence=confidence_for_query_data(data),
        )


def _incident_uuid() -> str | None:
    scope = get_evidence_query_scope()
    value = (scope.source_object_id or "").strip()
    return value or None


def _filter_analysislog(
    tool_name: str,
    parsed: Any,
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if tool_name == "query_network_flow":
        src = _text(getattr(parsed, "src_ip", None))
        dst = _text(getattr(parsed, "dst_ip", None))
        matched: list[dict[str, Any]] = []
        for item in items:
            item_src = _text(item.get("srcIp"))
            item_dst = _text(item.get("dstIp"))
            if src and src not in {item_src, item_dst}:
                continue
            if dst and dst not in {item_src, item_dst}:
                continue
            matched.append(item)
        return matched
    domain = _text(getattr(parsed, "domain", None))
    if not domain:
        return items
    matched = []
    for item in items:
        blob = " ".join(_text(value) for value in item.values())
        if domain in blob:
            matched.append(item)
    return matched


def _query_data(
    *,
    records: list[dict[str, Any]],
    reasons: list[str],
    coverage: CoverageState,
    degraded: bool,
    references: list[SourceReference] | None = None,
) -> EvidenceQueryData:
    return EvidenceQueryData(
        records=records,
        source_references=references or [],
        data_freshness=DataFreshness(
            state="missing" if coverage == "missing" else "fresh",
            stale_after_seconds=_STALE_AFTER_SECONDS,
        ),
        watermark=None,
        coverage=EvidenceCoverage(
            state=coverage,
            requested_sources=["sangfor_xdr"],
            available_sources=["sangfor_xdr"] if records or coverage != "missing" else [],
            reasons=reasons,
        ),
        next_cursor=None,
        degraded=degraded,
    )


def build_sangfor_query_adapters(
    client: SangforXdrClient,
    config: AdapterConfig,
) -> list[SangforQueryAdapter]:
    """One adapter instance per Evidence query tool (unique provider names)."""
    return [
        SangforQueryAdapter(config, client=client, tool_name=name) for name in QUERY_TOOL_NAMES
    ]
