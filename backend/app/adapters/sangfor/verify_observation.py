"""Read-only Sangfor observation for Verify tools.

Agents must not import this module. ``KIND=sangfor_xdr`` only; never Mock file
state. Isolate list is human reference — one row is not CONFIRMED.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

from app.adapters.sangfor.disposition import (
    BLOCK_LIST_PATH,
    BLOCK_SUCCESS_STATUS,
    VIRUS_SCAN_STATUS_PATH,
    block_status_would_verify,
    scan_task_would_verify,
)
from app.models.ids import new_call_id
from app.models.tool_meta import ToolResult, ToolResultStatus
from app.tools.inputs import CheckStatusInput

logger = logging.getLogger(__name__)

PROVIDER_NAME = "sangfor_xdr"
ISOLATE_LIST_PATH = "/api/xdr/v1/responses/host/isolate/list"
BLOCK_DETAIL_PATH = "/api/xdr/v1/responses/blockiprule/detail"
DNS_RULE_TYPE = "DNS"
_LIST_PAGE_SIZE = 10
_ISOLATE_PAGE_SIZE = 100
_SEVEN_DAYS_S = 7 * 24 * 60 * 60

XDR_MANAGED_VERIFY_TOOLS = frozenset(
    {
        "check_ip_block_status",
        "check_domain_block_status",
        "check_virus_scan_status",
    }
)
_NO_QUERY_UNVERIFIABLE = frozenset(
    {
        "check_account_status",
        "check_process_block_status",
        "check_file_quarantine_status",
        "check_new_alerts",
        "check_traffic_drop",
    }
)


def _now() -> datetime:
    return datetime.now(UTC)


def _tool_result(
    tool_name: str,
    *,
    status: ToolResultStatus,
    data: dict[str, Any],
    error_detail: str | None = None,
) -> dict[str, Any]:
    return ToolResult(
        call_id=new_call_id(),
        tool_name=tool_name,
        provider_name=PROVIDER_NAME,
        status=status,
        data=data,
        error_detail=error_detail,
    ).model_dump(mode="json")


def unverifiable_result(
    tool_name: str,
    *,
    detail: str,
    observed: Any = None,
) -> dict[str, Any]:
    """Non-SUCCESS path so VerifyAgent maps to EffectStatus.UNVERIFIABLE."""
    data: dict[str, Any] = {
        "detail": detail,
        "verified_at": _now().isoformat(),
    }
    if observed is not None:
        data["observed"] = observed
    return _tool_result(tool_name, status=ToolResultStatus.UNKNOWN, data=data)


def _parse_input(params: dict[str, Any]) -> CheckStatusInput | None:
    try:
        return CheckStatusInput.model_validate(params)
    except Exception:
        return None


def _options(params: dict[str, Any]) -> dict[str, Any]:
    parsed = _parse_input(params)
    if parsed is not None:
        return dict(parsed.parameters)
    raw = params.get("parameters")
    return dict(raw) if isinstance(raw, dict) else {}


def _target(params: dict[str, Any]) -> str:
    parsed = _parse_input(params)
    if parsed is not None:
        return str(parsed.target)
    value = params.get("target")
    return str(value) if value is not None else ""


def _job_id(params: dict[str, Any]) -> str | None:
    job_id = _options(params).get("job_id")
    if isinstance(job_id, str) and job_id.strip():
        return job_id.strip()
    return None


def _task_id(params: dict[str, Any]) -> str | None:
    options = _options(params)
    for key in ("taskId", "task_id", "job_id"):
        value = options.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _block_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    items = data.get("item") or []
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _rule_type(item: dict[str, Any]) -> str:
    rule = item.get("blockIpRule")
    if isinstance(rule, dict) and rule.get("type") is not None:
        return str(rule.get("type")).strip()
    if item.get("type") is not None:
        return str(item.get("type")).strip()
    return ""


def _item_status(item: dict[str, Any]) -> str | None:
    raw = item.get("status")
    if raw is None:
        return None
    return str(raw)


async def _resolve_client(client: Any | None) -> Any | None:
    if client is not None:
        return client
    try:
        from app.adapters.factory import build_sangfor_client
        from app.core.config import get_settings

        return build_sangfor_client(get_settings())
    except Exception:
        logger.info("sangfor verify observation has no live client")
        return None


async def observe_sangfor_verification(
    tool_name: str,
    params: dict[str, Any],
    *,
    client: Any | None = None,
) -> dict[str, Any]:
    """KIND=sangfor_xdr Verify injection. Never calls MockVerificationRuntime."""
    if tool_name in _NO_QUERY_UNVERIFIABLE:
        return unverifiable_result(tool_name, detail="need_manual_resolution")
    if tool_name == "check_host_isolation_status":
        return await _observe_host_isolation(params, client=client)
    if tool_name not in XDR_MANAGED_VERIFY_TOOLS:
        return unverifiable_result(tool_name, detail="need_manual_resolution")
    if _job_id(params) is None and tool_name != "check_virus_scan_status":
        return unverifiable_result(tool_name, detail="missing_job_id")
    if tool_name == "check_virus_scan_status" and _task_id(params) is None:
        return unverifiable_result(tool_name, detail="missing_task_id")

    resolved = await _resolve_client(client)
    if resolved is None:
        return unverifiable_result(tool_name, detail="sangfor_client_unavailable")
    try:
        if tool_name == "check_virus_scan_status":
            return await _observe_virus_scan(resolved, params)
        require_dns = tool_name == "check_domain_block_status"
        return await _observe_block_rule(resolved, params, require_dns=require_dns)
    except Exception:
        logger.warning("sangfor verify observation failed tool=%s", tool_name, exc_info=True)
        return unverifiable_result(tool_name, detail="sangfor_observation_error")


async def _observe_host_isolation(
    params: dict[str, Any],
    *,
    client: Any | None,
) -> dict[str, Any]:
    observed: Any = None
    resolved = await _resolve_client(client)
    if resolved is not None:
        try:
            observed = await _isolate_list(resolved, params)
        except Exception:
            logger.info("isolate/list observation failed; still UNVERIFIABLE")
            observed = None
    return unverifiable_result(
        "check_host_isolation_status",
        detail="need_manual_resolution",
        observed=observed,
    )


async def _isolate_list(client: Any, params: dict[str, Any]) -> list[dict[str, Any]]:
    end_ts = int(time.time())
    start_ts = end_ts - _SEVEN_DAYS_S
    result = await client.request(
        "POST",
        ISOLATE_LIST_PATH,
        json_body={
            "startTimestamp": start_ts,
            "endTimestamp": end_ts,
            "pageSize": _ISOLATE_PAGE_SIZE,
            "page": 1,
            "isolateStatus": "",
            "hostIp": _target(params),
        },
    )
    return _block_items(result.data)


async def _observe_block_rule(
    client: Any,
    params: dict[str, Any],
    *,
    require_dns: bool,
) -> dict[str, Any]:
    tool_name = (
        "check_domain_block_status" if require_dns else "check_ip_block_status"
    )
    job_id = _job_id(params)
    items = await _fetch_block_items(client, job_id=job_id)
    matched = [
        item
        for item in items
        if (not require_dns or _rule_type(item) == DNS_RULE_TYPE)
    ]
    verified = any(block_status_would_verify(_item_status(item)) for item in matched)
    if verified:
        return _tool_result(
            tool_name,
            status=ToolResultStatus.SUCCESS,
            data={
                "is_verified": True,
                "detail": "effect_verified",
                "verified_at": _now().isoformat(),
                "observed_status": BLOCK_SUCCESS_STATUS,
            },
        )
    return unverifiable_result(
        tool_name,
        detail="block_effect_unverified",
        observed=matched,
    )


async def _fetch_block_items(
    client: Any,
    *,
    job_id: str | None,
) -> list[dict[str, Any]]:
    if job_id:
        detail = await client.request(
            "POST",
            BLOCK_DETAIL_PATH,
            json_body={"ids": [job_id]},
        )
        items = _block_items(detail.data)
        if items:
            return items
    listed = await client.request(
        "POST",
        BLOCK_LIST_PATH,
        json_body={
            "page": 1,
            "pageSize": _LIST_PAGE_SIZE,
        },
    )
    return _block_items(listed.data)


async def _observe_virus_scan(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    task_id = _task_id(params)
    assert task_id is not None
    result = await client.request(
        "GET",
        VIRUS_SCAN_STATUS_PATH,
        path_params={"taskId": task_id},
    )
    data = result.data if isinstance(result.data, dict) else None
    status = None if data is None else data.get("status")
    status_text = None if status is None else str(status)
    items = _block_items(data)
    if scan_task_would_verify(status_text, items):
        return _tool_result(
            "check_virus_scan_status",
            status=ToolResultStatus.SUCCESS,
            data={
                "is_verified": True,
                "detail": "effect_verified",
                "verified_at": _now().isoformat(),
                "observed_status": status_text,
            },
        )
    return unverifiable_result(
        "check_virus_scan_status",
        detail="scan_effect_unverified",
        observed={"status": status_text, "item": items},
    )


__all__ = [
    "BLOCK_DETAIL_PATH",
    "ISOLATE_LIST_PATH",
    "XDR_MANAGED_VERIFY_TOOLS",
    "observe_sangfor_verification",
    "unverifiable_result",
]
