"""Layer 10 Sangfor first-contact probe (signed read-only against OpenAPI URIs).

Uses only SangforXdrClient + load_credentials.
Does not read .env.live. HTTP 200 is not business success — body.code must be Success.

Default: two signed POSTs (incidents/list time window + blockdevice/list).
Optional --write-same-status --event-uuid writes the current TMG dealStatus and
never writes 70. Confirmation uses dealstatus/list ``ids`` plus Layer 5
``dealstatus_readback_would_confirm`` (library code must match the written TMG).

This script is not production cutover and is not the product Demo.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_BACKEND = _ROOT / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.adapters.sangfor.client import SangforHttpResult, SangforXdrClient  # noqa: E402
from app.adapters.sangfor.disposition import (  # noqa: E402
    dealstatus_readback_would_confirm,
    source_disposition_from_outbound_tmg,
)
from app.adapters.sangfor.signing import (  # noqa: E402
    AUTH_HEADER_KEY,
    SIGN_DATE_KEY,
    load_credentials,
    redact_signing_text,
)

logger = logging.getLogger("sangfor_xdr_first_contact")

INCIDENTS_LIST_PATH = "/api/xdr/v1/incidents/list"
BLOCKDEVICE_LIST_PATH = "/api/xdr/v1/device/blockdevice/list"
DEALSTATUS_WRITE_PATH = "/api/xdr/v1/incidents/dealstatus"
DEALSTATUS_LIST_PATH = "/api/xdr/v1/incidents/dealstatus/list"

DEFAULT_PAGE_SIZE = 5
DEFAULT_LOOKBACK = timedelta(hours=24)
TIME_FIELD = "endTime"
FORBIDDEN_DEAL_STATUS = 70
DEVICE_KEYS = ("deviceId", "deviceName", "deviceType", "gatewayId")
BLOCKDEVICE_LIST_TYPES = ("AF", "EDR", "EDR LITE", "SAAS EDR", "SAAS EDR LITE")
DEFAULT_ARTIFACTS = _ROOT / "artifacts" / "sangfor-first-contact"


@dataclass
class CallRecord:
    method: str
    path: str
    json_body: Any
    http_status: int
    business_code: str | None
    message: str | None
    data: Any
    headers: dict[str, str]
    raw_text: str

    def business_ok(self) -> bool:
        return self.http_status == 200 and self.business_code == "Success"


@dataclass
class ProbeReport:
    exit_code: int
    calls: list[CallRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    devices: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    write_deal_status: int | None = None
    confirmed: bool | None = None
    artifacts_dir: Path | None = None


def _env_get(env: Mapping[str, str], key: str) -> str:
    return (env.get(key) or "").strip()


def _tls_verify(env: Mapping[str, str]) -> bool:
    raw = _env_get(env, "SANGFOR_TLS_VERIFY").lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    return True


def fail_closed_reason(env: Mapping[str, str]) -> str | None:
    """Return a fail-closed reason without constructing HTTP or echoing secrets."""
    app_env = _env_get(env, "APP_ENV") or "development"
    if app_env.lower() == "production":
        return "APP_ENV=production is fail-closed for first-contact"
    if not _env_get(env, "SANGFOR_XDR_BASE_URL"):
        return "missing SANGFOR_XDR_BASE_URL"
    access_key = _env_get(env, "SANGFOR_ACCESS_KEY") or None
    secret_key = _env_get(env, "SANGFOR_SECRET_KEY") or None
    auth_code = _env_get(env, "SANGFOR_AUTH_CODE") or _env_get(env, "AUTH_CODE") or None
    try:
        load_credentials(
            access_key=access_key,
            secret_key=secret_key,
            auth_code=auth_code,
        )
    except ValueError:
        return "missing Sangfor credentials (linkage code or AK/SK)"
    return None


def incidents_list_body(*, now: datetime | None = None) -> dict[str, Any]:
    """Same time-window shape as SangforSourceAdapter._list_body."""
    end = now or datetime.now(UTC)
    start = end - DEFAULT_LOOKBACK
    return {
        "startTimestamp": int(start.timestamp()),
        "endTimestamp": int(end.timestamp()),
        "timeField": TIME_FIELD,
        "page": 1,
        "pageSize": DEFAULT_PAGE_SIZE,
    }


def blockdevice_list_body() -> dict[str, Any]:
    """Catalog ``type`` is an array of AF/EDR product classes, not an empty string."""
    return {"type": list(BLOCKDEVICE_LIST_TYPES)}


def _devices_from_data(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    items = data.get("item") or []
    if not isinstance(items, list):
        return []
    devices: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        devices.append({key: item.get(key) for key in DEVICE_KEYS})
    return devices


def _incident_items(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    items = data.get("item") or []
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _header_presence(headers: Mapping[str, str]) -> dict[str, bool]:
    return {
        "authorization_present": AUTH_HEADER_KEY in headers,
        "sign_date_present": SIGN_DATE_KEY in headers,
    }


def _redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_signing_text(value)
    if isinstance(value, Mapping):
        return {str(key): _redact_obj(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_obj(item) for item in value]
    return value


def _call_summary(record: CallRecord) -> dict[str, Any]:
    return {
        "method": record.method,
        "path": record.path,
        "json_body": _redact_obj(record.json_body),
        "http_status": record.http_status,
        "business_code": record.business_code,
        "message": record.message,
        "headers": _header_presence(record.headers),
        "business_ok": record.business_ok(),
    }


async def _post(
    client: SangforXdrClient,
    path: str,
    body: dict[str, Any],
) -> CallRecord:
    result: SangforHttpResult = await client.request("POST", path, json_body=body)
    return CallRecord(
        method="POST",
        path=path,
        json_body=body,
        http_status=result.http_status,
        business_code=result.business_code,
        message=result.message,
        data=result.data,
        headers=dict(result.signed.headers),
        raw_text=result.raw_text,
    )


async def probe(
    client: SangforXdrClient,
    *,
    write_same_status: bool = False,
    event_uuid: str | None = None,
    now: datetime | None = None,
) -> ProbeReport:
    """Run the default read-only probe (and optional same-status write) on ``client``."""
    report = ProbeReport(exit_code=0)
    list_call = await _post(client, INCIDENTS_LIST_PATH, incidents_list_body(now=now))
    report.calls.append(list_call)
    logger.info(
        "incidents/list http_status=%s business_code=%s",
        list_call.http_status,
        list_call.business_code,
    )

    device_call = await _post(client, BLOCKDEVICE_LIST_PATH, blockdevice_list_body())
    report.calls.append(device_call)
    report.devices = _devices_from_data(device_call.data)
    if not report.devices:
        report.notes.append("no devices")
        logger.info("blockdevice/list empty item — site has no devices (probe success)")
    logger.info(
        "blockdevice/list http_status=%s business_code=%s devices=%s",
        device_call.http_status,
        device_call.business_code,
        len(report.devices),
    )

    if not list_call.business_ok() or not device_call.business_ok():
        report.exit_code = 1
        report.error = "read-only probe business failure"
        return report

    if not write_same_status:
        return report

    uuid = (event_uuid or "").strip()
    if not uuid:
        report.exit_code = 2
        report.error = "--write-same-status requires --event-uuid"
        return report

    match = next(
        (item for item in _incident_items(list_call.data) if str(item.get("uuId")) == uuid),
        None,
    )
    if match is None:
        report.exit_code = 1
        report.error = "event uuid not in incidents/list"
        return report

    current = match.get("dealStatus")
    if not isinstance(current, int):
        report.exit_code = 1
        report.error = "incidents/list dealStatus is not an integer"
        return report
    if current == FORBIDDEN_DEAL_STATUS:
        report.exit_code = 2
        report.error = "refusing to write dealStatus 70"
        return report

    write_body = {"uuIds": [uuid], "dealStatus": current}
    write_call = await _post(client, DEALSTATUS_WRITE_PATH, write_body)
    report.calls.append(write_call)
    report.write_deal_status = current
    logger.info(
        "dealstatus write http_status=%s business_code=%s dealStatus=%s",
        write_call.http_status,
        write_call.business_code,
        current,
    )

    readback_body = {"ids": [uuid]}
    readback_call = await _post(client, DEALSTATUS_LIST_PATH, readback_body)
    report.calls.append(readback_call)

    write_data = write_call.data if isinstance(write_call.data, dict) else {}
    items = _incident_items(readback_call.data)
    list_status = items[0].get("dealStatus") if items else None
    if not isinstance(list_status, int):
        list_status = None
    target = source_disposition_from_outbound_tmg(current)
    report.confirmed = (
        False
        if target is None
        else dealstatus_readback_would_confirm(
            write_code=write_call.business_code,
            succeeded_num=write_data.get("succeededNum"),
            total=write_data.get("total"),
            list_deal_status=list_status,
            target=target,
        )
    )
    if not write_call.business_ok() or not readback_call.business_ok():
        report.exit_code = 1
        report.error = "write-same-status business failure"
    return report


def write_artifacts(report: ProbeReport, artifacts_dir: Path) -> None:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "exit_code": report.exit_code,
        "error": report.error,
        "notes": report.notes,
        "devices": report.devices,
        "write_deal_status": report.write_deal_status,
        "confirmed": report.confirmed,
        "calls": [_call_summary(call) for call in report.calls],
    }
    (artifacts_dir / "summary.json").write_text(
        json.dumps(_redact_obj(summary), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    devices_path = artifacts_dir / "blockdevice.json"
    devices_path.write_text(
        json.dumps(report.devices, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    report.artifacts_dir = artifacts_dir


def client_from_env(env: Mapping[str, str]) -> SangforXdrClient:
    base_url = _env_get(env, "SANGFOR_XDR_BASE_URL")
    return SangforXdrClient(
        base_url,
        access_key=_env_get(env, "SANGFOR_ACCESS_KEY") or None,
        secret_key=_env_get(env, "SANGFOR_SECRET_KEY") or None,
        auth_code=_env_get(env, "SANGFOR_AUTH_CODE") or _env_get(env, "AUTH_CODE") or None,
        verify=_tls_verify(env),
    )


async def run(
    *,
    client: SangforXdrClient | None = None,
    env: Mapping[str, str] | None = None,
    write_same_status: bool = False,
    event_uuid: str | None = None,
    artifacts_dir: Path | None = None,
    now: datetime | None = None,
) -> ProbeReport:
    """CLI/test entry: fail-closed on missing URL/creds; inject ``client`` in tests."""
    source = env if env is not None else os.environ
    owns_client = client is None
    if client is None:
        reason = fail_closed_reason(source)
        if reason is not None:
            report = ProbeReport(exit_code=2, error=reason)
            logger.error("%s", reason)
            return report
        client = client_from_env(source)
    try:
        report = await probe(
            client,
            write_same_status=write_same_status,
            event_uuid=event_uuid,
            now=now,
        )
    finally:
        if owns_client:
            await client.aclose()

    target = artifacts_dir if artifacts_dir is not None else DEFAULT_ARTIFACTS
    try:
        write_artifacts(report, target)
    except OSError as exc:
        logger.error("failed to write artifacts: %s", exc)
        if report.exit_code == 0:
            report.exit_code = 1
            report.error = "failed to write artifacts"
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sangfor XDR first-contact probe (signed read-only; not Demo)",
    )
    parser.add_argument(
        "--write-same-status",
        action="store_true",
        help="Write the current TMG dealStatus for --event-uuid (never 70)",
    )
    parser.add_argument(
        "--event-uuid",
        default=None,
        help="Incident uuId required with --write-same-status",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=None,
        help="Directory for redacted JSON artifacts",
    )
    return parser.parse_args(argv)


async def async_main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    report = await run(
        write_same_status=args.write_same_status,
        event_uuid=args.event_uuid,
        artifacts_dir=args.artifacts_dir,
    )
    return report.exit_code


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(async_main(argv))


if __name__ == "__main__":
    raise SystemExit(main())
