"""Parse Sangfor overlay / block config from Settings.

Overlay owners and Disposition ``devices[]`` must come from the same parse so
they cannot drift. KIND=mock never calls this.
"""

from __future__ import annotations

import json
from typing import Any

from app.adapters.sangfor.capability_overlay import (
    SANGFOR_ADAPTER_KIND,
    SangforDevice,
    SangforOverlayConfig,
)
from app.adapters.sangfor.disposition import SangforBlockConfig
from app.core.config import Settings
from app.core.errors import ConfigurationError


def _parse_json_array(raw: str, *, field: str) -> list[Any]:
    text = (raw or "").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(
            f"{field} must be a JSON array",
            error_code="configuration_error",
            details={"field": field, "reason": str(exc)},
        ) from exc
    if not isinstance(payload, list):
        raise ConfigurationError(
            f"{field} must be a JSON array",
            error_code="configuration_error",
            details={"field": field},
        )
    return payload


def parse_id_list(raw: str, *, field: str) -> tuple[str, ...]:
    """JSON array or comma-separated identifiers."""
    text = (raw or "").strip()
    if not text:
        return ()
    if text.startswith("["):
        items = _parse_json_array(text, field=field)
        return tuple(str(item).strip() for item in items if str(item).strip())
    return tuple(part.strip() for part in text.split(",") if part.strip())


def parse_device_rows(raw: str) -> tuple[dict[str, Any], ...]:
    """Normalize Settings JSON into blockdevice-shaped dicts (deviceId / deviceType)."""
    rows: list[dict[str, Any]] = []
    for item in _parse_json_array(raw, field="SANGFOR_DEVICES"):
        if not isinstance(item, dict):
            continue
        device_id = item.get("deviceId", item.get("device_id", item.get("devId")))
        if device_id is None or str(device_id).strip() == "":
            continue
        device_type = item.get("deviceType", item.get("device_type", item.get("devType")))
        row: dict[str, Any] = {
            "deviceId": device_id,
            "deviceType": "" if device_type is None else str(device_type),
        }
        name = item.get("deviceName", item.get("device_name", item.get("devName")))
        if name is not None and str(name).strip() != "":
            row["deviceName"] = name
        gateway = item.get("gatewayId")
        if gateway is not None and str(gateway).strip() != "":
            row["gatewayId"] = gateway
        agent = item.get("agentId")
        if agent is not None and str(agent).strip() != "":
            row["agentId"] = agent
        version = item.get("deviceVersion", item.get("devVersion"))
        if version is not None and str(version).strip() != "":
            row["deviceVersion"] = version
        rows.append(row)
    return tuple(rows)


def overlay_config_from_settings(settings: Settings) -> SangforOverlayConfig:
    """Live-pack overlay inputs. Empty devices/ticket stay fail-closed (manual)."""
    rows = parse_device_rows(settings.sangfor_devices)
    template = (settings.sangfor_ticket_template_id or "").strip() or None
    return SangforOverlayConfig(
        adapter_kind=SANGFOR_ADAPTER_KIND,
        block_channel=(settings.sangfor_block_channel or "network").strip().lower(),
        devices=tuple(
            SangforDevice(
                device_type=str(row.get("deviceType") or ""),
                device_id=str(row["deviceId"]),
            )
            for row in rows
        ),
        ticket_template_id=template,
        ticket_assignee_ids=parse_id_list(
            settings.sangfor_ticket_assignee_ids,
            field="SANGFOR_TICKET_ASSIGNEE_IDS",
        ),
        host_identifiers=parse_id_list(
            settings.sangfor_host_identifiers,
            field="SANGFOR_HOST_IDENTIFIERS",
        ),
    )


def block_config_from_settings(settings: Settings) -> SangforBlockConfig:
    """Same device/ticket parse as overlay, shaped for Disposition HTTP bodies."""
    template = (settings.sangfor_ticket_template_id or "").strip()
    kwargs: dict[str, Any] = {
        "block_channel": (settings.sangfor_block_channel or "network").strip().lower(),
        "devices": parse_device_rows(settings.sangfor_devices),
        "next_assignee_ids": parse_id_list(
            settings.sangfor_ticket_assignee_ids,
            field="SANGFOR_TICKET_ASSIGNEE_IDS",
        ),
    }
    if template:
        kwargs["process_template_id"] = template
    return SangforBlockConfig(**kwargs)
