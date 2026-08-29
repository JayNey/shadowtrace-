"""Sangfor live-pack execution-owner overlay (alignment plan Layer 2).

Pure function: read the Layer 0 capability matrix + pack config, return
ToolMeta *copies* with narrowed ``supported_execution_owners``. Does not send
HTTP, does not mutate ``baseline_tool_index()``, and must not run for
``KIND=mock``.

Wiring onto ``ResponseAgent`` is Layer 8. This module only produces the copy.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.models.enums import DispositionIntentKind, ExecutionOwner, ToolCategory
from app.models.tool_meta import TERMINAL_DISPOSITION_TOOL, ToolMeta

SANGFOR_ADAPTER_KIND = "sangfor_xdr"
MOCK_ADAPTER_KIND = "mock"

KERNEL_RESPONSE_NAMES: frozenset[str] = frozenset(
    {
        "block_ip",
        "block_domain",
        "isolate_host",
        "quarantine_file",
        "block_process",
        "scan_host_for_virus",
        "disable_account",
        "force_logout",
        "reset_password",
        "revoke_token",
        "create_ticket",
        "notify_security_team",
        "update_source_event_disposition",
    }
)

_UNSUPPORTED_TO_KERNEL: dict[str, str] = {
    "isolate_host_create": "isolate_host",
    "quarantine_file_create": "quarantine_file",
    "disable_account": "disable_account",
    "force_logout": "force_logout",
    "reset_password": "reset_password",
    "revoke_token": "revoke_token",
    "block_process": "block_process",
}

_AF_TYPES = frozenset({"AF"})
_EDR_TYPES = frozenset({"EDR", "EDR LITE", "SAAS EDR", "SAAS EDR LITE"})


@dataclass(frozen=True)
class SangforDevice:
    """Block-device inventory row. ``device_type`` uses matrix literals (AF / EDR / …)."""

    device_type: str
    device_id: str = ""


@dataclass(frozen=True)
class SangforOverlayConfig:
    """Live-pack overlay inputs. Production fills this from Settings via runtime_config."""

    adapter_kind: str = MOCK_ADAPTER_KIND
    block_channel: str = "network"
    devices: tuple[SangforDevice, ...] = ()
    ticket_template_id: str | None = None
    ticket_assignee_ids: tuple[str, ...] = ()
    host_identifiers: tuple[str, ...] = ()


@dataclass(frozen=True)
class _MatrixIndex:
    roles: dict[str, str] = field(default_factory=dict)


def _repo_matrix_path() -> Path:
    here = Path(__file__).resolve()
    candidates = (
        here.parents[4] / "contracts" / "vendor" / "sangfor_xdr" / "capability_matrix.yaml",
        Path("/contracts/vendor/sangfor_xdr/capability_matrix.yaml"),
    )
    for path in candidates:
        if path.is_file():
            return path
    raise FileNotFoundError("Sangfor capability_matrix.yaml not found")


def load_capability_matrix(path: Path | None = None) -> _MatrixIndex:
    payload = yaml.safe_load((path or _repo_matrix_path()).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("capability matrix must be a mapping")
    operations = payload.get("operations") or []
    roles: dict[str, str] = {}
    for row in operations:
        if not isinstance(row, dict):
            continue
        name = str(row.get("internal_name") or "")
        role = str(row.get("role") or "")
        if name:
            roles[name] = role
    return _MatrixIndex(roles=roles)


def _norm_device_type(value: str) -> str:
    return " ".join(value.strip().upper().split())


def _has_af(devices: tuple[SangforDevice, ...]) -> bool:
    return any(_norm_device_type(device.device_type) in _AF_TYPES for device in devices)


def _has_edr(devices: tuple[SangforDevice, ...]) -> bool:
    return any(_norm_device_type(device.device_type) in _EDR_TYPES for device in devices)


def _copy_meta(meta: ToolMeta) -> ToolMeta:
    return meta.model_copy(deep=True)


def _with_owners(meta: ToolMeta, owners: list[ExecutionOwner]) -> ToolMeta:
    """Return a copy whose owners (and matching intents) are ``owners``.

    Empty owners cannot pass ToolMeta validation (Layer 8 relaxes Action, not
    ToolMeta). Use ``model_construct`` only for that copy. Never flip executable.
    """
    if not owners:
        payload: dict[str, Any] = meta.model_dump()
        payload["supported_execution_owners"] = []
        payload["required_disposition_intent_by_owner"] = {}
        return ToolMeta.model_construct(**payload)

    intents = dict(meta.required_disposition_intent_by_owner)
    kept: dict[ExecutionOwner, DispositionIntentKind] = {}
    for owner in owners:
        intent = intents.get(owner)
        if intent is None:
            intent = (
                DispositionIntentKind.ENTITY_ACTION_SUBMIT
                if owner is ExecutionOwner.XDR_MANAGED
                else DispositionIntentKind.EXECUTION_RESULT_RECORD
            )
        kept[owner] = intent
    return meta.model_copy(
        update={
            "supported_execution_owners": list(owners),
            "required_disposition_intent_by_owner": kept,
        },
        deep=True,
    )


def _xdr_only_if(ready: bool) -> list[ExecutionOwner]:
    return [ExecutionOwner.XDR_MANAGED] if ready else []


def _owner_decisions(
    matrix: _MatrixIndex,
    config: SangforOverlayConfig,
) -> dict[str, list[ExecutionOwner]]:
    decisions: dict[str, list[ExecutionOwner]] = {}
    roles = matrix.roles
    channel = (config.block_channel or "network").strip().lower()

    for internal_name, kernel in _UNSUPPORTED_TO_KERNEL.items():
        if roles.get(internal_name) == "unsupported_write":
            decisions[kernel] = []

    block_ip_ready = False
    if channel == "network":
        block_ip_ready = roles.get("block_ip_network") == "write" and _has_af(config.devices)
    elif channel == "endpoint":
        block_ip_ready = roles.get("block_ip_endpoint") == "write" and _has_edr(config.devices)
    decisions["block_ip"] = _xdr_only_if(block_ip_ready)

    domain_ready = (
        channel != "endpoint"
        and roles.get("block_domain_network") == "write"
        and _has_af(config.devices)
    )
    decisions["block_domain"] = _xdr_only_if(domain_ready)

    scan_ready = roles.get("virusscantask_create") == "write" and (
        bool(config.devices) or any(item.strip() for item in config.host_identifiers)
    )
    decisions["scan_host_for_virus"] = _xdr_only_if(scan_ready)

    ticket_ready = (
        roles.get("orders_create") == "write"
        and bool((config.ticket_template_id or "").strip())
        and any(item.strip() for item in config.ticket_assignee_ids)
    )
    decisions["create_ticket"] = _xdr_only_if(ticket_ready)

    if roles.get("incidents_dealstatus") == "write":
        decisions[TERMINAL_DISPOSITION_TOOL] = [ExecutionOwner.XDR_MANAGED]

    # No Sangfor write API for notify. Live pack must not keep DIRECT_TOOL.
    decisions["notify_security_team"] = []

    return decisions


def apply_capability_overlay(
    tool_index: Mapping[str, ToolMeta],
    config: SangforOverlayConfig,
    *,
    matrix_path: Path | None = None,
) -> dict[str, ToolMeta]:
    """Return ToolMeta copies. ``KIND=mock`` is identity. Sangfor pack narrows owners."""
    copies = {name: _copy_meta(meta) for name, meta in tool_index.items()}
    if config.adapter_kind != SANGFOR_ADAPTER_KIND:
        return copies

    decisions = _owner_decisions(load_capability_matrix(matrix_path), config)
    for name, meta in list(copies.items()):
        if meta.tool_category is not ToolCategory.RESPONSE:
            continue
        if name not in decisions:
            continue
        copies[name] = _with_owners(meta, decisions[name])
    return copies
