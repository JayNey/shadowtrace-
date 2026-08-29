"""Sangfor Vendor Wire Mock — replay open-list URIs for Adapter tests.

This is not the product Demo. Canonical Mock remains ``/mock-xdr/v1``.
Unknown paths (including invented isolate-create URIs) return 404.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

_EXTRA_P2_ROUTES: tuple[tuple[str, str], ...] = (
    ("POST", "/api/xdr/v1/responses/blockiprule/unblock"),
)


@dataclass
class SangforWireConfig:
    """Control dealstatus writeback alignment without implementing DispositionAdapter."""

    dealstatus_list_status: int = 6
    partial_dealstatus: bool = False


@dataclass
class _WireState:
    config: SangforWireConfig
    last_write: dict[str, Any] | None = None
    contained_ids: list[str] = field(default_factory=list)


def _repo_paths() -> tuple[Path, Path]:
    here = Path(__file__).resolve()
    roots = (
        here.parents[4] / "contracts" / "vendor" / "sangfor_xdr",
        Path("/contracts/vendor/sangfor_xdr"),
    )
    for root in roots:
        matrix = root / "capability_matrix.yaml"
        fixtures = root / "fixtures"
        if matrix.is_file() and fixtures.is_dir():
            return matrix, fixtures
    raise FileNotFoundError("Sangfor capability matrix / fixtures not found")


def _load_p0_p1_routes(matrix_path: Path) -> list[tuple[str, str]]:
    payload = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
    routes: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in payload.get("operations") or []:
        if not isinstance(row, dict):
            continue
        if row.get("in_loop") not in {"p0", "p1"}:
            continue
        method = row.get("method")
        path = row.get("path")
        if not method or not path:
            continue
        key = (str(method).upper(), str(path))
        if key in seen:
            continue
        seen.add(key)
        routes.append(key)
    for extra in _EXTRA_P2_ROUTES:
        if extra not in seen:
            routes.append(extra)
    return routes


def _template_regex(path: str) -> re.Pattern[str]:
    parts: list[str] = []
    for segment in path.strip("/").split("/"):
        if segment.startswith(":"):
            parts.append(r"[^/]+")
        else:
            parts.append(re.escape(segment))
    return re.compile("^/" + "/".join(parts) + "/?$")


def dealstatus_writeback_would_confirm(
    *,
    write_code: str | None,
    succeeded_num: int | None,
    total: int | None,
    list_deal_status: int | None,
    used_incidents_list: bool = False,
) -> bool:
    """Layer 5 CONFIRMED contract, locked here so fixtures cannot drift."""
    if used_incidents_list:
        return False
    if write_code != "Success":
        return False
    if succeeded_num is None or total is None or succeeded_num != total:
        return False
    return list_deal_status == 6


def entity_write_would_confirm(*, code: str | None) -> bool:
    return code == "Success"


def _load_json(fixtures: Path, name: str) -> dict[str, Any]:
    payload = json.loads((fixtures / name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"fixture {name} is not a JSON object")
    return payload


def _match(
    routes: list[tuple[str, str, re.Pattern[str]]],
    method: str,
    path: str,
) -> str | None:
    for route_method, template, regex in routes:
        if route_method == method and regex.match(path):
            return template
    return None


def create_sangfor_wire_app(
    *,
    config: SangforWireConfig | None = None,
) -> Starlette:
    """ASGI app that replays p0/p1 (plus unblock Part Success). Not a product Mock."""
    matrix_path, fixtures = _repo_paths()
    compiled = [
        (method, path, _template_regex(path)) for method, path in _load_p0_p1_routes(matrix_path)
    ]
    state = _WireState(config=config or SangforWireConfig())

    async def dispatch(request: Request) -> Response:
        method = request.method.upper()
        path = request.url.path
        template = _match(compiled, method, path)
        if template is None:
            return JSONResponse({"code": "NotFound", "message": "not in loop", "data": None}, 404)

        body: Any = None
        if method in {"POST", "PUT", "PATCH"}:
            try:
                body = await request.json()
            except Exception:
                body = {}

        payload = _handle(template, method, path, body, state, fixtures)
        return JSONResponse(payload, status_code=200)

    return Starlette(
        routes=[
            Route("/{rest:path}", dispatch, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]),
        ]
    )


def _handle(
    template: str,
    method: str,
    _path: str,
    body: Any,
    state: _WireState,
    fixtures: Path,
) -> dict[str, Any]:
    if template == "/api/xdr/v1/incidents/dealstatus" and method == "POST":
        payload = copy.deepcopy(
            _load_json(
                fixtures,
                "incidents_dealstatus_partial.json"
                if state.config.partial_dealstatus
                else "incidents_dealstatus_success.json",
            )
        )
        uuids = []
        if isinstance(body, dict):
            raw = body.get("uuIds") or []
            if isinstance(raw, list):
                uuids = [str(item) for item in raw]
            state.last_write = {
                "uuIds": uuids,
                "dealStatus": body.get("dealStatus"),
            }
            state.contained_ids = uuids
        return payload

    if template == "/api/xdr/v1/incidents/dealstatus/list" and method == "POST":
        payload = copy.deepcopy(_load_json(fixtures, "incidents_dealstatus_list.json"))
        ids: list[str] = []
        if isinstance(body, dict):
            raw = body.get("ids") or []
            if isinstance(raw, list):
                ids = [str(item) for item in raw]
        if not ids:
            ids = state.contained_ids or ["incident-wire-001"]
        status = state.config.dealstatus_list_status
        payload["data"]["item"] = [{"uuId": item_id, "dealStatus": status} for item_id in ids]
        return payload

    if template == "/api/xdr/v1/incidents/list" and method == "POST":
        payload = copy.deepcopy(_load_json(fixtures, "incidents_list.json"))
        if state.last_write and state.last_write.get("dealStatus") == 70:
            payload["data"]["item"][0]["dealStatus"] = 30
        return payload

    if template == "/api/xdr/v1/alerts/list" and method == "POST":
        return copy.deepcopy(_load_json(fixtures, "alerts_list.json"))

    if template == "/api/xdr/v1/assets/list" and method == "POST":
        return copy.deepcopy(_load_json(fixtures, "assets_list_invalid.json"))

    if template == "/api/xdr/v1/analysislog/networksecurity/list" and method == "POST":
        return copy.deepcopy(_load_json(fixtures, "analysislog_list.json"))

    if template == "/api/xdr/v1/analysislog/networksecurity/count" and method == "POST":
        return copy.deepcopy(_load_json(fixtures, "analysislog_count.json"))

    if template == "/api/xdr/v1/responses/host/isolate/list" and method == "POST":
        return copy.deepcopy(_load_json(fixtures, "isolate_list.json"))

    if template == "/api/xdr/v1/responses/virusscantask" and method == "POST":
        return copy.deepcopy(_load_json(fixtures, "virusscantask_create.json"))

    if template == "/api/xdr/v1/responses/virusscantask/:taskId" and method == "GET":
        return copy.deepcopy(_load_json(fixtures, "virusscantask_status.json"))

    if template == "/api/xdr/v1/device/blockdevice/list" and method == "POST":
        return copy.deepcopy(_load_json(fixtures, "blockdevice_list.json"))

    if template == "/api/xdr/v1/responses/blockiprule/list" and method == "POST":
        return copy.deepcopy(_load_json(fixtures, "blockiprule_list.json"))

    if template == "/api/xdr/v1/responses/blockiprule/unblock" and method == "POST":
        return copy.deepcopy(_load_json(fixtures, "blockiprule_unblock_part_success.json"))

    if template.startswith("/api/xdr/v1/responses/blockiprule/") and method == "POST":
        return copy.deepcopy(_load_json(fixtures, "blockiprule_ok.json"))

    if "/entities/" in template and method == "GET":
        return copy.deepcopy(_load_json(fixtures, "entities.json"))

    if template.endswith("/proof") and method == "GET":
        return copy.deepcopy(_load_json(fixtures, "proof.json"))

    return {"code": "Success", "message": "OK", "data": {}}
