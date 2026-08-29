#!/usr/bin/env python3
"""Extract the Sangfor XDR OpenAPI catalog from the challenge-cup HTML export.

Source of truth: ``挑战杯物料/OpenAPIDocument/深信服XDR平台接口开放列表.html``
(eolinker ``projectJSON``, 2026-04-28). This script does not invent URIs.

Usage::

    python3 scripts/extract_sangfor_catalog.py
    python3 scripts/extract_sangfor_catalog.py --stdout
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HTML = (
    REPO_ROOT / "挑战杯物料" / "OpenAPIDocument" / "深信服XDR平台接口开放列表.html"
)
DEFAULT_CATALOG = REPO_ROOT / "contracts" / "vendor" / "sangfor_xdr" / "catalog.json"

PROJECT_JSON_MARKER = "var projectJSON = "
PLACEHOLDER_RE = re.compile(r":[A-Za-z][A-Za-z0-9_]*")

# eolinker apiRequestType. 0 is POST — never treat 0 as empty.
METHOD_BY_REQUEST_TYPE: dict[int, str] = {
    0: "POST",
    1: "GET",
    2: "PUT",
    3: "DELETE",
    6: "PATCH",
}

_FIELD_KEYS = (
    "paramKey",
    "paramName",
    "paramNotNull",
    "paramValue",
    "paramLimit",
    "paramNote",
)


def parse_project_json(html_text: str) -> dict[str, Any]:
    """Decode ``var projectJSON = {…}`` with JSONDecoder.raw_decode."""
    idx = html_text.find(PROJECT_JSON_MARKER)
    if idx < 0:
        raise ValueError("HTML export is missing 'var projectJSON = '")
    payload = html_text[idx + len(PROJECT_JSON_MARKER) :].lstrip()
    if not payload.startswith("{"):
        raise ValueError("projectJSON payload does not start with '{'")
    obj, _end = json.JSONDecoder().raw_decode(payload)
    if not isinstance(obj, dict):
        raise ValueError("projectJSON did not decode to an object")
    return obj


def _slim_value_list(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        entry: dict[str, Any] = {}
        if "value" in item:
            entry["value"] = item["value"]
        if "valueDescription" in item:
            entry["valueDescription"] = item["valueDescription"]
        if entry:
            out.append(entry)
    return out


def slim_field_tree(params: Any) -> list[dict[str, Any]]:
    """Keep eolinker field keys, nested childList, and original enum lists."""
    if not isinstance(params, list):
        return []
    out: list[dict[str, Any]] = []
    for param in params:
        if not isinstance(param, dict):
            continue
        node: dict[str, Any] = {}
        for key in _FIELD_KEYS:
            if key in param:
                node[key] = param[key]
        value_list = _slim_value_list(param.get("paramValueList"))
        if value_list:
            node["paramValueList"] = value_list
        children = slim_field_tree(param.get("childList"))
        if children:
            node["childList"] = children
        if node:
            out.append(node)
    return out


def path_placeholders(api_uri: str) -> list[str]:
    """Placeholders from the URI itself, even when restfulParam is empty."""
    return PLACEHOLDER_RE.findall(api_uri)


def _iter_group_apis(project: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Walk top-level apiGroupList only (child groups are already listed flat)."""
    rows: list[tuple[str, dict[str, Any]]] = []
    for group in project.get("apiGroupList") or []:
        if not isinstance(group, dict):
            continue
        group_name = str(group.get("groupName") or "")
        for api in group.get("apiList") or []:
            if isinstance(api, dict):
                rows.append((group_name, api))
    return rows


def extract_operation(group_name: str, api: dict[str, Any]) -> dict[str, Any]:
    base = api.get("baseInfo") if isinstance(api.get("baseInfo"), dict) else {}
    request_type = base.get("apiRequestType")
    if request_type not in METHOD_BY_REQUEST_TYPE:
        raise ValueError(
            f"unknown apiRequestType {request_type!r} for {base.get('apiURI')!r}"
        )
    path = str(base.get("apiURI") or "")
    if not path:
        raise ValueError(f"api {base.get('apiName')!r} is missing apiURI")
    responses: list[dict[str, Any]] = []
    for result in api.get("resultInfo") or []:
        if not isinstance(result, dict):
            continue
        responses.append(
            {
                "responseCode": result.get("responseCode"),
                "responseName": result.get("responseName"),
                "paramList": slim_field_tree(result.get("paramList")),
            }
        )
    return {
        "method": METHOD_BY_REQUEST_TYPE[request_type],
        "path": path,
        "name": base.get("apiName") or "",
        "group_name": group_name,
        "path_placeholders": path_placeholders(path),
        "restful_params": slim_field_tree(api.get("restfulParam")),
        "url_params": slim_field_tree(api.get("urlParam")),
        "request": slim_field_tree(api.get("requestInfo")),
        "response": responses,
    }


def extract_catalog(project: dict[str, Any], *, source: str) -> dict[str, Any]:
    info = project.get("projectInfo") if isinstance(project.get("projectInfo"), dict) else {}
    operations = [
        extract_operation(group_name, api)
        for group_name, api in _iter_group_apis(project)
    ]
    operations.sort(key=lambda row: (str(row["path"]), str(row["method"])))
    return {
        "source": source,
        "project_name": info.get("projectName") or "",
        "project_update_time": info.get("projectUpdateTime") or "",
        "operation_count": len(operations),
        "operations": operations,
    }


def catalog_to_json(catalog: dict[str, Any]) -> str:
    return json.dumps(catalog, ensure_ascii=False, indent=2) + "\n"


def load_catalog_from_html(html_path: Path, *, source: str | None = None) -> dict[str, Any]:
    html_text = html_path.read_text(encoding="utf-8")
    project = parse_project_json(html_text)
    rel = source
    if rel is None:
        try:
            rel = str(html_path.resolve().relative_to(REPO_ROOT))
        except ValueError:
            rel = str(html_path)
    return extract_catalog(project, source=rel)


def write_catalog(path: Path, catalog: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(catalog_to_json(catalog), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--html",
        type=Path,
        default=DEFAULT_HTML,
        help="eolinker HTML export path",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_CATALOG,
        help="catalog.json destination",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="print JSON instead of writing --output",
    )
    args = parser.parse_args(argv)
    catalog = load_catalog_from_html(args.html)
    text = catalog_to_json(catalog)
    if args.stdout:
        sys.stdout.write(text)
        return 0
    write_catalog(args.output, catalog)
    print(
        f"Wrote {catalog['operation_count']} operations to {args.output}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
