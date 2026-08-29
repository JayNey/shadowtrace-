#!/usr/bin/env python3
"""Fail when committed Sangfor catalog.json diverges from a fresh HTML extract.

Re-parses the challenge-cup eolinker export and compares it to
``contracts/vendor/sangfor_xdr/catalog.json``. Never writes the baseline back.

Usage::

    python3 scripts/check_sangfor_catalog_drift.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from extract_sangfor_catalog import (  # noqa: E402
    DEFAULT_CATALOG,
    DEFAULT_HTML,
    catalog_to_json,
    load_catalog_from_html,
)


def load_committed_catalog(path: Path = DEFAULT_CATALOG) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} is not a JSON object")
    return payload


def catalog_drift_messages(*, html_path: Path, committed_path: Path) -> list[str]:
    fresh = load_catalog_from_html(html_path)
    committed = load_committed_catalog(committed_path)
    messages: list[str] = []
    if fresh == committed:
        return messages
    if fresh.get("operation_count") != committed.get("operation_count"):
        messages.append(
            "operation_count mismatch: "
            f"html={fresh.get('operation_count')!r} "
            f"committed={committed.get('operation_count')!r}"
        )
    if catalog_to_json(fresh) != catalog_to_json(committed):
        messages.append(
            f"{committed_path} drifted from {html_path}. "
            "Re-run: python3 scripts/extract_sangfor_catalog.py"
        )
    return messages


def main() -> int:
    if not DEFAULT_HTML.is_file():
        print(f"missing HTML export: {DEFAULT_HTML}", file=sys.stderr)
        return 1
    if not DEFAULT_CATALOG.is_file():
        print(f"missing catalog: {DEFAULT_CATALOG}", file=sys.stderr)
        return 1
    messages = catalog_drift_messages(
        html_path=DEFAULT_HTML,
        committed_path=DEFAULT_CATALOG,
    )
    if messages:
        for line in messages:
            print(line, file=sys.stderr)
        return 1
    print("Sangfor catalog drift check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
