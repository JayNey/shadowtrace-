"""Export the OpenAPI 3.1 document to ``contracts/openapi/openapi.json``.

Prefer updating all committed contracts together::

    make update-contracts

This script exports OpenAPI only. CI ``check-contract-drift`` compares the full
``contracts/`` tree; partial exports will fail the drift gate.

Usage:
    python scripts/export_openapi.py [--out contracts/openapi/openapi.json]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from contract_export_lib import export_openapi as _export_openapi

_DEFAULT_OUT = Path(__file__).resolve().parents[1] / "contracts" / "openapi" / "openapi.json"


def export_openapi(out_path: Path) -> Path:
    """Write the app's OpenAPI schema to ``out_path`` and return it."""
    return _export_openapi(out_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export OpenAPI document.")
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    args = parser.parse_args()
    out = export_openapi(args.out)
    print(f"Exported OpenAPI to {out}")


if __name__ == "__main__":
    main()
