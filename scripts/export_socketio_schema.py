"""Export the Socket.IO envelope schema into ``contracts/socketio/``.

Usage:
    python scripts/export_socketio_schema.py [--out contracts/socketio/events.schema.json]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from contract_export_lib import export_socketio_schema

_DEFAULT_OUT = (
    Path(__file__).resolve().parents[1] / "contracts" / "socketio" / "events.schema.json"
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export Socket.IO JSON Schema.")
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    args = parser.parse_args()
    out = export_socketio_schema(args.out)
    print(f"Exported Socket.IO schema to {out}")


if __name__ == "__main__":
    main()
