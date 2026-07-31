"""Export JSON Schema for every core model into ``contracts/schemas/``.

Usage:
    python scripts/export_schemas.py [--out contracts/schemas]

Each model in ``app.models.MODEL_REGISTRY`` is written to
``{out}/{model_name}.json``. Stale model files under ``out/`` are removed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from contract_export_lib import export_core_schemas

_DEFAULT_OUT = Path(__file__).resolve().parents[1] / "contracts" / "schemas"


def export_schemas(out_dir: Path) -> list[Path]:
    """Write one JSON Schema file per registered model; return written paths."""
    return export_core_schemas(out_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export core model JSON Schemas.")
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    args = parser.parse_args()
    written = export_schemas(args.out)
    print(f"Exported {len(written)} schemas to {args.out}")


if __name__ == "__main__":
    main()
