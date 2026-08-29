"""Export all committed contracts into a target directory (ISSUE-112).

Usage:
    python scripts/export_contracts.py [--out /tmp/shadowtrace-contracts]
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from contract_export_lib import COMMITTED_CONTRACTS_ROOT, export_all_contracts  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Export ShadowTrace contracts.")
    parser.add_argument(
        "--out",
        type=Path,
        default=COMMITTED_CONTRACTS_ROOT,
        help="Output root (defaults to committed contracts/ directory).",
    )
    args = parser.parse_args()

    out_root = args.out
    if out_root.resolve() == COMMITTED_CONTRACTS_ROOT.resolve():
        with tempfile.TemporaryDirectory(prefix="shadowtrace-contract-export-") as tmp:
            staging = Path(tmp)
            export_all_contracts(staging)
            _replace_tree(staging, out_root)
    else:
        export_all_contracts(out_root)

    print(f"Exported contracts to {out_root}")


def _replace_tree(source: Path, target: Path) -> None:
    """Atomically refresh ``target`` from a fully-built ``source`` tree.

    Hand-maintained ``vendor/`` packs are preserved; export_all_contracts does
    not emit them, and wiping them would destroy Sangfor fixtures.
    """
    import shutil

    def _hand_maintained(rel: str) -> bool:
        return rel == "vendor" or rel.startswith("vendor/")

    for path in sorted(target.rglob("*"), reverse=True):
        if path.is_file() and path.name != ".gitkeep":
            rel = path.relative_to(target).as_posix()
            if _hand_maintained(rel):
                continue
            path.unlink()
    for path in sorted(
        (item for item in target.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        rel = path.relative_to(target).as_posix()
        if _hand_maintained(rel):
            continue
        try:
            path.rmdir()
        except OSError:
            pass
    for path in source.rglob("*"):
        if path.is_file():
            rel = path.relative_to(source)
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)


if __name__ == "__main__":
    main()
