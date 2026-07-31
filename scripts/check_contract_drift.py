"""Fail when committed contracts diverge from a fresh export (ISSUE-112).

Exports into a clean temporary directory and recursively compares the result
against ``contracts/``. CI invokes this script; it never writes back baselines.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from contract_export_lib import (  # noqa: E402
    COMMITTED_CONTRACTS_ROOT,
    compare_contract_trees,
    export_all_contracts,
    format_contract_diffs,
)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="shadowtrace-contract-drift-") as tmp:
        fresh_root = Path(tmp) / "contracts"
        export_all_contracts(fresh_root)
        diffs = compare_contract_trees(COMMITTED_CONTRACTS_ROOT, fresh_root)
        if diffs:
            print(format_contract_diffs(diffs), file=sys.stderr)
            return 1
    print("Contract drift check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
