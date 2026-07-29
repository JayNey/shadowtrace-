"""Refresh ISSUE-087 regression golden baselines (explicit human confirmation)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]


def main() -> None:
    if os.environ.get("UPDATE_BASELINE") != "1":
        print(
            "Refusing to overwrite regression baselines without explicit confirmation.\n"
            "Re-run with: UPDATE_BASELINE=1 make update-baseline",
            file=sys.stderr,
        )
        raise SystemExit(1)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/regression/test_baseline_refresh.py",
            "-m",
            "baseline_refresh",
            "-v",
        ],
        cwd=BACKEND_DIR,
        env=os.environ.copy(),
        check=False,
    )
    if result.returncode == 0:
        print("Updated baseline JSON files under tests/regression/baseline/")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
