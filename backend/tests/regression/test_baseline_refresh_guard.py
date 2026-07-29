"""Guardrails for baseline refresh entrypoints (ISSUE-087)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

BACKEND_DIR = Path(__file__).resolve().parents[2]
SCRIPT = BACKEND_DIR / "scripts" / "update_regression_baseline.py"


def _run_script(extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("UPDATE_BASELINE", None)
    env.pop("UPDATE_BASELINE_CONFIRM", None)
    env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_update_script_refuses_without_confirmation_env() -> None:
    result = _run_script({"UPDATE_BASELINE": "1"})
    assert result.returncode == 1
    assert "UPDATE_BASELINE_CONFIRM" in result.stderr


def test_update_script_refuses_without_enable_flag() -> None:
    result = _run_script({"UPDATE_BASELINE_CONFIRM": "ISSUE-087"})
    assert result.returncode == 1
    assert "UPDATE_BASELINE=1" in result.stderr
