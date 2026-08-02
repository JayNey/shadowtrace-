"""Smoke script exit-code tests (ISSUE-106 / #609)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
SMOKE_SCRIPT = BACKEND_DIR.parent / "scripts" / "llm_smoke_test.py"


def test_llm_smoke_mock_mode_exit_zero() -> None:
    result = subprocess.run(
        [sys.executable, str(SMOKE_SCRIPT)],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["mode"] == "mock"
    assert payload["synthetic_chat_status"] == "success"
    assert "api_key" not in result.stdout.lower()
