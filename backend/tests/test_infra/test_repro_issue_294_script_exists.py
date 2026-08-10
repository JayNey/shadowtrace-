"""ISSUE-294 compose image resolver repro script guard."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
REPRO_SCRIPT = REPO_ROOT / "scripts" / "repro_issue_294_compose_image.sh"


def test_repro_issue_294_script_exists() -> None:
    assert REPRO_SCRIPT.is_file(), "ISSUE-294 repro script must exist"
    if os.access(REPRO_SCRIPT, os.X_OK):
        assert REPRO_SCRIPT.stat().st_mode & 0o111
    text = REPRO_SCRIPT.read_text(encoding="utf-8")
    assert "ISSUE-294" in text
    assert "--resolve-compose-image backend" in text
    assert "compose images -q backend" in text
