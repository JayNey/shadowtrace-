"""Fail when Alembic revision ids exceed alembic_version.version_num width (ISSUE-214).

Scans ``backend/migrations/versions/*.py`` and ensures every ``revision = "..."``
string length is <= ``ALEMBIC_VERSION_NUM_WIDTH`` (must match
``0032_alembic_version_widen.py``).

CI and ``make check-migration-revisions`` invoke this script.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VERSIONS_DIR = REPO_ROOT / "backend" / "migrations" / "versions"

# Must match backend/migrations/versions/0032_alembic_version_widen.py
ALEMBIC_VERSION_NUM_WIDTH = 64


def _revision_ids() -> list[tuple[str, Path, int]]:
    rows: list[tuple[str, Path, int]] = []
    for path in sorted(VERSIONS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == "revision"
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    revision = node.value.value
                    rows.append((revision, path, len(revision)))
    return rows


def main() -> int:
    if not VERSIONS_DIR.is_dir():
        print(f"Missing migrations directory: {VERSIONS_DIR}", file=sys.stderr)
        return 1

    violations: list[str] = []
    for revision, path, length in _revision_ids():
        if length > ALEMBIC_VERSION_NUM_WIDTH:
            rel = path.relative_to(REPO_ROOT)
            violations.append(
                f"{rel}: revision {revision!r} is {length} chars "
                f"(max {ALEMBIC_VERSION_NUM_WIDTH})"
            )

    if violations:
        print(
            "Alembic revision id length gate failed (ISSUE-214):\n"
            + "\n".join(f"  - {line}" for line in violations),
            file=sys.stderr,
        )
        return 1

    print(
        f"Migration revision length gate passed "
        f"(max width {ALEMBIC_VERSION_NUM_WIDTH})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
