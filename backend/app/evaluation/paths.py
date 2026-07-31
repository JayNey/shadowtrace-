"""Path normalization for portable evaluation artifacts (ISSUE-105 / #608)."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def repo_relative_manifest_path(path: Path, *, repo_root: Path | None = None) -> str:
    """Return a repo-relative POSIX path for cross-environment artifact comparison."""
    root = (repo_root or REPO_ROOT).resolve()
    resolved = path.resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return resolved.name


__all__ = ["REPO_ROOT", "repo_relative_manifest_path"]
