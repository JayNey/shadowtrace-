"""Docker build context guards (ISSUE-278)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT_DOCKERIGNORE = REPO_ROOT / ".dockerignore"
FRONTEND_DOCKERIGNORE = REPO_ROOT / "frontend" / ".dockerignore"
BACKEND_DOCKERFILE = REPO_ROOT / "backend" / "Dockerfile"
COMPOSE_PATH = REPO_ROOT / "infra" / "docker-compose.yml"
CHECK_SCRIPT = REPO_ROOT / "scripts" / "check_docker_build_context.py"

_BACKEND_SERVICES = frozenset({"mock-xdr", "backend", "worker", "scheduler-beat", "scheduler-worker"})


def _load_check_module():
    spec = importlib.util.spec_from_file_location("check_docker_build_context", CHECK_SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # dataclasses looks up cls.__module__ in sys.modules during decoration.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_root_and_frontend_dockerignore_exist() -> None:
    assert ROOT_DOCKERIGNORE.is_file(), "repo root must ship .dockerignore for backend build context"
    assert FRONTEND_DOCKERIGNORE.is_file(), "frontend must ship .dockerignore for SPA build context"


def test_backend_dockerfile_does_not_copy_full_backend_tree() -> None:
    text = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY backend/ ./backend/" not in text, (
        "backend/Dockerfile must not COPY the entire backend/ tree (tests/.venv leak)"
    )
    assert "COPY backend/scripts ./backend/scripts" in text
    assert "ISSUE-278" in text


def test_compose_backend_services_share_root_context() -> None:
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = data.get("services") or {}
    for name in sorted(_BACKEND_SERVICES):
        build = (services.get(name) or {}).get("build") or {}
        assert build.get("dockerfile") == "backend/Dockerfile", f"{name} must use backend/Dockerfile"
        assert build.get("context") == "..", (
            f"{name} must use repo-root context (shared, .dockerignore-filtered)"
        )


def test_compose_frontend_uses_frontend_context() -> None:
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    build = ((data.get("services") or {}).get("frontend") or {}).get("build") or {}
    assert build.get("context") == "../frontend"
    assert build.get("dockerfile") == "Dockerfile"


def test_dockerignore_validation_script_passes() -> None:
    proc = subprocess.run(
        [sys.executable, str(CHECK_SCRIPT), "--validate-dockerignore"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_matcher_excludes_worktrees_venv_variants_and_root_caches() -> None:
    mod = _load_check_module()
    matcher = mod.DockerignoreMatcher.from_file(ROOT_DOCKERIGNORE)
    for rel in (
        ".worktrees/probe/blob",
        "artifacts/out.bin",
        "backend/.venv/lib/python/site.py",
        "backend/.venv-review/lib/x",
        ".mypy_cache/3.11/foo.data",
        ".pnpm-store/v3/files/ab",
        "backend/tests/test_x.py",
        ".env.issue278-probe",
    ):
        assert matcher.excludes_path_or_ancestor(rel), f"expected exclude: {rel}"


def test_matcher_keeps_runtime_copy_sources() -> None:
    mod = _load_check_module()
    matcher = mod.DockerignoreMatcher.from_file(ROOT_DOCKERIGNORE)
    for rel in (
        "backend/app/main.py",
        "backend/scripts/load_playbook_release.py",
        "backend/uv.lock",
        "backend/pyproject.toml",
        "contracts/schemas/foo.json",
        "data/playbooks/x.yaml",
        "scripts/check_docker_build_context.py",
    ):
        assert not matcher.excludes_path_or_ancestor(rel), f"must keep in context: {rel}"


def test_backend_root_context_within_limit_clean_workspace() -> None:
    proc = subprocess.run(
        [sys.executable, str(CHECK_SCRIPT), "--context", "backend-root"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_backend_root_context_excludes_dirty_workspace_blobs() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(CHECK_SCRIPT),
            "--context",
            "backend-root",
            "--seed-dirty",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "dirty-seed OK" in proc.stdout


def test_frontend_context_within_limit() -> None:
    proc = subprocess.run(
        [sys.executable, str(CHECK_SCRIPT), "--context", "frontend"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_frontend_seed_dirty_excludes_local_markers() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(CHECK_SCRIPT),
            "--context",
            "frontend",
            "--seed-dirty",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "dirty-seed OK" in proc.stdout
    # Must not create repo-layout markers under frontend/
    assert not (REPO_ROOT / "frontend" / "backend" / ".venv").exists()
    assert not (REPO_ROOT / "frontend" / "frontend" / "node_modules").exists()


def test_context_fails_when_over_max_bytes() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(CHECK_SCRIPT),
            "--context",
            "backend-root",
            "--max-context-bytes",
            "1",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "exceeds limit" in (proc.stderr or proc.stdout)


def test_seed_dirty_fails_when_ignore_empty(tmp_path: Path) -> None:
    mod = _load_check_module()
    dockerignore = tmp_path / ".dockerignore"
    dockerignore.write_text("# empty ignore on purpose\n", encoding="utf-8")
    # Minimal tree so measure is small but seed adds 2MiB markers.
    (tmp_path / "keep.txt").write_text("ok\n", encoding="utf-8")
    profile = mod.ContextProfile(
        name="backend-root",
        root=tmp_path,
        dockerignore=dockerignore,
        max_bytes=80 * 1024 * 1024,
    )
    assert mod.check_context(profile, seed_dirty=True) == 1
