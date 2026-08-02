"""Compose must not hardcode LLM_MODE over env_file (ISSUE-106 / #609)."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_PATH = REPO_ROOT / "infra" / "docker-compose.yml"


def test_compose_does_not_hardcode_llm_mode() -> None:
    content = COMPOSE_PATH.read_text(encoding="utf-8")
    assert "LLM_MODE:" not in content, (
        "infra/docker-compose.yml must not set LLM_MODE in environment:; "
        "use .env / env_file so backend and worker share the same LLM config."
    )


def test_compose_services_use_env_file_for_backend_and_workers() -> None:
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = data.get("services") or {}
    for name in ("backend", "worker", "scheduler-worker"):
        service = services.get(name)
        assert service is not None, f"missing service {name}"
        env_files = service.get("env_file") or []
        assert env_files, f"{name} must load env_file for LLM_* overrides"
