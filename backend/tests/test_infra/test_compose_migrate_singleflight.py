"""Compose DB migration singleflight policy (ISSUE-238)."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_PATH = REPO_ROOT / "infra" / "docker-compose.yml"

_BACKEND_DOCKERFILE = "backend/Dockerfile"
_MIGRATE_RUNNER = "backend"
_WORKER_SERVICES = frozenset({"worker", "scheduler-beat", "scheduler-worker"})


def _uses_backend_dockerfile(service: dict) -> bool:
    build = service.get("build")
    if isinstance(build, dict):
        return build.get("dockerfile") == _BACKEND_DOCKERFILE
    return False


def _compose_services() -> dict:
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = data.get("services")
    assert isinstance(services, dict), "docker-compose.yml must define services"
    return services


def _service_env(name: str) -> dict[str, str]:
    service = _compose_services()[name]
    env = service.get("environment") or {}
    assert isinstance(env, dict), f"{name}.environment must be a mapping"
    return {str(k): str(v) for k, v in env.items()}


def test_backend_is_the_only_compose_migration_runner() -> None:
    services = _compose_services()
    for name, service in services.items():
        if not _uses_backend_dockerfile(service):
            continue
        env = service.get("environment") or {}
        assert isinstance(env, dict), f"{name}.environment must be a mapping"
        skip = str(env.get("SKIP_DB_MIGRATE", "")).lower() == "true"
        if name == _MIGRATE_RUNNER:
            assert not skip, "backend must run alembic on startup"
        else:
            assert skip, (
                f"{name} uses {_BACKEND_DOCKERFILE} and must set SKIP_DB_MIGRATE=true "
                "(only backend runs alembic)"
            )


def test_celery_services_wait_for_backend_healthy() -> None:
    services = _compose_services()
    for name in sorted(_WORKER_SERVICES):
        depends_on = services[name].get("depends_on") or {}
        assert isinstance(depends_on, dict), f"{name}.depends_on must be a mapping"
        backend_dep = depends_on.get(_MIGRATE_RUNNER)
        assert backend_dep is not None, f"{name} must depend on backend"
        assert backend_dep.get("condition") == "service_healthy", (
            f"{name} must wait for backend health (migrations complete)"
        )


def test_worker_services_skip_db_migrate_env() -> None:
    for name in sorted(_WORKER_SERVICES):
        assert _service_env(name)["SKIP_DB_MIGRATE"] == "true"
