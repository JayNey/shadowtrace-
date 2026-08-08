"""Sensitive REST GET authorization matrix (ISSUE-268 / ID-SEC-002)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.v1.deps import get_disposition_sync as _real_get_disposition_sync
from app.api.v1.deps import get_event_service as _real_get_event_service
from app.api.v1.deps import get_state_machine as _real_get_state_machine
from app.core.auth import require_read_access
from app.core.config import get_settings
from app.main import app
from tests.test_api.test_contracts import (
    _MockDispositionSyncService,
    _MockEventService,
    _MockStateMachine,
)

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
        "empty-token": {"subject": "empty-1", "roles": []},
        "viewer-token": {"subject": "viewer-1", "roles": ["viewer"]},
    }
)

# Non-sensitive probes stay reachable without known roles.
READ_AUTHZ_EXEMPT_GET = {
    ("GET", "/api/v1/health"),
}


def _collect_dependency_callables(dep: Any) -> list[Callable[..., Any]]:
    found: list[Callable[..., Any]] = []
    call = getattr(dep, "call", None)
    if callable(call):
        found.append(call)
    for child in getattr(dep, "dependencies", ()) or ():
        found.extend(_collect_dependency_callables(child))
    return found


def _route_has_read_guard(route: APIRoute) -> bool:
    callables = _collect_dependency_callables(route.dependant)
    for fn in callables:
        if fn is require_read_access:
            return True
        # ``require_roles`` installs an inner ``_dep`` checker per route.
        if getattr(fn, "__name__", "") == "_dep":
            return True
    return False


def test_sensitive_get_routes_mount_read_guard() -> None:
    """Every sensitive GET must use ReadPrincipal or require_roles."""
    missing: list[str] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if "GET" not in route.methods:
            continue
        path = route.path
        if not path.startswith("/api/v1/"):
            continue
        key = ("GET", path)
        if key in READ_AUTHZ_EXEMPT_GET:
            continue
        if not _route_has_read_guard(route):
            missing.append(f"{route.methods} {path}")
    assert not missing, "sensitive GET routes missing read guard:\n" + "\n".join(sorted(missing))


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client() -> TestClient:
    async def _mock_event_service() -> _MockEventService:
        return _MockEventService()

    async def _mock_state_machine() -> _MockStateMachine:
        return _MockStateMachine()

    async def _mock_disposition_sync() -> _MockDispositionSyncService:
        return _MockDispositionSyncService()

    app.dependency_overrides[_real_get_event_service] = _mock_event_service
    app.dependency_overrides[_real_get_state_machine] = _mock_state_machine
    app.dependency_overrides[_real_get_disposition_sync] = _mock_disposition_sync
    yield TestClient(app)
    app.dependency_overrides.pop(_real_get_event_service, None)
    app.dependency_overrides.pop(_real_get_state_machine, None)
    app.dependency_overrides.pop(_real_get_disposition_sync, None)


class _ListEventsSpy(_MockEventService):
    list_calls = 0

    async def list_events(self, **kwargs: object) -> Any:
        type(self).list_calls += 1
        return await super().list_events(**kwargs)


@pytest.fixture
def spy_client() -> TestClient:
    async def _mock_event_service() -> _ListEventsSpy:
        return _ListEventsSpy()

    _ListEventsSpy.list_calls = 0
    app.dependency_overrides[_real_get_event_service] = _mock_event_service
    yield TestClient(app)
    app.dependency_overrides.pop(_real_get_event_service, None)


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize(
    ("token", "label"),
    [
        ("empty-token", "empty roles"),
        ("viewer-token", "unknown-only roles"),
    ],
)
def test_zero_known_roles_forbidden_on_sensitive_get(
    client: TestClient, token: str, label: str
) -> None:
    resp = client.get("/api/v1/events", headers=_hdr(token))
    assert resp.status_code == 403, label
    assert resp.json()["error_code"] == "forbidden"


def test_known_role_still_reads_events(client: TestClient) -> None:
    resp = client.get("/api/v1/events", headers=_hdr("analyst-token"))
    assert resp.status_code == 200


def test_reject_before_event_store_query(spy_client: TestClient) -> None:
    resp = spy_client.get("/api/v1/events", headers=_hdr("empty-token"))
    assert resp.status_code == 403
    assert _ListEventsSpy.list_calls == 0


def test_trusted_proxy_empty_roles_forbidden(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRUSTED_AUTH_PROXY_ENABLED", "true")
    monkeypatch.setenv("TRUSTED_PROXY_ALLOWLIST", "testclient")
    get_settings.cache_clear()

    resp = client.get(
        "/api/v1/events",
        headers={"X-Auth-Subject": "proxied-user", "X-Auth-Roles": ""},
    )
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "forbidden"


def test_trusted_proxy_unknown_roles_forbidden(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRUSTED_AUTH_PROXY_ENABLED", "true")
    monkeypatch.setenv("TRUSTED_PROXY_ALLOWLIST", "testclient")
    get_settings.cache_clear()

    resp = client.get(
        "/api/v1/events",
        headers={"X-Auth-Subject": "proxied-user", "X-Auth-Roles": "superuser,root"},
    )
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "forbidden"


def test_health_stays_unauthenticated(client: TestClient) -> None:
    resp = client.get("/api/v1/health")
    assert resp.status_code in {200, 503}
