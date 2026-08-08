"""Sensitive REST GET authorization matrix (ISSUE-268 / ID-SEC-002)."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.routing import APIRoute, APIRouter
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

# Representative sensitive GETs for runtime 403 coverage beyond /events.
SENSITIVE_GET_SAMPLES = (
    "/api/v1/events",
    "/api/v1/events/evt-matrix-1/evidence",
    "/api/v1/events/evt-matrix-1/audit-logs",
    "/api/v1/events/evt-matrix-1/dispositions",
    "/api/v1/search?q=test",
    "/api/v1/stats",
)


def _iter_api_routes(router_like: Any, prefix: str = "") -> Iterator[tuple[str, APIRoute]]:
    """Walk nested FastAPI ``_IncludedRouter`` trees (0.140+)."""
    if type(router_like).__name__ == "_IncludedRouter":
        ctx = router_like.include_context
        yield from _iter_api_routes(
            router_like.original_router,
            prefix + (ctx.prefix or ""),
        )
        return
    for route in getattr(router_like, "routes", ()) or ():
        if isinstance(route, APIRoute):
            yield prefix + route.path, route
        elif type(route).__name__ == "_IncludedRouter":
            ctx = route.include_context
            yield from _iter_api_routes(
                route.original_router,
                prefix + (ctx.prefix or ""),
            )
        elif isinstance(route, APIRouter):
            yield from _iter_api_routes(route, prefix)


def _collect_dependency_callables(dep: Any) -> list[Callable[..., Any]]:
    found: list[Callable[..., Any]] = []
    call = getattr(dep, "call", None)
    if callable(call):
        found.append(call)
    for child in getattr(dep, "dependencies", ()) or ():
        found.extend(_collect_dependency_callables(child))
    return found


def _route_has_read_guard(route: APIRoute) -> bool:
    for fn in _collect_dependency_callables(route.dependant):
        if fn is require_read_access:
            return True
        if getattr(fn, "__shadowtrace_read_guard__", False):
            return True
    return False


def test_sensitive_get_routes_mount_read_guard() -> None:
    """Every sensitive GET must use ReadPrincipal or require_roles."""
    missing: list[str] = []
    scanned = 0
    for path, route in _iter_api_routes(app):
        if "GET" not in (route.methods or set()):
            continue
        if not path.startswith("/api/v1/"):
            continue
        scanned += 1
        key = ("GET", path)
        if key in READ_AUTHZ_EXEMPT_GET:
            continue
        if not _route_has_read_guard(route):
            missing.append(f"{sorted(route.methods)} {path}")
    assert scanned >= 30, f"route walker under-scanned GET /api/v1 paths: {scanned}"
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
@pytest.mark.parametrize("path", SENSITIVE_GET_SAMPLES)
def test_zero_known_roles_forbidden_on_sensitive_get(
    client: TestClient, token: str, label: str, path: str
) -> None:
    resp = client.get(path, headers=_hdr(token))
    assert resp.status_code == 403, f"{label} path={path}"
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


def test_chat_zero_known_roles_forbidden_before_event_lookup(client: TestClient) -> None:
    """Sensitive chat read path must fail-closed like GET (ISSUE-268 follow-through)."""
    from app.api.v1.chat import get_event_qa_service as _real_get_event_qa_service

    calls = {"get_event": 0, "answer": 0}

    class _SpyEvents:
        async def get_event(self, event_id: str) -> object | None:
            calls["get_event"] += 1
            return object()

    class _SpyQA:
        async def answer(self, *args: object, **kwargs: object) -> None:
            calls["answer"] += 1
            raise AssertionError("qa must not run for unauthorized principal")

    async def _events() -> _SpyEvents:
        return _SpyEvents()

    async def _qa() -> _SpyQA:
        return _SpyQA()

    app.dependency_overrides[_real_get_event_service] = _events
    app.dependency_overrides[_real_get_event_qa_service] = _qa
    try:
        resp = client.post(
            "/api/v1/events/evt-matrix-1/chat",
            headers=_hdr("empty-token"),
            json={"question": "为什么高危"},
        )
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "forbidden"
        assert calls["get_event"] == 0
        assert calls["answer"] == 0
    finally:
        app.dependency_overrides.pop(_real_get_event_service, None)
        app.dependency_overrides.pop(_real_get_event_qa_service, None)
