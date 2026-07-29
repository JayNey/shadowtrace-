"""Search API contract tests (ISSUE-084)."""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.api.v1.deps import get_search_service
from app.core.auth import Principal, get_principal
from app.core.config import get_settings
from app.main import app
from app.models.search import SearchResponse, SearchResultItem

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
    }
)


class _MockSearchService:
    async def search(
        self,
        q: str,
        scope: str = "all",
        page: int = 1,
        page_size: int = 20,
    ) -> SearchResponse:
        return SearchResponse(
            items=[
                SearchResultItem(
                    index="tool_call_log",
                    doc_id="call-1",
                    highlight="",
                    source_summary="[工具调用] block_ip (success)",
                    event_id="evt-1",
                )
            ],
            total=1,
            page=page,
            page_size=page_size,
            degraded=True,
        )


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    monkeypatch.setenv("OPENSEARCH_ENABLED", "false")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _clear_overrides() -> Iterator[None]:
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _hdr() -> dict[str, str]:
    return {"Authorization": "Bearer analyst-token"}


def _client() -> TestClient:
    async def _principal() -> Principal:
        return Principal(subject="analyst-1", roles=["analyst"])

    app.dependency_overrides[get_principal] = _principal
    app.dependency_overrides[get_search_service] = lambda: _MockSearchService()
    return TestClient(app)


def test_search_api_requires_auth() -> None:
    response = TestClient(app).get("/api/v1/search", params={"q": "block_ip"})
    assert response.status_code == 401


def test_search_api_degraded_fallback() -> None:
    client = _client()
    response = client.get("/api/v1/search", params={"q": "block_ip"}, headers=_hdr())
    assert response.status_code == 200
    payload = response.json()
    assert payload["degraded"] is True
    assert payload["total"] == 1
    assert payload["items"][0]["source_summary"]
    assert payload["items"][0]["event_id"] == "evt-1"


def test_search_api_invalid_scope_422() -> None:
    client = _client()
    response = client.get(
        "/api/v1/search",
        params={"q": "block_ip", "scope": "invalid-scope"},
        headers=_hdr(),
    )
    assert response.status_code == 422


def test_search_api_response_model_fields() -> None:
    client = _client()
    response = client.get(
        "/api/v1/search",
        params={"q": "block_ip", "scope": "tool-calls", "page": 2, "page_size": 10},
        headers=_hdr(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert set(payload.keys()) >= {"items", "total", "page", "page_size", "degraded"}
    assert payload["page"] == 2
    assert payload["page_size"] == 10
