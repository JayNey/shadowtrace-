"""ISSUE-269: evidence raw_data sanitization and API safe projection tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.agents.evidence_parser import EvidenceParser
from app.api.v1.deps import _get_context_store, get_event_service
from app.core.auth import Principal, get_principal
from app.main import app
from app.models.agent_io import CollectionStatus
from app.models.context import EventContext
from app.models.enums import EvidenceSource
from app.models.evidence import Evidence
from app.models.tool_meta import ToolResult, ToolResultStatus
from app.services.evidence_safe_projection import (
    EVIDENCE_SAFE_PROJECTION_VERSION,
    EvidenceSanitizerError,
    project_evidence_for_api,
    sanitize_evidence_for_persist,
    sanitize_evidence_raw_data,
)


def _login_record(**extra: Any) -> dict[str, Any]:
    base = {
        "record_id": "id-sec-1",
        "account": "ops-user",
        "src_ip": "10.20.30.23",
        "logged_at": "2024-06-15T09:01:00Z",
        "event_type": "login",
        "result": "success",
    }
    base.update(extra)
    return base


def test_sanitize_strips_disallowed_fields_and_redacts_denied_metadata() -> None:
    record = _login_record(
        token="must-not-persist",
        Authorization="Bearer secret-token-123",
        headers={"Cookie": "session=abc", "X-Forwarded-For": "1.2.3.4"},
        vendor_metadata={"region": "cn-north", "token": "must-redact"},
    )
    cleaned = sanitize_evidence_raw_data("query_account_login", record)
    assert "token" not in cleaned
    assert "Authorization" not in cleaned
    assert "headers" not in cleaned
    assert "vendor_metadata" not in cleaned
    assert cleaned["account"] == "ops-user"


def test_sanitize_redacts_nested_secrets_inside_allowed_fields() -> None:
    record = _login_record(
        note="nested secret token=super-secret and api_key=abc",
        cmdline="curl -H 'Authorization: Bearer nested-secret'",
    )
    cleaned = sanitize_evidence_raw_data("query_account_login", record)
    assert "super-secret" not in cleaned["note"]
    assert "nested-secret" not in cleaned["cmdline"]
    assert "[REDACTED]" in cleaned["note"]


def test_sanitize_redacts_case_insensitive_denied_keys() -> None:
    record = _login_record(
        Authorization="Bearer xyz",
        PASSWORD="hunter2",
        refreshToken="tok-2",
    )
    cleaned = sanitize_evidence_raw_data("query_account_login", record)
    assert "Authorization" not in cleaned
    assert "PASSWORD" not in cleaned
    assert "refreshToken" not in cleaned


def test_sanitize_redacts_pii_in_string_values() -> None:
    record = _login_record(note="contact alice@example.com or 13800138000")
    cleaned = sanitize_evidence_raw_data("query_account_login", record)
    assert "alice@example.com" not in cleaned["note"]
    assert "13800138000" not in cleaned["note"]
    assert "[REDACTED]" in cleaned["note"]


def test_sanitize_fail_closed_on_depth_budget() -> None:
    # Nest using an allowlisted key so depth policy is reached (ISSUE-269).
    record: dict[str, Any] = {"result": {}}
    current = record["result"]
    assert isinstance(current, dict)
    for _ in range(30):
        deeper: dict[str, Any] = {}
        current["result"] = deeper
        current = deeper
    with pytest.raises(EvidenceSanitizerError, match="depth"):
        sanitize_evidence_raw_data("query_account_login", record)


def test_sanitize_fail_closed_on_payload_budget() -> None:
    record = _login_record(note="x" * (40_000))
    with pytest.raises(EvidenceSanitizerError, match="payload"):
        sanitize_evidence_raw_data("query_account_login", record)


def test_sanitize_strips_unknown_nested_keys_under_allowed_parent() -> None:
    record = _login_record(
        result={"account": "ops-user", "sid": "deadbeef-session", "token": "nope"}
    )
    cleaned = sanitize_evidence_raw_data("query_account_login", record)
    assert cleaned["result"]["account"] == "ops-user"
    assert "sid" not in cleaned["result"]
    assert "token" not in cleaned["result"]


def test_parser_redacts_secrets_in_description_and_related_entities() -> None:
    parser = EvidenceParser()
    tool_result = ToolResult(
        call_id="call-desc-sidechannel",
        tool_name="query_account_login",
        provider_name="evidence_projection",
        status=ToolResultStatus.SUCCESS,
        confidence=0.8,
        data={
            "records": [
                _login_record(account="Bearer leak-token-999"),
            ],
            "source_references": [],
        },
        execution_time_ms=3,
    )
    rows = parser.parse("query_account_login", tool_result, event_id="evt-sec-desc")
    assert len(rows) == 1
    assert "leak-token-999" not in rows[0].description
    assert all("leak-token-999" not in item for item in rows[0].related_entities)
    assert "leak-token-999" not in str(rows[0].raw_data)
    assert "[REDACTED]" in rows[0].description or "Bearer" not in rows[0].description


def test_parser_persists_sanitized_raw_data_not_full_provider_record() -> None:
    parser = EvidenceParser()
    tool_result = ToolResult(
        call_id="call-sanitize",
        tool_name="query_account_login",
        provider_name="evidence_projection",
        status=ToolResultStatus.SUCCESS,
        confidence=0.8,
        data={
            "records": [
                _login_record(
                    token="must-not-persist",
                    Authorization="Bearer xyz",
                )
            ],
            "source_references": [],
        },
        execution_time_ms=3,
    )
    rows = parser.parse("query_account_login", tool_result, event_id="evt-sec")
    assert len(rows) == 1
    assert "token" not in rows[0].raw_data
    assert "Authorization" not in rows[0].raw_data
    assert rows[0].raw_data["account"] == "ops-user"


def test_project_evidence_for_api_omits_raw_data() -> None:
    item = Evidence(
        evidence_id="evd-1",
        event_id="evt-1",
        source=EvidenceSource.IDENTITY,
        evidence_type="login",
        description="test",
        confidence=0.9,
        raw_data={"token": "secret", "account": "ops"},
    )
    projected = project_evidence_for_api(item)
    dumped = projected.model_dump(mode="json")
    assert "raw_data" not in dumped
    assert projected.schema_version == EVIDENCE_SAFE_PROJECTION_VERSION


def test_persist_re_sanitizes_defense_in_depth() -> None:
    dirty = Evidence(
        evidence_id="evd-2",
        event_id="evt-2",
        source=EvidenceSource.IDENTITY,
        evidence_type="login",
        description="账号 Bearer leak-token-persist 登录",
        confidence=0.5,
        related_entities=["Bearer leak-token-persist"],
        raw_data={"account": "ops", "Authorization": "Bearer leak"},
    )
    clean = sanitize_evidence_for_persist(dirty)
    assert "Authorization" not in clean.raw_data
    assert clean.raw_data["account"] == "ops"
    assert "leak-token-persist" not in clean.description
    assert all("leak-token-persist" not in item for item in clean.related_entities)


class _EventService:
    async def get_event(self, event_id: str) -> object | None:
        return object()


class _ContextStore:
    def __init__(self, evidence_output: dict[str, Any]) -> None:
        self._evidence_output = evidence_output

    async def get_full_context(self, event_id: str) -> EventContext:
        return EventContext(evidence_output=self._evidence_output)


def test_api_evidence_never_returns_raw_data_even_from_legacy_context() -> None:
    evidence_output = {
        "evidence_list": [
            {
                "evidence_id": "evd-legacy",
                "event_id": "evt-api-269",
                "source": EvidenceSource.IDENTITY.value,
                "evidence_type": "login",
                "description": "legacy row",
                "confidence": 0.7,
                "timestamp": datetime(2024, 6, 15, 9, 0, tzinfo=UTC).isoformat(),
                "related_entities": [],
                "source_ref": None,
                "raw_data": {
                    "account": "ops",
                    "Authorization": "Bearer legacy-secret",
                    "cookie": "sid=deadbeef",
                },
                "mitre_technique": None,
                "is_conflicting": False,
            }
        ],
        "conflicts": [],
        "gaps": [],
        "success_sources": [EvidenceSource.IDENTITY.value],
        "failed_sources": [],
        "overall_confidence": 0.7,
        "collection_status": CollectionStatus.COMPLETED.value,
    }

    async def _principal() -> Principal:
        return Principal(subject="analyst-1", roles=["analyst"])

    async def _event_service() -> _EventService:
        return _EventService()

    def _context_store() -> _ContextStore:
        return _ContextStore(evidence_output)

    app.dependency_overrides[get_principal] = _principal
    app.dependency_overrides[get_event_service] = _event_service
    app.dependency_overrides[_get_context_store] = _context_store
    try:
        response = TestClient(app).get("/api/v1/events/evt-api-269/evidence")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["evidence_list"]
    item = payload["evidence_list"][0]
    assert "raw_data" not in item
    assert item["schema_version"] == EVIDENCE_SAFE_PROJECTION_VERSION
    body = response.text
    assert "legacy-secret" not in body
    assert "deadbeef" not in body
