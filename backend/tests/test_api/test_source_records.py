"""Unit tests for source-record ingest helpers (ISSUE-077 review fixes)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import OperationalError

from app.api.v1 import source_records as sr
from app.core.errors import DependencyUnavailableError, ValidationError
from app.models.enums import EventType, Severity


def test_optional_enum_accepts_valid_and_case_variants() -> None:
    assert sr._optional_enum(None, Severity, field_name="severity") is None
    assert sr._optional_enum("critical", Severity, field_name="severity") is Severity.CRITICAL
    assert sr._optional_enum("CRITICAL", Severity, field_name="severity") is Severity.CRITICAL
    assert (
        sr._optional_enum("data_exfiltration", EventType, field_name="event_type")
        is EventType.DATA_EXFILTRATION
    )


def test_optional_enum_rejects_unknown_values() -> None:
    with pytest.raises(ValidationError) as exc_info:
        sr._optional_enum("not-a-severity", Severity, field_name="severity")
    assert exc_info.value.error_code == "validation_error"
    assert exc_info.value.details["field"] == "severity"


@pytest.mark.asyncio
async def test_get_source_record_does_not_mask_db_error_for_fixture_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BrokenSession:
        async def get(self, *_args: Any, **_kwargs: Any) -> None:
            raise OperationalError("SELECT 1", {}, Exception("down"))

        async def __aenter__(self) -> _BrokenSession:
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

    def _factory() -> _BrokenSession:
        return _BrokenSession()

    monkeypatch.setattr(
        "app.core.config.get_settings",
        lambda: MagicMock(app_env="development"),
    )

    with pytest.raises(DependencyUnavailableError) as exc_info:
        await sr.get_source_record(
            "src-associated-1",
            principal=MagicMock(),
            session_factory=_factory,  # type: ignore[arg-type]
        )
    assert exc_info.value.error_code == "dependency_unavailable"
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_ingest_rejects_blank_source_product() -> None:
    body = MagicMock()
    body.normalized = {}
    body.raw_payload = {}
    body.incident_ref = None
    body.related_alert_refs = []
    body.reference = MagicMock(source_product="  ")

    with pytest.raises(ValidationError) as exc_info:
        await sr.ingest_source_record(
            body,
            principal=MagicMock(),
            event_service=AsyncMock(),
        )
    assert exc_info.value.details["field"] == "reference.source_product"
