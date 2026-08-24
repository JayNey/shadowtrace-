"""Unit tests for event detail ``_db_read`` fail-closed behaviour."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from app.core.errors import DependencyUnavailableError


class _BoomSession:
    async def __aenter__(self) -> Any:
        raise TimeoutError("db timeout")

    async def __aexit__(self, *_args: object) -> None:
        return None


@pytest.mark.asyncio
async def test_db_read_transient_error_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.v1 import events as events_mod

    monkeypatch.setattr(events_mod, "_try_get_session_factory", lambda: lambda: _BoomSession())
    table = MagicMock()
    table.__tablename__ = "event_audit_log"

    with pytest.raises(DependencyUnavailableError, match="database query failed") as exc_info:
        await events_mod._db_read("evt-db-timeout", table, order_by=MagicMock())

    assert exc_info.value.details.get("transient") is True
    assert exc_info.value.details.get("event_id") == "evt-db-timeout"
