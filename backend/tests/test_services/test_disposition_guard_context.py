"""Disposition guard context helper tests (ISSUE-224)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.disposition_guard_context import resolve_approved_action_ids


@pytest.mark.asyncio
async def test_resolve_approved_action_ids_returns_sorted_unique_ids() -> None:
    session = AsyncMock()
    session.scalars.return_value = MagicMock(
        all=MagicMock(return_value=["act-b", "act-a", "act-b"]),
    )

    result = await resolve_approved_action_ids(
        session,
        event_id="evt-1",
        plan_revision=2,
    )

    assert result == ["act-a", "act-b"]
    session.scalars.assert_awaited_once()
