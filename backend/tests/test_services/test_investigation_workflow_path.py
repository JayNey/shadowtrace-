"""Tests for investigation workflow_path trace recording (ISSUE-103)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.services.investigation_guidance import record_investigation_workflow_path


@pytest.mark.asyncio
async def test_record_investigation_workflow_path_logs_trace() -> None:
    session_factory = AsyncMock(spec=async_sessionmaker[AsyncSession])
    log_trace = AsyncMock()
    fixed_now = datetime(2026, 8, 1, 10, 0, tzinfo=UTC)

    with (
        patch(
            "app.services.investigation_guidance.AgentTraceService",
            return_value=AsyncMock(log_trace=log_trace),
        ),
        patch("app.services.investigation_guidance.datetime") as mock_datetime,
    ):
        mock_datetime.now.return_value = fixed_now
        await record_investigation_workflow_path(
            session_factory,
            "evt-workflow-103",
            workflow_path="analysis_only",
            include_response_execution=False,
        )

    log_trace.assert_awaited_once()
    args = log_trace.await_args.args
    assert args[0] == "evt-workflow-103"
    assert args[1] == "super_agent"
    assert args[2]["workflow_path"] == "analysis_only"
    assert args[2]["include_response_execution"] is False
    assert args[3]["workflow_path"] == "analysis_only"


@pytest.mark.asyncio
async def test_record_investigation_workflow_path_full_loop() -> None:
    session_factory = AsyncMock(spec=async_sessionmaker[AsyncSession])
    log_trace = AsyncMock()

    with patch(
        "app.services.investigation_guidance.AgentTraceService",
        return_value=AsyncMock(log_trace=log_trace),
    ):
        await record_investigation_workflow_path(
            session_factory,
            "evt-full-loop",
            workflow_path="full_loop",
            include_response_execution=True,
        )

    payload = log_trace.await_args.args[2]
    assert payload["workflow_path"] == "full_loop"
    assert payload["include_response_execution"] is True
