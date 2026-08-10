"""ISSUE-300 unit tests: deterministic rejection mark helpers (no DB required)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.enums import OutboxDeliveryStatus, WritebackStatus
from app.services.disposition_sync_service import DispositionSyncService


def _service() -> DispositionSyncService:
    return DispositionSyncService(
        session_factory=AsyncMock(),  # type: ignore[arg-type]
        context_store=AsyncMock(),  # type: ignore[arg-type]
        adapter_registry=SimpleNamespace(get=lambda _name: SimpleNamespace(name="mock")),  # type: ignore[arg-type]
        outbound_guard=AsyncMock(),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_mark_deterministic_rejection_skips_non_leased_outbox() -> None:
    """Stale lease must not crash the worker via assert."""
    outbox = SimpleNamespace(
        outbox_id="obx-1",
        delivery_status=OutboxDeliveryStatus.READY.value,
        event_id="evt-1",
        writeback_id="wbk-1",
        action_id="act-1",
    )
    session = MagicMock()
    session.scalar = AsyncMock(return_value=outbox)
    session.begin = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(), __aexit__=AsyncMock()))
    session_factory = MagicMock()
    session_factory.return_value.__aenter__ = AsyncMock(return_value=session)
    session_factory.return_value.__aexit__ = AsyncMock()

    service = _service()
    service._session_factory = session_factory
    service._sync_writeback_summary = AsyncMock()
    service._maybe_resume = AsyncMock()

    await service._mark_delivery_deterministic_rejection(
        "obx-1",
        error_code="not_found",
        error_detail="missing object",
    )

    service._sync_writeback_summary.assert_not_called()


@pytest.mark.asyncio
async def test_mark_delivery_paused_unknown_skips_non_leased_outbox() -> None:
    outbox = SimpleNamespace(
        outbox_id="obx-2",
        delivery_status=OutboxDeliveryStatus.PAUSED.value,
        event_id="evt-2",
        writeback_id="wbk-2",
        action_id="act-2",
    )
    session = MagicMock()
    session.scalar = AsyncMock(return_value=outbox)
    session.begin = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(), __aexit__=AsyncMock()))
    session_factory = MagicMock()
    session_factory.return_value.__aenter__ = AsyncMock(return_value=session)
    session_factory.return_value.__aexit__ = AsyncMock()

    service = _service()
    service._session_factory = session_factory
    service._sync_writeback_summary = AsyncMock()
    service._maybe_resume = AsyncMock()

    await service._mark_delivery_paused_unknown(
        "obx-2",
        error_code="delivery_outcome_unknown",
        error_detail="RuntimeError: simulated",
    )

    service._sync_writeback_summary.assert_not_called()


@pytest.mark.asyncio
async def test_mark_delivery_conflict_skips_non_leased_outbox() -> None:
    outbox = SimpleNamespace(
        outbox_id="obx-3",
        delivery_status=OutboxDeliveryStatus.DEAD_LETTER.value,
        event_id="evt-3",
        writeback_id="wbk-3",
        action_id="act-3",
    )
    session = MagicMock()
    session.scalar = AsyncMock(return_value=outbox)
    session.begin = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(), __aexit__=AsyncMock()))
    session_factory = MagicMock()
    session_factory.return_value.__aenter__ = AsyncMock(return_value=session)
    session_factory.return_value.__aexit__ = AsyncMock()

    service = _service()
    service._session_factory = session_factory
    service._sync_writeback_summary = AsyncMock()
    service._maybe_resume = AsyncMock()

    await service._mark_delivery_conflict(
        "obx-3",
        error_code="version_conflict",
        error_detail="stale token",
    )

    service._sync_writeback_summary.assert_not_called()
