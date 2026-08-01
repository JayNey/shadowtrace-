"""Crash-window matrix for durable auto-investigate intents (ISSUE-108 / #612)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.db import models as orm
from app.models.enums import EventStatus, InvestigationIntentStatus, Severity
from app.models.investigation_intent import IntentDeliveryAdmission
from app.services.auto_investigate_policy import AutoInvestigatePolicyService
from app.services.investigation_intent_service import InvestigationIntentService


@pytest.fixture(autouse=True)
def _suppress_background_intent_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        lambda: None,
    )


@pytest.mark.parametrize(
    ("initial_status", "event_status", "expected_status"),
    [
        (
            InvestigationIntentStatus.ENQUEUED,
            EventStatus.NEW,
            InvestigationIntentStatus.RETRY,
        ),
        (
            InvestigationIntentStatus.STARTED,
            EventStatus.TRIAGING,
            InvestigationIntentStatus.TERMINAL,
        ),
        (
            InvestigationIntentStatus.STARTED,
            EventStatus.NEW,
            InvestigationIntentStatus.RETRY,
        ),
    ],
    ids=["enqueued-stale-retry", "started-event-active-terminal", "started-stale-retry"],
)
@pytest.mark.asyncio
async def test_reconcile_stale_crash_window_outcomes(
    session_factory: async_sessionmaker[AsyncSession],
    initial_status: InvestigationIntentStatus,
    event_status: EventStatus,
    expected_status: InvestigationIntentStatus,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=5,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-window-{uuid4().hex[:8]}"
    event_id = f"evt-window-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=event_status.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=initial_status.value,
                    revision=1,
                    attempt=0,
                    broker_task_id="task-window",
                    updated_at=datetime.now(UTC) - timedelta(minutes=15),
                )
            )
    assert await service.reconcile_stale(limit=100) >= 0
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == expected_status.value


@pytest.mark.asyncio
async def test_stale_broker_delivery_never_reaches_started(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-stale-window-{uuid4().hex[:8]}"
    event_id = f"evt-stale-window-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id="task-current",
                )
            )
    admission = await service.mark_started(intent_id, broker_task_id="task-stale")
    assert admission is IntentDeliveryAdmission.STALE_SUPERSEDED
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.ENQUEUED.value
