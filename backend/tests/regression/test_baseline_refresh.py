"""One-shot baseline refresh (invoked via ``make update-baseline``)."""

from __future__ import annotations

import os

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.redis_client import RedisClient
from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.state import MockXDRState
from app.services.context_service import EventContextStore
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService
from app.services.event_service import EventService
from app.services.state_machine_service import StateMachineService
from tests.regression.helpers import ingest_and_run_golden_chain, reset_regression_state
from tests.regression.scenarios import REGRESSION_SCENARIOS
from tests.regression.snapshot import SnapshotRecorder, save_baseline

pytestmark = [
    pytest.mark.baseline_refresh,
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("UPDATE_BASELINE") != "1"
        or os.environ.get("UPDATE_BASELINE_CONFIRM") != "ISSUE-087",
        reason="baseline refresh requires UPDATE_BASELINE=1 and UPDATE_BASELINE_CONFIRM=ISSUE-087",
    ),
]


@pytest.mark.asyncio
async def test_refresh_all_regression_baselines(
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    redis_client: RedisClient,
    run_graph_investigation: object,
    event_disposition_service: EventDispositionService,
    disposition_sync_service: DispositionSyncService,
    state_machine_service: StateMachineService,
) -> None:
    recorder = SnapshotRecorder(session_factory, context_store=context_store)
    for scenario_id in REGRESSION_SCENARIOS:
        await reset_regression_state(session_factory, redis_client)

        event_id = await ingest_and_run_golden_chain(
            scenario_id=scenario_id,
            source_adapter=source_adapter,
            source_ingester=source_ingester,
            event_service=event_service,
            mock_xdr_state=mock_xdr_state,
            session_factory=session_factory,
            run_graph_investigation=run_graph_investigation,
            context_store=context_store,
            event_disposition_service=event_disposition_service,
            disposition_sync_service=disposition_sync_service,
            state_machine_service=state_machine_service,
        )
        snapshot = await recorder.record(event_id, scenario_id)
        save_baseline(scenario_id, snapshot)

    assert len(REGRESSION_SCENARIOS) == 8
