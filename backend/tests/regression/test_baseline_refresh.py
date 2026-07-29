"""One-shot baseline refresh (invoked via ``make update-baseline``)."""

from __future__ import annotations

import os

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.redis_client import RedisClient
from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.state import MockXDRState
from app.services.context_service import EventContextStore
from app.services.event_service import EventService
from tests.integration.integration_fixtures import (
    _clear_shadowtrace_keys,
    _truncate_business_tables,
)
from tests.regression.scenarios import REGRESSION_SCENARIOS
from tests.regression.snapshot import SnapshotRecorder, save_baseline
from tests.system.helpers import ingest_scenario_event, run_rule_fallback_main_chain

pytestmark = [pytest.mark.baseline_refresh, pytest.mark.integration]


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
) -> None:
    if os.environ.get("UPDATE_BASELINE") != "1":
        pytest.skip("set UPDATE_BASELINE=1 to refresh regression baselines")

    recorder = SnapshotRecorder(session_factory, context_store=context_store)
    for scenario_id in REGRESSION_SCENARIOS:
        await _truncate_business_tables(session_factory)
        await _clear_shadowtrace_keys(redis_client)

        event_id = await ingest_scenario_event(
            scenario_id=scenario_id,
            source_adapter=source_adapter,
            source_ingester=source_ingester,
            event_service=event_service,
            mock_xdr_state=mock_xdr_state,
            session_factory=session_factory,
        )
        await run_rule_fallback_main_chain(
            event_id=event_id,
            run_graph_investigation=run_graph_investigation,
            scenario_id=scenario_id,
        )
        snapshot = await recorder.record(event_id, scenario_id=scenario_id)
        save_baseline(scenario_id, snapshot)

    assert len(REGRESSION_SCENARIOS) == 8
