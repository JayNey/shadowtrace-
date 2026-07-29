"""Regression golden-path integration tests (ISSUE-087)."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.state import MockXDRState
from app.services.context_service import EventContextStore
from app.services.event_service import EventService
from tests.regression.scenarios import DEMO_SCENARIOS, REGRESSION_SCENARIOS
from tests.regression.snapshot import (
    SnapshotDiffer,
    SnapshotRecorder,
    baseline_path,
    format_drifts,
    load_baseline,
)
from tests.system.helpers import ingest_scenario_event, run_rule_fallback_main_chain

pytestmark = [pytest.mark.regression, pytest.mark.integration]


@pytest.mark.usefixtures("clean_state")
@pytest.mark.parametrize("scenario_id", REGRESSION_SCENARIOS)
@pytest.mark.asyncio
async def test_regression_scenario_matches_baseline(
    scenario_id: str,
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    run_graph_investigation: object,
) -> None:
    baseline = load_baseline(scenario_id)
    if baseline is None:
        pytest.skip(
            f"missing baseline for {scenario_id!r}; run `make update-baseline` first "
            f"(expected {baseline_path(scenario_id)})"
        )

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

    recorder = SnapshotRecorder(session_factory, context_store=context_store)
    current = await recorder.record(event_id, scenario_id=scenario_id)
    drifts = SnapshotDiffer().diff(baseline, current)
    blocking = SnapshotDiffer.blocking_drifts(drifts)
    assert not blocking, format_drifts(blocking)


def test_demo_scenarios_are_subset_of_regression_registry() -> None:
    assert set(DEMO_SCENARIOS).issubset(set(REGRESSION_SCENARIOS))
