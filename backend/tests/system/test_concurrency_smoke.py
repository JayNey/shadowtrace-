"""ISSUE-086 concurrent investigation smoke — 10 events, isolated contexts."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from httpx import ASGITransport
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRSourceAdapter
from app.core.redis_client import RedisClient
from app.data_generators.scenarios import build_scenario
from app.db import models as orm
from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.api import create_app
from app.mock_xdr.state import MockXDRState
from app.models.enums import EventStatus, FinalVerdict
from app.orchestration.lease import LEASE_KEY_PREFIX, EventLease, generate_owner_id
from app.services.context_service import EventContextStore
from app.services.event_service import EventService
from app.services.evidence_projection import EvidenceProjection, bind_evidence_projection
from tests.integration.conftest import FailingLLMClient
from tests.system.helpers import ALL_SOURCE_KINDS

pytestmark = [pytest.mark.system, pytest.mark.integration]

CONCURRENT_COUNT = 10

SCENARIO_IDS = (
    "insider_data_exfiltration",
    "host_compromise",
    "lateral_movement",
    "malicious_process",
    "insider_privilege_abuse",
    "account_anomaly_fp",
    "suspicious_domain_access",
    "other_unclassified",
    "host_compromise",
    "malicious_process",
)


async def _event_id_for_scenario_incident(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    connector_id: str,
    source_object_id: str,
) -> str:
    async with session_factory() as session:
        event_id = await session.scalar(
            select(orm.SecurityEvent.event_id).where(
                orm.SecurityEvent.creation_source_ref["connector_id"].as_string() == connector_id,
                orm.SecurityEvent.creation_source_ref["source_object_id"].as_string()
                == source_object_id,
            )
        )
    assert event_id is not None, (
        f"no event for connector={connector_id!r} source_object_id={source_object_id!r}"
    )
    return event_id


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_ten_concurrent_events_reach_terminal_state_without_cross_talk(
    session_factory: async_sessionmaker[AsyncSession],
    source_ingester: SourceIngester,
    event_service: EventService,
    context_store: EventContextStore,
    build_super_agent: object,
    redis_client: RedisClient,
) -> None:
    lease = EventLease(redis_client)

    async def _ingest_one(index: int) -> tuple[str, str]:
        scenario_id = SCENARIO_IDS[index]
        scenario = build_scenario(scenario_id, seed=42 + index, instance=index)
        incident = scenario.incidents[0]
        connector_id = incident.reference.connector_id
        source_object_id = incident.reference.source_object_id

        state = MockXDRState()
        state.load_scenario(scenario)
        transport = ASGITransport(app=create_app(state=state))
        async with httpx.AsyncClient(
            transport=transport,
            base_url=f"http://mock-xdr-{index}",
            timeout=30.0,
        ) as client:
            adapter = MockXDRSourceAdapter(
                base_url=f"http://mock-xdr-{index}",
                read_token="mock-read-token",
                write_token="mock-write-token",
                client=client,
                max_retries=0,
            )
            summary = await source_ingester.poll(adapter, ALL_SOURCE_KINDS, batch_size=10)
            assert summary.rejected == 0, summary.errors
            assert summary.accepted >= 1, summary.model_dump()
            event_id = await _event_id_for_scenario_incident(
                session_factory,
                connector_id=connector_id,
                source_object_id=source_object_id,
            )
            return event_id, scenario_id

    async def _investigate(event_id: str, scenario_id: str) -> str:
        owner_id = generate_owner_id()
        acquired = await lease.acquire(event_id, owner_id)
        assert acquired is True, f"lease conflict acquiring {event_id}"
        agent, projection = build_super_agent(  # type: ignore[operator]
            llm_client=FailingLLMClient(),
            scenario_id=scenario_id,
            lease=lease,
        )
        try:
            with bind_evidence_projection(EvidenceProjection(session_factory)):
                await agent.investigate(event_id, lease_acquired=True)
        finally:
            await lease.release(event_id, owner_id)
        return event_id

    seeded = await asyncio.gather(*[_ingest_one(i) for i in range(CONCURRENT_COUNT)])
    assert len({event_id for event_id, _ in seeded}) == CONCURRENT_COUNT

    event_ids_raw = await asyncio.gather(
        *[_investigate(event_id, scenario_id) for event_id, scenario_id in seeded],
        return_exceptions=True,
    )
    failures: list[tuple[str, BaseException]] = []
    event_ids: list[str] = []
    for item in event_ids_raw:
        if isinstance(item, BaseException):
            failures.append(("investigate", item))
        else:
            event_ids.append(item)
    if failures:
        details = "\n".join(f"{label}: {exc!r}" for label, exc in failures)
        pytest.fail(f"{len(failures)}/{CONCURRENT_COUNT} investigate failures:\n{details}")
    assert len(set(event_ids)) == CONCURRENT_COUNT

    for event_id in event_ids:
        event = await event_service.get_event(event_id)
        assert event is not None
        assert event.status in {EventStatus.REPORTING, EventStatus.CLOSED}

    # EventContext isolation: snapshot and journal rows stay scoped per event_id.
    for event_id in event_ids:
        ctx_event = await context_store.get(event_id, "event")
        assert ctx_event is not None
        assert ctx_event.get("event_id") == event_id

    async with session_factory() as session:
        for event_id in event_ids:
            journal_event_ids = (
                await session.scalars(
                    select(orm.EventContextJournal.event_id).where(
                        orm.EventContextJournal.event_id == event_id
                    )
                )
            ).all()
            assert journal_event_ids, f"missing context journal for {event_id}"
            assert all(row_id == event_id for row_id in journal_event_ids)

    for event_id in event_ids:
        event = await event_service.get_event(event_id)
        assert event is not None
        if event.status is EventStatus.REPORTING:
            assert event.final_verdict in {
                FinalVerdict.CONFIRMED_THREAT,
                FinalVerdict.NONE,
                FinalVerdict.POSSIBLE_FALSE_POSITIVE,
            }

    client = redis_client.get_client()
    for event_id in event_ids:
        holder = await client.get(f"{LEASE_KEY_PREFIX}{event_id}")
        assert holder is None, f"orphan lease holder for {event_id}: {holder!r}"
