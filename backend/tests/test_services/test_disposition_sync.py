"""DispositionSyncService tests (ISSUE-059).

Requires Compose PostgreSQL (+ Redis for context). Run from ``backend/``:

    pytest tests/test_services/test_disposition_sync.py -v
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from httpx import ASGITransport
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.adapters.mock_xdr import MockXDRDispositionAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.agents.verify_agent import _action_from_row
from app.core.errors import (
    InvalidStateTransitionError,
    ValidationError,
    WritebackConflictError,
    WritebackUnsupportedError,
)
from app.core.guardrails import OutboundDispositionGuard
from app.data_generators.scenarios import build_scenario
from app.db import models as orm
from app.mock_xdr.api import create_app
from app.mock_xdr.state import MockXDRState
from app.models.action import Action
from app.models.disposition import (
    DispositionCommand,
    DispositionReceipt,
    SourceObjectLocator,
    TargetWritebackResult,
)
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    ConfirmationEvidence,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionJobStatus,
    ExecutionOwner,
    ExecutionSubstate,
    FinalVerdict,
    OutboxDeliveryStatus,
    Severity,
    SourceDisposition,
    SourceObjectKind,
    TargetExecutionStatus,
    TargetWritebackStatus,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.execution import ActionExecutionJob, TargetExecutionResult
from app.models.ids import new_disposition_id
from app.models.source import SourceReference
from app.services.context_service import (
    EventContextStore,
    append_context_journal_in_session,
    event_summary_from_security_event,
    unwrap_journal_value,
)
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_sync_service import (
    OUTBOX_SUPERSEDED_ERROR_CODE,
    DispositionSyncService,
    OutboxWorker,
    WritebackLookupKind,
)
from tests.test_services._mock_xdr_test_helpers import (
    SCENARIO_INCIDENT_ID,
    fetch_mock_concurrency_token,
)

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated() -> None:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)

    async def _probe() -> None:
        try:
            async with engine.connect() as conn:
                await conn.execute(select(1))
        except Exception as exc:  # noqa: BLE001
            await engine.dispose()
            pytest.skip(f"PostgreSQL not reachable: {exc}")

    import asyncio

    asyncio.run(_probe())
    command.upgrade(_alembic_config(), "head")
    asyncio.run(engine.dispose())


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(select(1))
    except Exception as exc:  # noqa: BLE001
        await engine.dispose()
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def redis_client():
    from app.core.redis_client import RedisClient

    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.skip("Redis not reachable; start Compose redis first")
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def store(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
) -> EventContextStore:
    return EventContextStore(redis_client, session_factory)


@pytest_asyncio.fixture
async def mock_xdr_state() -> MockXDRState:
    state = MockXDRState()
    state.load_scenario(build_scenario("insider_data_exfiltration", seed=42))
    return state


@pytest_asyncio.fixture
async def mock_xdr_client(mock_xdr_state: MockXDRState) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(state=mock_xdr_state)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://mock-xdr",
        timeout=30.0,
    ) as client:
        yield client


@pytest_asyncio.fixture
async def cleanup(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    yield
    async with session_factory() as session:
        async with session.begin():
            for table in (
                orm.ApprovalPublication,
                orm.ApprovalRecordORM,
                orm.MemoryAccessAuditLog,
                orm.EventAuditLog,
                orm.EventContextJournal,
                orm.EventContextFieldVersion,
                orm.ActionTargetResult,
                orm.ActionExecutionJob,
                orm.GraphResumeIntent,
                orm.DispositionReceipt,
                orm.DispositionOutbox,
                orm.Action,
                orm.Evidence,
                orm.Report,
                orm.SourceEventLink,
                orm.SourceObject,
                orm.SecurityEvent,
            ):
                await session.execute(delete(table))


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _locator(*, object_id: str = "88442201") -> SourceObjectLocator:
    return SourceObjectLocator(
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_kind=SourceObjectKind.INCIDENT,
        source_object_id=object_id,
    )


def _settings_overlay(**overrides: object) -> Settings:
    from app.core.config import Settings, get_settings

    payload = get_settings().model_dump()
    payload.update(overrides)
    return Settings.model_construct(**payload)


async def _seed_event_action_source(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
) -> tuple[str, str, str, SourceObjectLocator, str]:
    sfx = _sfx()
    event_id = f"evt-sync-{sfx}"
    action_id = f"act-{sfx}"
    connector_id = "conn-disposition"
    source_record_id = f"src-{sfx}"
    object_id = SCENARIO_INCIDENT_ID
    locator = _locator(object_id=object_id)
    concurrency_token = await fetch_mock_concurrency_token(mock_xdr_client, object_id=object_id)
    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id=connector_id,
        source_object_id=object_id,
        ingested_at=datetime.now(UTC),
    )
    async with session_factory() as session:
        async with session.begin():
            existing = await session.get(orm.SourceConnector, connector_id)
            if existing is None:
                session.add(
                    orm.SourceConnector(
                        connector_id=connector_id,
                        source_product="mock_xdr",
                        display_name="Mock XDR",
                    )
                )
            existing_object = await session.scalar(
                select(orm.SourceObject).where(
                    orm.SourceObject.source_product == "mock_xdr",
                    orm.SourceObject.source_tenant_id == "tenant-demo",
                    orm.SourceObject.connector_id == connector_id,
                    orm.SourceObject.source_kind == SourceObjectKind.INCIDENT.value,
                    orm.SourceObject.source_object_id == object_id,
                )
            )
            if existing_object is None:
                session.add(
                    orm.SourceObject(
                        source_record_id=source_record_id,
                        source_product="mock_xdr",
                        source_tenant_id="tenant-demo",
                        connector_id=connector_id,
                        source_kind=SourceObjectKind.INCIDENT.value,
                        source_object_id=object_id,
                        current_concurrency_token=concurrency_token,
                        next_outbox_sequence=0,
                    )
                )
            else:
                source_record_id = existing_object.source_record_id
                concurrency_token = (
                    existing_object.current_concurrency_token or concurrency_token
                )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.OTHER.value,
                    title="sync-test",
                    description="",
                    status=EventStatus.EXECUTING_RESPONSE.value,
                    severity=Severity.HIGH.value,
                    risk_score=80,
                    confidence=0.9,
                    final_verdict=FinalVerdict.NONE.value,
                    creation_source_ref=ref.model_dump(mode="json"),
                    source_reference_snapshots=[ref.model_dump(mode="json")],
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    disposition_source_ref=locator.model_dump(mode="json"),
                    occurred_at=datetime.now(UTC),
                )
            )
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        await store.init_context(event_id, event_summary_from_security_event(row))
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level=ActionLevel.L2.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    status=ActionStatus.EXECUTING.value,
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    target_type="ip",
                    target="203.0.113.88",
                    writeback_required=True,
                    writeback_applicable=True,
                    writeback_readiness=WritebackReadiness.READY.value,
                    disposition_source_ref=locator.model_dump(mode="json"),
                    idempotency_key=f"idem-{sfx}",
                )
            )
    return event_id, action_id, source_record_id, locator, concurrency_token


def _sync_service(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    client: httpx.AsyncClient,
    *,
    resume: AsyncMock | None = None,
    event_bus: Any | None = None,
) -> DispositionSyncService:
    registry = DispositionAdapterRegistry()
    adapter = MockXDRDispositionAdapter(
        client=client,
        read_token="mock-read-token",
        write_token="mock-write-token",
    )
    registry.register("mock_xdr", adapter)
    return DispositionSyncService(
        session_factory,
        context_store=store,
        adapter_registry=registry,
        outbound_guard=OutboundDispositionGuard(),
        event_bus=event_bus,
        resume_investigation=resume,
    )


async def _enqueue_compensation_record(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
) -> tuple[DispositionSyncService, str, str, orm.DispositionOutbox, str]:
    """Seed rollback action and enqueue COMPENSATION_RECORD (ISSUE-307 tests)."""
    (
        event_id,
        original_action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    rollback_action_id = f"act-rb-{_sfx()}"
    parent_disposition_id = new_disposition_id()
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=rollback_action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-rb-{_sfx()}",
                    action_category=ActionCategory.ROLLBACK.value,
                    action_name="unblock ip",
                    tool_name="unblock_ip",
                    action_level=ActionLevel.L2.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    status=ActionStatus.SUCCESS.value,
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    target_type="ip",
                    target="203.0.113.88",
                    source_action_id=original_action_id,
                    writeback_required=False,
                    writeback_applicable=False,
                    writeback_readiness=WritebackReadiness.NOT_REQUIRED.value,
                    disposition_source_ref=locator.model_dump(mode="json"),
                    idempotency_key=f"idem-rb-{_sfx()}",
                    executed_at=datetime.now(UTC),
                )
            )
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    rollback_action = Action.model_validate(
        {
            "action_id": rollback_action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-compensation",
            "action_category": ActionCategory.ROLLBACK,
            "action_name": "unblock ip",
            "tool_name": "unblock_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.SUCCESS,
            "target": "203.0.113.88",
            "source_action_id": original_action_id,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-rb-action-{_sfx()}",
        }
    )
    command = factory.build_compensation_record(
        rollback_action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="RollbackService",
        disposition_id=new_disposition_id(),
        closure_cycle=1,
        parent_disposition_id=parent_disposition_id,
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
                logical_slot=f"compensation:{original_action_id}",
                guard_context={"approved_action_ids": [rollback_action_id]},
            )
    assert record.intent_kind is DispositionIntentKind.COMPENSATION_RECORD
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, record.outbox_id)
        assert row is not None
    return sync, event_id, source_record_id, row, rollback_action_id


@pytest.mark.asyncio
async def test_get_disposition_by_id(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    disposition_id = new_disposition_id()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-get",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=disposition_id,
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    loaded, status = await sync.get_disposition(disposition_id)
    assert loaded.disposition_id == disposition_id
    assert status is None or isinstance(status, WritebackStatus)


@pytest.mark.asyncio
async def test_enqueue_and_deliver_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-test",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    assert record.intent_kind.value == "entity_action_submit"
    delivered = await sync.process_ready_outboxes(limit=1)
    assert delivered == 1
    async with session_factory() as session:
        outbox_row = await session.scalar(
            select(orm.DispositionOutbox).where(orm.DispositionOutbox.outbox_id == record.outbox_id)
        )
        assert outbox_row is not None
        assert outbox_row.delivery_status == "delivered"
        action_row = await session.get(orm.Action, action_id)
        assert action_row is not None
        assert action_row.writeback_status in {
            WritebackStatus.ACCEPTED.value,
            WritebackStatus.CONFIRMED.value,
        }
        if action_row.writeback_status == WritebackStatus.ACCEPTED.value:
            assert action_row.status == ActionStatus.EXECUTING.value
        else:
            assert action_row.status == ActionStatus.SUCCESS.value
        receipt = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.writeback_id == record.writeback_id
            )
        )
        assert receipt is not None
        assert receipt.status in {
            WritebackStatus.ACCEPTED.value,
            WritebackStatus.CONFIRMED.value,
        }


@pytest.mark.asyncio
async def test_retry_unknown_writeback_rejected(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id = f"wbk-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{_sfx()}",
                    writeback_id=writeback_id,
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={"source_locator": locator.model_dump(mode="json")},
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )
    with pytest.raises(WritebackConflictError):
        await sync.retry_writeback(writeback_id, operator="operator-1")


async def _insert_operator_retry_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    action_id: str,
    source_record_id: str,
    locator: SourceObjectLocator,
    concurrency_token: str,
    delivery_status: OutboxDeliveryStatus,
    writeback_status: WritebackStatus | None,
    idempotency_key: str | None = None,
    superseded_by_disposition_id: str | None = None,
) -> tuple[str, str]:
    writeback_id = f"wbk-{_sfx()}"
    outbox_id = f"obx-{_sfx()}"
    disposition_id = f"disp-{_sfx()}"
    idem = idempotency_key or f"idem-{_sfx()}"
    command_payload = factory_build_min_command(
        action_id,
        event_id,
        locator,
        concurrency_token,
    )
    command_payload["disposition_id"] = disposition_id
    command_payload["idempotency_key"] = idem
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=writeback_id,
                    disposition_id=disposition_id,
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=idem,
                    superseded_by_disposition_id=superseded_by_disposition_id,
                    command_payload=command_payload,
                    command_payload_sha256="deadbeef",
                    delivery_status=delivery_status.value,
                    latest_writeback_status=(
                        writeback_status.value if writeback_status is not None else None
                    ),
                )
            )
    return writeback_id, outbox_id


@pytest.mark.asyncio
async def test_operator_retry_dead_letter_re_enqueues(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DEAD_LETTER,
        writeback_status=WritebackStatus.FAILED,
    )
    status = await sync.retry_writeback(writeback_id, operator="operator-1")
    assert status is WritebackStatus.PENDING
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.READY.value
        assert row.latest_writeback_status == WritebackStatus.PENDING.value


@pytest.mark.asyncio
async def test_operator_retry_delivered_failed_re_enqueues(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.FAILED,
    )
    status = await sync.retry_writeback(writeback_id, operator="operator-1")
    assert status is WritebackStatus.PENDING
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.READY.value


@pytest.mark.asyncio
async def test_operator_retry_confirmed_rejected(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, _ = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.CONFIRMED,
    )
    with pytest.raises(WritebackConflictError, match="CONFIRMED"):
        await sync.retry_writeback(writeback_id, operator="operator-1")


@pytest.mark.asyncio
async def test_operator_retry_lookup_degraded_stays_paused(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.adapters.mock_xdr import MockXDRDispositionAdapter

    class _DegradedLookupAdapter(MockXDRDispositionAdapter):
        async def lookup_submission(
            self,
            idempotency_key: str,
            source_locator: SourceObjectLocator,
        ) -> None:
            raise RuntimeError("lookup degraded")

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    registry = DispositionAdapterRegistry()
    registry.register(
        "mock_xdr",
        _DegradedLookupAdapter(
            client=mock_xdr_client,
            read_token="mock-read-token",
            write_token="mock-write-token",
        ),
    )
    sync = DispositionSyncService(
        session_factory,
        context_store=store,
        adapter_registry=registry,
        outbound_guard=OutboundDispositionGuard(),
    )
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DEAD_LETTER,
        writeback_status=WritebackStatus.FAILED,
    )
    adapter = registry.get("mock_xdr")
    original_submit = adapter.submit
    submit_calls = 0

    async def _counting_submit(*args: Any, **kwargs: Any) -> Any:
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(*args, **kwargs)

    adapter.submit = _counting_submit  # type: ignore[method-assign]
    with pytest.raises(WritebackConflictError, match="lookup degraded"):
        await sync.retry_writeback(writeback_id, operator="operator-1")
    await sync.process_ready_outboxes(limit=5)
    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value


@pytest.mark.asyncio
async def test_operator_retry_late_confirmed_reconcile_no_resend(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-late",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-late-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="test",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    await sync.process_ready_outboxes(limit=1)
    adapter = sync._adapters.get("mock_xdr")
    original_submit = adapter.submit
    submit_calls = 0

    async def _counting_submit(*args: Any, **kwargs: Any) -> Any:
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(*args, **kwargs)

    adapter.submit = _counting_submit  # type: ignore[method-assign]
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.DispositionOutbox, record.outbox_id)
            assert row is not None
            row.latest_writeback_status = WritebackStatus.FAILED.value
            row.delivery_status = OutboxDeliveryStatus.DELIVERED.value
    status = await sync.retry_writeback(record.writeback_id, operator="operator-1")
    assert status in {WritebackStatus.CONFIRMED, WritebackStatus.ACCEPTED}
    await sync.process_ready_outboxes(limit=5)
    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, record.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == record.writeback_id
                )
            )
        ).all()
        assert len(receipts) >= 2


@pytest.mark.asyncio
async def test_operator_retry_operation_replay_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DEAD_LETTER,
        writeback_status=WritebackStatus.FAILED,
    )
    op_id = f"op-replay-{_sfx()}"
    first = await sync.retry_writeback(
        writeback_id,
        operator="operator-1",
        operation_id=op_id,
    )
    second = await sync.retry_writeback(
        writeback_id,
        operator="operator-1",
        operation_id=op_id,
    )
    assert first is second is WritebackStatus.PENDING
    async with session_factory() as session:
        replay_rows = (
            await session.scalars(
                select(orm.EventAuditLog).where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.reason.like(
                        f"operator_retry:replay:{writeback_id}:{op_id}:%"
                    ),
                )
            )
        ).all()
        assert len(replay_rows) == 1


@pytest.mark.asyncio
async def test_operator_retry_without_safe_retry_blocked(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.adapters.mock_xdr import LiveDispositionAdapterStub

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    registry = DispositionAdapterRegistry()
    registry.register("live_stub", LiveDispositionAdapterStub())
    sync = DispositionSyncService(
        session_factory,
        context_store=store,
        adapter_registry=registry,
        outbound_guard=OutboundDispositionGuard(),
    )
    live_locator = locator.model_copy(update={"source_product": "live_stub"})
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=live_locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DEAD_LETTER,
        writeback_status=WritebackStatus.FAILED,
    )
    adapter = registry.get("live_stub")
    original_submit = adapter.submit
    submit_calls = 0

    async def _counting_submit(*args: Any, **kwargs: Any) -> Any:
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(*args, **kwargs)

    adapter.submit = _counting_submit  # type: ignore[method-assign]
    with pytest.raises(WritebackConflictError, match="lookup capability unavailable"):
        await sync.retry_writeback(writeback_id, operator="operator-1")
    await sync.process_ready_outboxes(limit=5)
    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value


@pytest.mark.asyncio
async def test_operator_retry_superseded_head_rejected(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DEAD_LETTER,
        writeback_status=WritebackStatus.FAILED,
        superseded_by_disposition_id="disp-new-head",
    )
    with pytest.raises(WritebackConflictError, match="superseded"):
        await sync.retry_writeback(writeback_id, operator="operator-1")
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value


@pytest.mark.asyncio
async def test_resolve_writeback_manual_confirmed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    writeback_id = f"wbk-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{_sfx()}",
                    writeback_id=writeback_id,
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={"source_locator": locator.model_dump(mode="json")},
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )
    sync = _sync_service(session_factory, store, mock_xdr_client)
    status = await sync.resolve_writeback(
        writeback_id,
        "manual_confirmed",
        principal="admin-1",
        comment="ticket-123",
        evidence_ref="evidence://ticket-123",
    )
    assert status is WritebackStatus.CONFIRMED


async def _mark_action_writeback_not_applicable(
    session_factory: async_sessionmaker[AsyncSession],
    action_id: str,
) -> None:
    async with session_factory() as session:
        async with session.begin():
            action = await session.get(orm.Action, action_id, with_for_update=True)
            assert action is not None
            action.writeback_applicable = False
            action.writeback_readiness = WritebackReadiness.NOT_REQUIRED.value
            action.writeback_status = None


@pytest.mark.asyncio
async def test_sync_lookup_and_resolve_skip_writeback_status_when_not_applicable(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-195: lookup/resolve paths must not denormalize writeback_status."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    await _mark_action_writeback_not_applicable(session_factory, action_id)
    sync = _sync_service(session_factory, store, mock_xdr_client)

    lookup_writeback_id = f"wbk-lookup-{_sfx()}"
    resolve_writeback_id = f"wbk-resolve-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-lookup-{_sfx()}",
                    writeback_id=lookup_writeback_id,
                    disposition_id=f"disp-lookup-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-lookup-{_sfx()}",
                    command_payload={"source_locator": locator.model_dump(mode="json")},
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.FAILED.value,
                )
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-resolve-{_sfx()}",
                    writeback_id=resolve_writeback_id,
                    disposition_id=f"disp-resolve-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=2,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-resolve-{_sfx()}",
                    command_payload={"source_locator": locator.model_dump(mode="json")},
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )

    async with session_factory() as session:
        async with session.begin():
            lookup_outbox = await session.scalar(
                select(orm.DispositionOutbox).where(
                    orm.DispositionOutbox.writeback_id == lookup_writeback_id
                )
            )
            assert lookup_outbox is not None
            lookup_outbox.latest_writeback_status = WritebackStatus.CONFIRMED.value
    await sync.resolve_writeback(
        resolve_writeback_id,
        "manual_confirmed",
        principal="admin-1",
        comment="ticket-195",
        evidence_ref="evidence://ticket-195",
    )

    async with session_factory() as session:
        action_row = await session.get(orm.Action, action_id)
        assert action_row is not None
        assert action_row.writeback_applicable is False
        assert action_row.writeback_status is None
        lookup_outbox = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.writeback_id == lookup_writeback_id
            )
        )
        assert lookup_outbox is not None
        assert lookup_outbox.latest_writeback_status == WritebackStatus.CONFIRMED.value
        resolve_outbox = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.writeback_id == resolve_writeback_id
            )
        )
        assert resolve_outbox is not None
        assert resolve_outbox.latest_writeback_status == WritebackStatus.CONFIRMED.value


@pytest.mark.asyncio
async def test_entity_action_submit_skips_writeback_status_when_not_applicable(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-195: delivery receipt must not set writeback_status on non-applicable rows."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    await _mark_action_writeback_not_applicable(session_factory, action_id)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-test",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": False,
            "writeback_readiness": WritebackReadiness.NOT_REQUIRED,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    delivered = await sync.process_ready_outboxes(limit=1)
    assert delivered == 1
    async with session_factory() as session:
        outbox_row = await session.scalar(
            select(orm.DispositionOutbox).where(orm.DispositionOutbox.outbox_id == record.outbox_id)
        )
        assert outbox_row is not None
        assert outbox_row.delivery_status == "delivered"
        assert outbox_row.latest_writeback_status in {
            WritebackStatus.ACCEPTED.value,
            WritebackStatus.CONFIRMED.value,
        }
        action_row = await session.get(orm.Action, action_id)
        assert action_row is not None
        assert action_row.writeback_applicable is False
        assert action_row.writeback_status is None
        _action_from_row(action_row)


@pytest.mark.asyncio
async def test_resume_hook_called_on_terminal_writeback(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    resume = AsyncMock()
    sync = _sync_service(session_factory, store, mock_xdr_client, resume=resume)
    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "execution_substate",
                ExecutionSubstate.WAITING_WRITEBACK.value,
            )
            writeback_id = f"wbk-{_sfx()}"
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{_sfx()}",
                    writeback_id=writeback_id,
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={"source_locator": locator.model_dump(mode="json")},
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )
    await sync.resolve_writeback(
        writeback_id,
        "manual_confirmed",
        principal="admin-1",
        comment="done",
        evidence_ref="evidence://ok",
    )
    resume.assert_awaited_once_with(event_id)


@pytest.mark.asyncio
async def test_outbound_guard_blocks_non_allowlisted_field(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.core.errors import GuardrailViolationError
    from app.core.guardrails import OutboundDispositionGuard

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-guard",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    payload = command.model_dump(mode="json")
    payload["reason"] = "analysis leak"
    guard = OutboundDispositionGuard()
    with pytest.raises(GuardrailViolationError):
        await guard.validate(payload, {"event_id": event_id, "approved_action_ids": [action_id]})


@pytest.mark.asyncio
async def test_expired_lease_outbox_paused_not_waiting_retry(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-260: expired LEASED must PAUSE (lookup-first), not WAITING_RETRY."""
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    idem = f"idem-{_sfx()}"
    expired = datetime.now(UTC) - timedelta(minutes=5)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=idem,
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                        "idempotency_key": idem,
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.LEASED.value,
                    locked_by="stale-worker",
                    locked_at=expired,
                    lease_expires_at=expired,
                )
            )
    worker = OutboxWorker(sync)
    claimed = await worker.run_once(limit=1)
    assert claimed == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert row.latest_writeback_status == WritebackStatus.UNKNOWN.value
        assert row.attempt == 0
        assert row.next_retry_at is None
        assert row.last_error_code == "lease_expired"


@pytest.mark.asyncio
async def test_finalize_commit_failure_uses_lookup_first(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    mock_xdr_state: MockXDRState,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-260: a real post-submit receipt crash is recovered without resubmit."""
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    writeback_id = f"wbk-{_sfx()}"
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-crash",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-crash-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id=writeback_id,
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    submit_before = len(mock_xdr_state.disposition_by_id)

    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=writeback_id,
                    disposition_id=command.disposition_id,
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=command.idempotency_key,
                    command_payload=command.model_dump(mode="json"),
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    latest_writeback_status=WritebackStatus.PENDING.value,
                )
            )

    original_append_receipt = sync._append_receipt
    fault_injected = False

    async def _crash_once_after_submit(*args: object, **kwargs: object) -> object:
        nonlocal fault_injected
        if not fault_injected and kwargs.get("receipt") is not None:
            fault_injected = True
            raise RuntimeError("fault injection: crash before receipt commit")
        return await original_append_receipt(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(sync, "_append_receipt", _crash_once_after_submit)
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert fault_injected is True
    assert len(mock_xdr_state.disposition_by_id) == submit_before + 1
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert row.latest_writeback_status == WritebackStatus.UNKNOWN.value
        assert row.last_error_code == "delivery_outcome_unknown"

    assert await worker.run_once(limit=1) == 0
    assert len(mock_xdr_state.disposition_by_id) == submit_before + 1

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value
        assert row.latest_writeback_status in {
            WritebackStatus.ACCEPTED.value,
            WritebackStatus.CONFIRMED.value,
        }
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert {receipt.status for receipt in receipts} >= {
            WritebackStatus.UNKNOWN.value,
            WritebackStatus.ACCEPTED.value,
        }


@pytest.mark.asyncio
async def test_paused_outbox_not_claimed_before_lookup(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-260: lookup must finish before a PAUSED row can be submitted."""
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.PAUSED.value,
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                    last_error_code="lease_expired",
                )
            )
    calls: list[str] = []
    adapter = sync._adapters.get("mock_xdr")
    original_lookup = adapter.lookup_submission
    original_submit = adapter.submit

    async def _lookup_first(
        idempotency_key: str,
        source_locator: SourceObjectLocator,
    ) -> object:
        calls.append("lookup")
        return await original_lookup(idempotency_key, source_locator)

    async def _submit_after_lookup(command: DispositionCommand) -> object:
        assert calls == ["lookup"]
        calls.append("submit")
        return await original_submit(command)

    monkeypatch.setattr(adapter, "lookup_submission", _lookup_first)
    monkeypatch.setattr(adapter, "submit", _submit_after_lookup)
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert calls == ["lookup", "submit"]
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value


@pytest.mark.asyncio
async def test_lookup_never_accepted_safe_retry_re_enqueues(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-260: lookup 404 + safe-retry adapter re-enqueues; otherwise stays PAUSED."""
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    idem = f"idem-never-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=idem,
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                        "idempotency_key": idem,
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.PAUSED.value,
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                    last_error_code="lease_expired",
                )
            )
    worker = OutboxWorker(sync)
    assert await sync.reconcile_paused_outboxes(limit=1) == 1
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.READY.value
        assert row.latest_writeback_status == WritebackStatus.PENDING.value
        assert row.last_error_code == "lookup_never_accepted"

    assert await worker.run_once(limit=1) == 1
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value


@pytest.mark.asyncio
async def test_lookup_degraded_keeps_outbox_paused_and_releases_reconcile_lease(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-260: transport/5xx lookup outcomes are not treated as not-found."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    idem = f"idem-degraded-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=idem,
                    command_payload={
                        **factory_build_min_command(
                            action_id,
                            event_id,
                            locator,
                            concurrency_token,
                        ),
                        "idempotency_key": idem,
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.PAUSED.value,
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )

    adapter = sync._adapters.get("mock_xdr")

    async def _lookup_503(
        _idempotency_key: str,
        _source_locator: SourceObjectLocator,
    ) -> None:
        raise httpx.ReadTimeout("provider lookup timed out")

    monkeypatch.setattr(adapter, "lookup_submission", _lookup_503)
    assert await sync.reconcile_paused_outboxes(limit=1) == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert row.latest_writeback_status == WritebackStatus.UNKNOWN.value
        assert row.last_error_code == "lookup_degraded"
        assert row.locked_by is None
        assert row.lease_expires_at is None


@pytest.mark.asyncio
async def test_reconcile_batch_isolates_invalid_paused_row(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-260: one malformed PAUSED row cannot roll back another row."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    bad_outbox_id = f"obx-bad-{_sfx()}"
    good_outbox_id = f"obx-good-{_sfx()}"
    good_idem = f"idem-good-{_sfx()}"
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add_all(
                [
                    orm.DispositionOutbox(
                        outbox_id=bad_outbox_id,
                        writeback_id=f"wbk-bad-{_sfx()}",
                        disposition_id=f"disp-bad-{_sfx()}",
                        action_id=action_id,
                        event_id=event_id,
                        closure_cycle=1,
                        source_record_id=source_record_id,
                        source_locator_hash="hash-bad",
                        source_sequence=1,
                        intent_kind="entity_action_submit",
                        logical_slot="bad",
                        idempotency_key=f"idem-bad-{_sfx()}",
                        command_payload={"invalid": True},
                        command_payload_sha256="bad",
                        delivery_status=OutboxDeliveryStatus.PAUSED.value,
                        latest_writeback_status=WritebackStatus.UNKNOWN.value,
                        updated_at=now - timedelta(seconds=1),
                    ),
                    orm.DispositionOutbox(
                        outbox_id=good_outbox_id,
                        writeback_id=f"wbk-good-{_sfx()}",
                        disposition_id=f"disp-good-{_sfx()}",
                        action_id=action_id,
                        event_id=event_id,
                        closure_cycle=1,
                        source_record_id=source_record_id,
                        source_locator_hash="hash-good",
                        source_sequence=2,
                        intent_kind="entity_action_submit",
                        logical_slot="good",
                        idempotency_key=good_idem,
                        command_payload={
                            **factory_build_min_command(
                                action_id,
                                event_id,
                                locator,
                                concurrency_token,
                            ),
                            "idempotency_key": good_idem,
                        },
                        command_payload_sha256="good",
                        delivery_status=OutboxDeliveryStatus.PAUSED.value,
                        latest_writeback_status=WritebackStatus.UNKNOWN.value,
                        updated_at=now,
                    ),
                ]
            )

    assert await sync.reconcile_paused_outboxes(limit=2) == 1
    async with session_factory() as session:
        bad = await session.get(orm.DispositionOutbox, bad_outbox_id)
        good = await session.get(orm.DispositionOutbox, good_outbox_id)
        assert bad is not None and good is not None
        assert bad.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert bad.last_error_code == "lookup_claim_invalid"
        assert good.delivery_status == OutboxDeliveryStatus.READY.value
        assert good.latest_writeback_status == WritebackStatus.PENDING.value


@pytest.mark.asyncio
async def test_lookup_update_blocks_illegal_transition(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """FAILED → CONFIRMED via fenced lookup is allowed with evidence_adjudication."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.FAILED,
    )
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None

    async def _found(*_args: Any, **_kwargs: Any) -> DispositionReceipt:
        return _complete_confirmed_receipt(
            writeback_id,
            evidence=ConfirmationEvidence.READBACK_VERIFIED,
        )

    adapter.lookup_submission = _found  # type: ignore[method-assign]
    outcome = await sync.reconcile_writeback_lookup(writeback_id)
    assert outcome.kind is WritebackLookupKind.FOUND
    async with session_factory() as session:
        outbox = await session.get(orm.DispositionOutbox, outbox_id)
        assert outbox is not None
        assert outbox.latest_writeback_status == WritebackStatus.CONFIRMED.value


@pytest.mark.asyncio
async def test_lookup_update_blocks_illegal_transition_to_pending(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """FAILED → PENDING from a lookup receipt still requires safe-retry proof."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, _outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.FAILED,
    )
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    now = datetime.now(UTC)

    async def _pending(*_args: Any, **_kwargs: Any) -> DispositionReceipt:
        return DispositionReceipt(
            writeback_id=writeback_id,
            sequence=1,
            disposition_id="disp-pending",
            action_id=action_id,
            source_record_id=source_record_id,
            status=WritebackStatus.PENDING,
            observed_at=now,
            submitted_at=now,
            simulated=True,
        )

    adapter.lookup_submission = _pending  # type: ignore[method-assign]
    with pytest.raises(InvalidStateTransitionError):
        await sync.reconcile_writeback_lookup(writeback_id)


def factory_build_min_command(
    action_id: str,
    event_id: str,
    locator: SourceObjectLocator,
    concurrency_token: str,
) -> dict:
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-min",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{action_id}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    return command.model_dump(mode="json")


async def _insert_leased_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    action_id: str,
    source_record_id: str,
    locator: SourceObjectLocator,
    concurrency_token: str,
    outbox_id: str | None = None,
    attempt: int = 0,
) -> str:
    oid = outbox_id or f"obx-{_sfx()}"
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=oid,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.LEASED.value,
                    locked_by="worker-a",
                    locked_at=now,
                    lease_expires_at=now + timedelta(seconds=30),
                    attempt=attempt,
                )
            )
    return oid


async def _reset_outbox_ready(
    session_factory: async_sessionmaker[AsyncSession], outbox_id: str
) -> None:
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.DispositionOutbox, outbox_id, with_for_update=True)
            assert row is not None
            row.delivery_status = OutboxDeliveryStatus.READY.value
            row.locked_by = None
            row.locked_at = None
            row.lease_expires_at = None
            row.next_retry_at = None
            row.attempt = 0


async def _ready_outbox_for_concurrency(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
) -> tuple[DispositionSyncService, str]:
    event_id, action_id, source_record_id, locator, token = await _seed_event_action_source(
        session_factory, store, mock_xdr_client
    )
    outbox_id = await _insert_leased_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=token,
    )
    await _reset_outbox_ready(session_factory, outbox_id)
    return _sync_service(session_factory, store, mock_xdr_client), outbox_id


@pytest.mark.asyncio
async def test_submit_blocking_does_not_hold_database_row_lock(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    sync, outbox_id = await _ready_outbox_for_concurrency(
        session_factory, store, mock_xdr_client
    )
    adapter = sync._adapters.get("mock_xdr")
    original_submit = adapter.submit
    submit_started = asyncio.Event()
    release_submit = asyncio.Event()

    async def blocked_submit(command: DispositionCommand) -> DispositionReceipt:
        submit_started.set()
        await release_submit.wait()
        return await original_submit(command)

    adapter.submit = blocked_submit  # type: ignore[method-assign]
    delivery = asyncio.create_task(sync.deliver_outbox(outbox_id))
    await asyncio.wait_for(submit_started.wait(), timeout=2)

    async def acquire_target_lock() -> None:
        async with session_factory() as session:
            async with session.begin():
                row = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.outbox_id == outbox_id)
                    .with_for_update()
                )
                assert row is not None

    await asyncio.wait_for(acquire_target_lock(), timeout=2)
    release_submit.set()
    await delivery


@pytest.mark.asyncio
@pytest.mark.parametrize("competitor", ["direct", "batch"])
async def test_direct_delivery_has_one_claim_against_direct_or_batch(
    competitor: str,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    sync, outbox_id = await _ready_outbox_for_concurrency(
        session_factory, store, mock_xdr_client
    )
    adapter = sync._adapters.get("mock_xdr")
    original_submit = adapter.submit
    submit_started = asyncio.Event()
    release_submit = asyncio.Event()
    submit_count = 0

    async def blocked_submit(command: DispositionCommand) -> DispositionReceipt:
        nonlocal submit_count
        submit_count += 1
        submit_started.set()
        await release_submit.wait()
        return await original_submit(command)

    adapter.submit = blocked_submit  # type: ignore[method-assign]
    first = asyncio.create_task(sync.deliver_outbox(outbox_id))
    await asyncio.wait_for(submit_started.wait(), timeout=2)
    if competitor == "direct":
        await sync.deliver_outbox(outbox_id)
    else:
        assert await OutboxWorker(sync).run_once(limit=1) == 0
    release_submit.set()
    await first
    assert submit_count == 1


async def _assert_stale_worker_outcome_cannot_modify_reclaimed_lease(
    outcome: str,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    sync, outbox_id = await _ready_outbox_for_concurrency(
        session_factory, store, mock_xdr_client
    )
    adapter = sync._adapters.get("mock_xdr")
    original_submit = adapter.submit
    submit_started = asyncio.Event()
    release_submit = asyncio.Event()

    async def stale_submit(command: DispositionCommand) -> DispositionReceipt:
        submit_started.set()
        await release_submit.wait()
        if outcome == "failure":
            raise OSError("provider transport failed")
        if outcome == "conflict":
            raise WritebackConflictError("provider conflict")
        if outcome == "deterministic_rejection":
            raise WritebackUnsupportedError("provider rejected command")
        receipt = await original_submit(command)
        if outcome == "unknown":
            return receipt.model_copy(update={"status": WritebackStatus.UNKNOWN})
        return receipt

    adapter.submit = stale_submit  # type: ignore[method-assign]
    delivery = asyncio.create_task(sync.deliver_outbox(outbox_id))
    await asyncio.wait_for(submit_started.wait(), timeout=2)

    # Expire A's real lease, then drive the production lookup-first reclaim path.
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.DispositionOutbox, outbox_id, with_for_update=True)
            assert row is not None
            row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert await sync._claim_outbox(outbox_id) is None
    lookup_claims = await sync._claim_paused_outboxes(limit=1)
    assert len(lookup_claims) == 1
    worker_b = lookup_claims[0]
    assert worker_b.outbox_id == outbox_id
    release_submit.set()
    await delivery

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert row.locked_by == worker_b.token
        assert row.attempt == worker_b.attempt
        assert row.locked_at == worker_b.locked_at
        assert row.lease_expires_at == worker_b.lease_expires_at
        receipt_count = await session.scalar(
            select(func.count(orm.DispositionReceipt.writeback_id)).where(
                orm.DispositionReceipt.writeback_id == row.writeback_id
            )
        )
        assert receipt_count == 0


@pytest.mark.asyncio
async def test_stale_worker_success_cannot_modify_real_reclaimed_claim(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    await _assert_stale_worker_outcome_cannot_modify_reclaimed_lease(
        "success", session_factory, store, mock_xdr_client, cleanup
    )


@pytest.mark.asyncio
async def test_stale_worker_failure_cannot_modify_real_reclaimed_claim(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    await _assert_stale_worker_outcome_cannot_modify_reclaimed_lease(
        "failure", session_factory, store, mock_xdr_client, cleanup
    )


@pytest.mark.asyncio
async def test_stale_worker_unknown_cannot_modify_real_reclaimed_claim(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    await _assert_stale_worker_outcome_cannot_modify_reclaimed_lease(
        "unknown", session_factory, store, mock_xdr_client, cleanup
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["conflict", "deterministic_rejection"])
async def test_stale_worker_terminal_error_cannot_modify_real_reclaimed_claim(
    outcome: str,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    await _assert_stale_worker_outcome_cannot_modify_reclaimed_lease(
        outcome, session_factory, store, mock_xdr_client, cleanup
    )


@pytest.mark.asyncio
async def test_real_worker_b_reclaims_after_worker_a_lease_expiry(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    sync, outbox_id = await _ready_outbox_for_concurrency(
        session_factory, store, mock_xdr_client
    )
    worker_a = await sync._claim_outbox(outbox_id)
    assert worker_a is not None
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.DispositionOutbox, outbox_id, with_for_update=True)
            assert row is not None
            row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)

    # Expired egress is UNKNOWN: the delivery claim converts to PAUSED and the
    # next real worker acquires the lookup-first reconciliation lease.
    assert await sync._claim_outbox(outbox_id) is None
    claims = await sync._claim_paused_outboxes(limit=1)
    assert len(claims) == 1
    worker_b = claims[0]
    assert worker_b.outbox_id == outbox_id
    assert worker_b.token != worker_a.fence_token
    assert worker_b.attempt == worker_a.attempt + 1
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert row.locked_by == worker_b.token
        assert row.attempt == worker_b.attempt
        assert row.locked_at == worker_b.locked_at
        assert row.lease_expires_at == worker_b.lease_expires_at


@pytest.mark.asyncio
async def test_waiting_retry_future_next_retry_at_not_claimed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    future = datetime.now(UTC) + timedelta(minutes=10)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.WAITING_RETRY.value,
                    attempt=1,
                    next_retry_at=future,
                    last_error_code="delivery_failed",
                )
            )
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=5) == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.WAITING_RETRY.value


@pytest.mark.asyncio
async def test_waiting_retry_due_is_claimed_and_delivered(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    past = datetime.now(UTC) - timedelta(seconds=5)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.WAITING_RETRY.value,
                    attempt=1,
                    next_retry_at=past,
                    last_error_code="delivery_failed",
                )
            )
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=5) == 1
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value


@pytest.mark.asyncio
async def test_outbox_max_attempts_moves_to_dead_letter(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings, "cache_clear", lambda: None)
    settings = _settings_overlay(outbox_max_attempts=2)
    monkeypatch.setattr("app.services.disposition_sync_service.get_settings", lambda: settings)

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = await _insert_leased_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        attempt=2,
    )

    await sync._mark_delivery_waiting_retry(outbox_id, error_code="delivery_failed")

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.attempt == 2
        assert row.next_retry_at is None

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=5) == 0


@pytest.mark.asyncio
async def test_delivery_exception_pauses_unknown_without_hot_retry(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    async def _fail_submit(_command: object) -> None:
        raise RuntimeError("simulated adapter failure")

    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    monkeypatch.setattr(adapter, "submit", _fail_submit)
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert row.latest_writeback_status == WritebackStatus.UNKNOWN.value
        assert row.attempt == 1
        assert row.next_retry_at is None
        assert row.last_error_code == "delivery_outcome_unknown"
        assert row.last_error_detail is not None
        assert "RuntimeError" in row.last_error_detail

    assert await worker._claim_batch(limit=1) == []


@pytest.mark.asyncio
async def test_waiting_retry_null_next_retry_at_backfilled_not_claimed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.WAITING_RETRY.value,
                    attempt=1,
                    next_retry_at=None,
                    last_error_code="delivery_failed",
                )
            )
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=5) == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.WAITING_RETRY.value
        assert row.next_retry_at is not None
        assert row.next_retry_at > datetime.now(UTC)


@pytest.mark.asyncio
async def test_guardrail_blocked_moves_to_dead_letter(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.errors import GuardrailViolationError
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    async def _guardrail_block(command: object, context: object) -> None:
        del command, context
        raise GuardrailViolationError(
            "blocked writeback field",
            error_code="guardrail_violation",
        )

    monkeypatch.setattr(sync._guard, "validate", _guardrail_block)
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == "guardrail_blocked"
        assert row.last_error_detail is not None
        assert row.next_retry_at is None

    assert await worker.run_once(limit=1) == 0


@pytest.mark.asyncio
async def test_adapter_not_found_dead_letters_without_pause(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-300: explicit adapter not_found must not enter PAUSED/lookup retry."""
    (
        event_id,
        action_id,
        source_record_id,
        _locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    job_id = await _attach_xdr_execution_job(
        session_factory,
        action_id=action_id,
        event_id=event_id,
        idempotency_key=f"idem-failed-{_sfx()}",
    )
    sync = _sync_service(session_factory, store, mock_xdr_client)
    missing_locator = SourceObjectLocator(
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_kind=SourceObjectKind.INCIDENT,
        source_object_id="incident-missing-not-found",
    )
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id,
                            event_id,
                            missing_locator,
                            concurrency_token,
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.latest_writeback_status == WritebackStatus.FAILED.value
        assert row.last_error_code == "not_found"
        assert row.next_retry_at is None
        action = await session.get(orm.Action, action_id)
        assert action is not None
        assert action.writeback_status == WritebackStatus.FAILED.value
        job = await session.get(orm.ActionExecutionJob, job_id)
        assert job is not None
        assert job.status == ExecutionJobStatus.FAILED.value
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert len(receipts) == 1
        assert receipts[0].status == WritebackStatus.FAILED.value

    assert await worker.run_once(limit=1) == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value


@pytest.mark.asyncio
async def test_paused_not_found_reconcile_does_not_re_enqueue(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-300: reconcile must not safe-retry pre-submit deterministic rejections."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.PAUSED.value,
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                    last_error_code="not_found",
                    last_error_detail="legacy misclassified deterministic rejection",
                )
            )

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.latest_writeback_status == WritebackStatus.FAILED.value
        assert row.last_error_code == "not_found"
        action = await session.get(orm.Action, action_id)
        assert action is not None
        assert action.status == ActionStatus.FAILED.value
        assert action.writeback_status == WritebackStatus.FAILED.value
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert len(receipts) == 1
        assert receipts[0].status == WritebackStatus.FAILED.value


@pytest.mark.asyncio
async def test_adapter_unknown_submission_stays_paused_for_lookup(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-300: transport/5xx ambiguity still uses PAUSED + lookup recovery."""
    from app.models.disposition import DispositionReceipt

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    job_id = await _attach_xdr_execution_job(
        session_factory,
        action_id=action_id,
        event_id=event_id,
        idempotency_key=f"idem-unknown-{_sfx()}",
    )
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    adapter = sync._adapters.get("mock_xdr")
    original_submit = adapter.submit

    async def _unknown_submit(command: DispositionCommand) -> DispositionReceipt:
        return DispositionReceipt(
            writeback_id=f"wbk-unknown-{command.disposition_id}",
            sequence=1,
            disposition_id=command.disposition_id,
            action_id=command.action_id,
            source_record_id=command.source_locator.source_object_id,
            status=WritebackStatus.UNKNOWN,
            provider_code="unknown_delivery",
            provider_message="simulated transport loss",
            submitted_at=datetime.now(UTC),
            observed_at=datetime.now(UTC),
            simulated=True,
        )

    monkeypatch.setattr(adapter, "submit", _unknown_submit)
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert row.latest_writeback_status == WritebackStatus.UNKNOWN.value
        assert row.last_error_code == "submission_unknown"
        job = await session.get(orm.ActionExecutionJob, job_id)
        assert job is not None
        assert job.status == ExecutionJobStatus.UNKNOWN.value

    monkeypatch.setattr(adapter, "submit", original_submit)


@pytest.mark.asyncio
async def test_writeback_conflict_delivered_without_pause(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-300: version conflict remains a definitive terminal outcome, not PAUSED."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    job_id = await _attach_xdr_execution_job(
        session_factory,
        action_id=action_id,
        event_id=event_id,
        idempotency_key=f"idem-conflict-{_sfx()}",
    )
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    adapter = sync._adapters.get("mock_xdr")

    async def _conflict_submit(_command: DispositionCommand) -> None:
        raise WritebackConflictError(
            "version conflict",
            error_code="version_conflict",
            details={"status": 409},
        )

    monkeypatch.setattr(adapter, "submit", _conflict_submit)
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value
        assert row.latest_writeback_status == WritebackStatus.CONFLICT.value
        assert row.last_error_code == "version_conflict"
        job = await session.get(orm.ActionExecutionJob, job_id)
        assert job is not None
        assert job.status == ExecutionJobStatus.FAILED.value


@pytest.mark.asyncio
async def test_ambiguous_validation_error_stays_paused_for_lookup(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-300: non-allowlist ValidationError must not dead-letter."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    adapter = sync._adapters.get("mock_xdr")

    async def _ambiguous_validation(_command: DispositionCommand) -> None:
        raise ValidationError("malformed payload", error_code="validation_error")

    monkeypatch.setattr(adapter, "submit", _ambiguous_validation)
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert row.latest_writeback_status == WritebackStatus.UNKNOWN.value
        assert row.last_error_code == "delivery_outcome_unknown"


@pytest.mark.asyncio
async def test_transport_exception_stays_paused_for_lookup(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-300: transport/5xx ambiguity still uses PAUSED + lookup recovery."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    adapter = sync._adapters.get("mock_xdr")

    async def _transport_failure(_command: DispositionCommand) -> None:
        raise RuntimeError("simulated upstream 503")

    monkeypatch.setattr(adapter, "submit", _transport_failure)
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert row.latest_writeback_status == WritebackStatus.UNKNOWN.value
        assert row.last_error_code == "delivery_outcome_unknown"


@pytest.mark.asyncio
async def test_append_receipt_sanitizes_sensitive_raw_result_before_persist(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-181: malicious adapter raw_result must not land verbatim in DB."""
    from app.models.disposition import DispositionReceipt

    (
        event_id,
        action_id,
        source_record_id,
        _locator,
        _concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id = f"wbk-{_sfx()}"
    outbox_id = f"obx-{_sfx()}"
    disposition_id = f"disp-{_sfx()}"
    malicious_raw = {
        "token": "secret-token-value",
        "password": "hunter2",
        "details": {"api_key": "sk-test1234567890"},
        "provider_status": "accepted",
    }
    receipt = DispositionReceipt(
        writeback_id=writeback_id,
        sequence=0,
        disposition_id=disposition_id,
        action_id=action_id,
        source_record_id=source_record_id,
        status=WritebackStatus.CONFIRMED,
        confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
        provider_message="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
        target_results=[
            TargetWritebackResult(
                canonical_target="host:workstation-1",
                status=TargetWritebackStatus.CONFIRMED,
                provider_code="token=secret-provider-code",
                message_code="Bearer leaked-target-token",
                artifact_ref="https://user:password@internal.example/artifact/1",
            )
        ],
        raw_result=dict(malicious_raw),
        simulated=True,
    )
    original_raw = dict(receipt.raw_result)
    original_message = receipt.provider_message
    original_target_results = [item.model_copy() for item in receipt.target_results]

    async with session_factory() as session:
        async with session.begin():
            outbox = orm.DispositionOutbox(
                outbox_id=outbox_id,
                writeback_id=writeback_id,
                disposition_id=disposition_id,
                action_id=action_id,
                event_id=event_id,
                closure_cycle=1,
                source_record_id=source_record_id,
                source_locator_hash="hash",
                source_sequence=1,
                intent_kind="entity_action_submit",
                logical_slot="default",
                idempotency_key=f"idem-{_sfx()}",
                command_payload={"intent_kind": "entity_action_submit"},
                command_payload_sha256="deadbeef",
                delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                latest_writeback_status=WritebackStatus.CONFIRMED.value,
            )
            session.add(outbox)
            persisted = await sync._append_receipt(session, outbox, receipt=receipt)

    assert receipt.raw_result == original_raw
    assert receipt.provider_message == original_message
    assert [item.model_dump() for item in receipt.target_results] == [
        item.model_dump() for item in original_target_results
    ]
    assert persisted.status is WritebackStatus.CONFIRMED
    assert persisted.confirmation_evidence is ConfirmationEvidence.READBACK_VERIFIED
    assert persisted.raw_result["provider_status"] == "accepted"
    assert persisted.raw_result["token"] == "***"
    assert persisted.raw_result["password"] == "***"
    assert persisted.raw_result["details"]["api_key"] == "***"
    assert "[REDACTED]" in (persisted.provider_message or "")
    assert persisted.target_results[0].canonical_target == "host:workstation-1"
    assert persisted.target_results[0].status is TargetWritebackStatus.CONFIRMED
    assert "[REDACTED]" in (persisted.target_results[0].provider_code or "")
    assert "[REDACTED]" in (persisted.target_results[0].message_code or "")
    assert "[REDACTED]" in (persisted.target_results[0].artifact_ref or "")

    async with session_factory() as session:
        row = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.writeback_id == writeback_id,
                orm.DispositionReceipt.sequence == 1,
            )
        )
        assert row is not None
        assert row.status == WritebackStatus.CONFIRMED.value
        assert row.confirmation_evidence == ConfirmationEvidence.READBACK_VERIFIED.value
        assert row.raw_result["token"] == "***"
        assert row.raw_result["password"] == "***"
        assert "secret-token-value" not in str(row.raw_result)
        assert "hunter2" not in str(row.raw_result)
        assert "[REDACTED]" in str(row.target_results)

        journal_value = await session.scalar(
            select(orm.EventContextJournal.value)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "disposition_receipts",
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        assert journal_value is not None
        journal_items = unwrap_journal_value(journal_value)
        assert isinstance(journal_items, list)
        assert journal_items
        journal_receipt = journal_items[-1]
        assert journal_receipt["status"] == WritebackStatus.CONFIRMED.value
        assert journal_receipt["confirmation_evidence"] == (
            ConfirmationEvidence.READBACK_VERIFIED.value
        )
        assert journal_receipt["raw_result"]["token"] == "***"
        assert journal_receipt["raw_result"]["password"] == "***"
        assert "secret-token-value" not in str(journal_receipt)
        assert "hunter2" not in str(journal_receipt)
        assert "[REDACTED]" in str(journal_receipt["target_results"])


@pytest.mark.asyncio
async def test_append_receipt_preserves_mock_receipt_gate_fields(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-181: sanitize must not strip confirmation_evidence or writeback status."""
    from app.models.disposition import DispositionReceipt

    (
        event_id,
        action_id,
        source_record_id,
        _locator,
        _concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id = f"wbk-{_sfx()}"
    outbox_id = f"obx-{_sfx()}"
    disposition_id = f"disp-{_sfx()}"
    receipt = DispositionReceipt(
        writeback_id=writeback_id,
        sequence=0,
        disposition_id=disposition_id,
        action_id=action_id,
        source_record_id=source_record_id,
        status=WritebackStatus.CONFIRMED,
        confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
        provider_record_id="mock-record-1",
        provider_job_id="mock-job-1",
        raw_result={"simulated": True, "status": "confirmed"},
        simulated=True,
    )

    async with session_factory() as session:
        async with session.begin():
            outbox = orm.DispositionOutbox(
                outbox_id=outbox_id,
                writeback_id=writeback_id,
                disposition_id=disposition_id,
                action_id=action_id,
                event_id=event_id,
                closure_cycle=1,
                source_record_id=source_record_id,
                source_locator_hash="hash",
                source_sequence=1,
                intent_kind="entity_action_submit",
                logical_slot="default",
                idempotency_key=f"idem-{_sfx()}",
                command_payload={"intent_kind": "entity_action_submit"},
                command_payload_sha256="deadbeef",
                delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                latest_writeback_status=WritebackStatus.CONFIRMED.value,
            )
            session.add(outbox)
            persisted = await sync._append_receipt(session, outbox, receipt=receipt)

    assert persisted.status is WritebackStatus.CONFIRMED
    assert persisted.confirmation_evidence is ConfirmationEvidence.READBACK_VERIFIED
    assert persisted.provider_record_id == "mock-record-1"
    assert persisted.provider_job_id == "mock-job-1"
    assert persisted.raw_result["simulated"] is True
    assert persisted.raw_result["status"] == "confirmed"
    assert persisted.simulated is True


@pytest.mark.asyncio
async def test_deliver_outbox_blocked_when_writeback_fence_closed_after_enqueue(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-222: enqueue under mock, flip settings, deliver must not submit."""
    from app.core.config import Settings, get_settings
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-fence",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(command):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(command)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    monkeypatch.setattr(get_settings, "cache_clear", lambda: None)
    blocked_settings = _settings_overlay(
        disposition_mode="live_xdr",
        disposition_adapter_kind="http",
        allow_xdr_writeback=False,
    )
    monkeypatch.setattr(
        "app.services.writeback_side_effect_fence.get_settings",
        lambda: blocked_settings,
    )
    monkeypatch.setattr(
        "app.services.disposition_sync_service.get_settings",
        lambda: blocked_settings,
    )

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, record.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        assert row.last_error_detail is not None
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert receipts == []


@pytest.mark.asyncio
async def test_deliver_outbox_sync_ready_blocked_when_writeback_fence_closed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-222: synchronous deliver_outbox on READY must fail-closed too."""
    from app.core.config import Settings, get_settings
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(command):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(command)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    monkeypatch.setattr(get_settings, "cache_clear", lambda: None)
    blocked_settings = _settings_overlay(block_live_action_execution=True)
    monkeypatch.setattr(
        "app.services.writeback_side_effect_fence.get_settings",
        lambda: blocked_settings,
    )

    await sync.deliver_outbox(outbox_id)
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_deliver_outbox_blocked_when_action_execution_frozen(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-222: worker delivery must fail-closed when BLOCK_LIVE_ACTION_EXECUTION is on."""
    from app.core.config import Settings, get_settings
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(command):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(command)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)
    monkeypatch.setattr(get_settings, "cache_clear", lambda: None)
    blocked_settings = _settings_overlay(block_live_action_execution=True)
    monkeypatch.setattr(
        "app.services.writeback_side_effect_fence.get_settings",
        lambda: blocked_settings,
    )

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_deliver_outbox_fence_blocks_from_waiting_retry(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-222: WAITING_RETRY outbox must fail-closed when writeback fence is closed."""
    from app.core.config import Settings, get_settings
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.WAITING_RETRY.value,
                    attempt=1,
                    next_retry_at=datetime.now(UTC) - timedelta(seconds=5),
                )
            )

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(command):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(command)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)
    monkeypatch.setattr(get_settings, "cache_clear", lambda: None)
    blocked_settings = _settings_overlay(
        disposition_mode="live_xdr",
        disposition_adapter_kind="http",
        allow_xdr_writeback=False,
    )
    monkeypatch.setattr(
        "app.services.writeback_side_effect_fence.get_settings",
        lambda: blocked_settings,
    )

    await sync.deliver_outbox(outbox_id)
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_deliver_outbox_fence_blocks_when_action_row_missing(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-222: missing action row must fail-closed without adapter.submit."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    real_get = AsyncSession.get

    async def _get_without_action(self, entity, ident, **kwargs):  # type: ignore[no-untyped-def]
        if entity is orm.Action:
            return None
        return await real_get(self, entity, ident, **kwargs)

    monkeypatch.setattr(AsyncSession, "get", _get_without_action)

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(command):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(command)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    await sync.deliver_outbox(outbox_id)
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        assert row.last_error_detail is not None
        assert action_id in row.last_error_detail


@pytest.mark.asyncio
async def test_deliver_rejects_after_approval_revoked(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-235 (SUS-301): an approval revoked between enqueue and delivery
    must fail-closed — the entity-class outbox is not delivered (the
    enqueue-time approved snapshot must not go out after revoke/supersede)."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-revoke",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )

    # Revoke the approval while the outbox is still in flight.
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.REJECTED.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    await sync.deliver_outbox(record.outbox_id)

    # Fail-closed: never submitted, outbox dead-lettered with the fence code.
    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, record.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        assert row.last_error_detail is not None
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert receipts == []


@pytest.mark.asyncio
async def test_worker_deliver_rejects_after_approval_revoked(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-235: production worker lease path must also fail-closed after revoke."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-worker-revoke",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.REJECTED.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, record.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_deliver_execution_result_rejected_after_supersede(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-235: an EXECUTION_RESULT_RECORD whose action was superseded after
    enqueue (supersede-only — status may still be SUCCESS) must not be
    delivered; the delivery-time re-check fails closed."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-result",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.DIRECT_TOOL,
            "status": ActionStatus.SUCCESS,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    job = ActionExecutionJob(
        job_id=f"job-{_sfx()}",
        event_id=event_id,
        action_id=action_id,
        provider_name="mock_tool_provider",
        idempotency_key=f"idem-job-{_sfx()}",
        status=ExecutionJobStatus.SUCCESS,
        target_results=[
            TargetExecutionResult(
                canonical_target="ip:203.0.113.88",
                status=TargetExecutionStatus.SUCCESS,
                code="block_success",
                message="block success",
            )
        ],
    )
    command = factory.build_execution_result_record(
        action,
        job,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        closure_cycle=1,
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    assert record.intent_kind.value == "execution_result_record"

    # Supersede-only: mirror production timing — action already SUCCESS, then superseded.
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.SUCCESS.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_result_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_result_submit)

    await sync.deliver_outbox(record.outbox_id)

    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, record.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_deliver_compensation_record_rejected_after_supersede(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-307: COMPENSATION_RECORD whose rollback action was superseded after
    enqueue must not be delivered; delivery-time approval re-check fails closed."""
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        sync,
        _event_id,
        _source_record_id,
        outbox_row,
        rollback_action_id,
    ) = await _enqueue_compensation_record(session_factory, store, mock_xdr_client)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, rollback_action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.SUCCESS.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    await sync.deliver_outbox(outbox_row.outbox_id)

    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        assert row.last_error_detail is not None
        assert "approval revoked before delivery" in row.last_error_detail
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert receipts == []


@pytest.mark.asyncio
async def test_deliver_compensation_record_rejected_after_approval_revoked(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-307: COMPENSATION_RECORD must fail-closed after rollback action revoke."""
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        sync,
        _event_id,
        _source_record_id,
        outbox_row,
        rollback_action_id,
    ) = await _enqueue_compensation_record(session_factory, store, mock_xdr_client)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, rollback_action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.REJECTED.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    await sync.deliver_outbox(outbox_row.outbox_id)

    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        assert row.last_error_detail is not None
        assert "approval revoked before delivery" in row.last_error_detail
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert receipts == []


@pytest.mark.asyncio
async def test_worker_deliver_compensation_record_rejected_after_supersede(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-307: worker lease path must fail-closed for superseded compensation."""
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        sync,
        _event_id,
        _source_record_id,
        outbox_row,
        rollback_action_id,
    ) = await _enqueue_compensation_record(session_factory, store, mock_xdr_client)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, rollback_action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.SUCCESS.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        assert row.last_error_detail is not None
        assert "approval revoked before delivery" in row.last_error_detail
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert receipts == []


@pytest.mark.asyncio
async def test_worker_deliver_compensation_record_rejected_after_approval_revoked(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-307: worker lease path must fail-closed for revoked compensation."""
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        sync,
        _event_id,
        _source_record_id,
        outbox_row,
        rollback_action_id,
    ) = await _enqueue_compensation_record(session_factory, store, mock_xdr_client)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, rollback_action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.REJECTED.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_deliver_compensation_record_succeeds_when_rollback_still_approved(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-307 regression: valid compensation still delivers when rollback action is approved."""
    (
        sync,
        _event_id,
        _source_record_id,
        outbox_row,
        _rollback_action_id,
    ) = await _enqueue_compensation_record(session_factory, store, mock_xdr_client)

    await sync.deliver_outbox(outbox_row.outbox_id)

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value
        assert row.latest_writeback_status in {
            WritebackStatus.ACCEPTED.value,
            WritebackStatus.CONFIRMED.value,
        }
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert receipts


@pytest.mark.asyncio
async def test_worker_deliver_compensation_record_succeeds_when_rollback_still_approved(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-307 regression: worker lease path still delivers valid compensation."""
    (
        sync,
        _event_id,
        _source_record_id,
        outbox_row,
        _rollback_action_id,
    ) = await _enqueue_compensation_record(session_factory, store, mock_xdr_client)

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value
        assert row.latest_writeback_status in {
            WritebackStatus.ACCEPTED.value,
            WritebackStatus.CONFIRMED.value,
        }
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert receipts


@pytest.mark.asyncio
async def test_deliver_event_status_update_rejected_after_approval_revoked(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-290: terminal EVENT_STATUS_UPDATE must fail-closed after revoke."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    sync, _event_id, _source_record_id, outbox_row = await _enqueue_terminal_event_status_update(
        session_factory,
        store,
        mock_xdr_client,
    )
    action_id = outbox_row.action_id

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.REJECTED.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    await sync.deliver_outbox(outbox_row.outbox_id)

    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        assert row.last_error_detail is not None
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert receipts == []


@pytest.mark.asyncio
async def test_deliver_event_status_update_rejected_after_supersede(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-290: EVENT_STATUS_UPDATE whose action was superseded after enqueue must not deliver."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    sync, _event_id, _source_record_id, outbox_row = await _enqueue_terminal_event_status_update(
        session_factory,
        store,
        mock_xdr_client,
    )
    action_id = outbox_row.action_id

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.SUCCESS.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    await sync.deliver_outbox(outbox_row.outbox_id)

    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        assert row.last_error_detail is not None
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert receipts == []


@pytest.mark.asyncio
async def test_worker_deliver_event_status_update_rejected_after_approval_revoked(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-290: worker lease path must fail-closed for revoked terminal writeback."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    sync, _event_id, _source_record_id, outbox_row = await _enqueue_terminal_event_status_update(
        session_factory,
        store,
        mock_xdr_client,
    )
    action_id = outbox_row.action_id

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.REJECTED.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_worker_deliver_event_status_update_rejected_after_supersede(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-290: worker lease path must fail-closed for superseded terminal writeback."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    sync, _event_id, _source_record_id, outbox_row = await _enqueue_terminal_event_status_update(
        session_factory,
        store,
        mock_xdr_client,
    )
    action_id = outbox_row.action_id

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.SUCCESS.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_accepted_then_confirmed_receipts_are_append_only(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-290: approved terminal EVENT_STATUS_UPDATE still delivers to CONFIRMED."""
    sync, _event_id, _source_record_id, outbox_row = await _enqueue_terminal_event_status_update(
        session_factory,
        store,
        mock_xdr_client,
    )

    await sync.deliver_outbox(outbox_row.outbox_id)

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value
        assert row.latest_writeback_status == WritebackStatus.CONFIRMED.value
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                ).order_by(orm.DispositionReceipt.sequence)
            )
        ).all()
        assert [receipt.status for receipt in receipts] == [
            WritebackStatus.ACCEPTED.value,
            WritebackStatus.CONFIRMED.value,
        ]
        assert [receipt.sequence for receipt in receipts] == [1, 2]


@pytest.mark.asyncio
async def test_readback_failure_event_is_published_only_after_accepted_receipt_commit(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sync, event_id, _source_record_id, outbox_row = await _enqueue_terminal_event_status_update(
        session_factory,
        store,
        mock_xdr_client,
    )
    bus = AsyncMock()
    bus.publish_event.return_value = True
    sync._bus = bus  # type: ignore[assignment]
    adapter = sync._adapters.get("mock_xdr")
    monkeypatch.setattr(
        adapter,
        "confirm_readback",
        AsyncMock(side_effect=TimeoutError("readback timeout")),
    )

    await sync.deliver_outbox(outbox_row.outbox_id)

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt)
                .where(orm.DispositionReceipt.writeback_id == row.writeback_id)
                .order_by(orm.DispositionReceipt.sequence)
            )
        ).all()
        assert [receipt.status for receipt in receipts] == [WritebackStatus.ACCEPTED.value]
    assert any(
        call.args[0] == event_id and call.args[1] == "writeback_readback_failed"
        for call in bus.publish_event.await_args_list
    )


async def _enqueue_terminal_event_status_update(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    *,
    target_disposition: SourceDisposition = SourceDisposition.CONTAINED,
    idempotency_key: str | None = None,
    logical_slot: str = "terminal",
) -> tuple[DispositionSyncService, str, str, orm.DispositionOutbox]:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    idem = idempotency_key or f"idem-terminal-{_sfx()}"
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-terminal",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "close event",
            "tool_name": "update_event_disposition",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "event",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": idem,
        }
    )
    command = factory.build_event_status_update(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="test-operator",
        disposition_id=new_disposition_id(),
        closure_cycle=1,
        target_disposition=target_disposition,
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
                logical_slot=logical_slot,
            )
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, record.outbox_id)
        assert row is not None
    return sync, event_id, source_record_id, row


@pytest.mark.asyncio
async def test_superseded_outbox_not_claimed_by_worker(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-273: superseded rows with delayed-retry shape must never be claimed."""
    sync, event_id, source_record_id, first_row = await _enqueue_terminal_event_status_update(
        session_factory,
        store,
        mock_xdr_client,
    )
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": first_row.action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-terminal-2",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "close event",
            "tool_name": "update_event_disposition",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "event",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": first_row.command_payload["source_locator"],
            "idempotency_key": f"idem-supersede-{_sfx()}",
        }
    )
    locator = SourceObjectLocator.model_validate(first_row.command_payload["source_locator"])
    concurrency_token = first_row.command_payload.get("source_concurrency_token")
    command = factory.build_event_status_update(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="test-operator",
        disposition_id=new_disposition_id(),
        closure_cycle=1,
        target_disposition=SourceDisposition.COMPLETED,
    )
    async with session_factory() as session:
        async with session.begin():
            second = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
                logical_slot="terminal",
            )

    async with session_factory() as session:
        async with session.begin():
            old = await session.get(orm.DispositionOutbox, first_row.outbox_id)
            assert old is not None
            assert old.superseded_by_disposition_id is not None
            assert old.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
            old.delivery_status = OutboxDeliveryStatus.WAITING_RETRY.value
            old.next_retry_at = datetime.now(UTC) - timedelta(seconds=1)
            # Isolate the superseded row: leave no other claimable active head.
            new_head = await session.get(orm.DispositionOutbox, second.outbox_id)
            assert new_head is not None
            new_head.delivery_status = OutboxDeliveryStatus.DELIVERED.value

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    worker = OutboxWorker(sync)
    claimed = await worker.run_once(limit=10)
    assert claimed == 0
    assert submit_calls == 0


@pytest.mark.asyncio
async def test_superseded_outbox_pre_egress_blocks_delivery(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-273: pre-egress CAS must block delivery of a superseded head."""
    sync, _event_id, _source_record_id, first_row = await _enqueue_terminal_event_status_update(
        session_factory,
        store,
        mock_xdr_client,
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.DispositionOutbox, first_row.outbox_id)
            assert row is not None
            row.superseded_by_disposition_id = "disp-newer-head"
            row.delivery_status = OutboxDeliveryStatus.READY.value

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    await sync.deliver_outbox(first_row.outbox_id)
    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, first_row.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == OUTBOX_SUPERSEDED_ERROR_CODE


@pytest.mark.asyncio
async def test_idempotent_enqueue_returns_existing_head_without_superseding(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-273: identical payload/token/cycle replays return the existing active head."""
    idem = f"idem-replay-{_sfx()}"
    sync, event_id, source_record_id, first_row = await _enqueue_terminal_event_status_update(
        session_factory,
        store,
        mock_xdr_client,
        idempotency_key=idem,
    )
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": first_row.action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-terminal",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "close event",
            "tool_name": "update_event_disposition",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "event",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": first_row.command_payload["source_locator"],
            "idempotency_key": idem,
        }
    )
    locator = SourceObjectLocator.model_validate(first_row.command_payload["source_locator"])
    command = factory.build_event_status_update(
        action,
        source_locator=locator,
        source_concurrency_token=first_row.command_payload.get("source_concurrency_token"),
        operator_id="test-operator",
        disposition_id=first_row.disposition_id,
        closure_cycle=1,
        target_disposition=SourceDisposition.CONTAINED,
    )
    async with session_factory() as session:
        async with session.begin():
            replay = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
                logical_slot="terminal",
            )

    assert replay.outbox_id == first_row.outbox_id
    assert replay.disposition_id == first_row.disposition_id
    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
        )
    assert int(count or 0) == 1


async def _attach_xdr_execution_job(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    action_id: str,
    event_id: str,
    idempotency_key: str,
) -> str:
    job_id = f"job-{_sfx()}"
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_xdr",
                    idempotency_key=idempotency_key,
                    status=ExecutionJobStatus.RUNNING.value,
                    attempt=1,
                    started_at=now,
                )
            )
            action = await session.get(orm.Action, action_id, with_for_update=True)
            assert action is not None
            action.execution_job_id = job_id
    return job_id


@pytest.mark.asyncio
async def test_entity_submit_accepted_receipt_stays_accepted_while_job_reaches_success(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-311: entity receipt stays ACCEPTED; job SUCCESS requires effect readback."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    idempotency_key = f"idem-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            action = await session.get(orm.Action, action_id, with_for_update=True)
            assert action is not None
            action.idempotency_key = idempotency_key
    job_id = await _attach_xdr_execution_job(
        session_factory,
        action_id=action_id,
        event_id=event_id,
        idempotency_key=idempotency_key,
    )
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-mapper",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target_type": "ip",
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": idempotency_key,
            "execution_job_id": job_id,
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    assert await sync.process_ready_outboxes(limit=1) == 1
    async with session_factory() as session:
        receipt = await session.scalar(
            select(orm.DispositionReceipt)
            .where(orm.DispositionReceipt.writeback_id == record.writeback_id)
            .order_by(orm.DispositionReceipt.sequence.desc())
            .limit(1)
        )
        job_row = await session.get(orm.ActionExecutionJob, job_id)
        assert receipt is not None
        assert receipt.status == WritebackStatus.ACCEPTED.value
        assert job_row is not None
        assert job_row.status == ExecutionJobStatus.SUCCESS.value


@pytest.mark.asyncio
async def test_entity_effect_completion_writes_scoped_observation_and_job_success(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-311: provider applied-state readback unlocks verify observation surfaces."""
    from app.providers.tools.mock_provider import (
        MockToolProvider,
        bind_mock_tool_provider,
        get_mock_tool_provider,
    )
    from app.tools.mock_state import MockEnvironmentState

    observation_state = MockEnvironmentState.in_memory()
    with bind_mock_tool_provider(MockToolProvider(observation_state)):
        (
            event_id,
            action_id,
            source_record_id,
            locator,
            concurrency_token,
        ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
        idempotency_key = f"idem-{_sfx()}"
        async with session_factory() as session:
            async with session.begin():
                action = await session.get(orm.Action, action_id, with_for_update=True)
                assert action is not None
                action.idempotency_key = idempotency_key
        job_id = await _attach_xdr_execution_job(
            session_factory,
            action_id=action_id,
            event_id=event_id,
            idempotency_key=idempotency_key,
        )
        sync = _sync_service(session_factory, store, mock_xdr_client)
        factory = DispositionCommandFactory()
        action = Action.model_validate(
            {
                "action_id": action_id,
                "event_id": event_id,
                "plan_revision": 1,
                "action_fingerprint": "fp-obs",
                "action_category": ActionCategory.RESPONSE,
                "action_name": "block ip",
                "tool_name": "block_ip",
                "action_level": ActionLevel.L2,
                "execution_owner": ExecutionOwner.XDR_MANAGED,
                "status": ActionStatus.EXECUTING,
                "target_type": "ip",
                "target": "203.0.113.88",
                "writeback_required": True,
                "writeback_applicable": True,
                "writeback_readiness": WritebackReadiness.READY,
                "disposition_source_ref": locator,
                "idempotency_key": idempotency_key,
                "execution_job_id": job_id,
            }
        )
        command = factory.build_entity_action_submit(
            action,
            source_locator=locator,
            source_concurrency_token=concurrency_token,
            operator_id="ActionExecutionService",
            disposition_id=new_disposition_id(),
            writeback_id="pending",
            closure_cycle=1,
            entity_action_code="block_ip",
        )
        async with session_factory() as session:
            async with session.begin():
                record = await sync.enqueue_command(
                    session,
                    command=command,
                    event_id=event_id,
                    source_record_id=source_record_id,
                )
        original_publish = sync._publish_entity_effect_projection

        async def _projection_unavailable(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("simulated observation projection outage")

        monkeypatch.setattr(
            sync,
            "_publish_entity_effect_projection",
            _projection_unavailable,
        )
        assert await sync.process_ready_outboxes(limit=1) == 1
        async with session_factory() as session:
            pending_job = await session.get(orm.ActionExecutionJob, job_id)
            assert pending_job is not None
            assert pending_job.status == ExecutionJobStatus.SUCCESS.value
            assert (pending_job.raw_result or {}).get("effect_projection_pending") is True
        assert (
            await observation_state.get_observation(
                "ip_blocks",
                "203.0.113.88",
                include_pending=True,
                job_id=job_id,
            )
            is None
        )
        monkeypatch.setattr(
            sync,
            "_publish_entity_effect_projection",
            original_publish,
        )
        assert await sync.reconcile_pending_entity_effects(limit=1) == 1

        async with session_factory() as session:
            receipt = await session.scalar(
                select(orm.DispositionReceipt)
                .where(orm.DispositionReceipt.writeback_id == record.writeback_id)
                .order_by(orm.DispositionReceipt.sequence.desc())
                .limit(1)
            )
            job_row = await session.get(orm.ActionExecutionJob, job_id)
            assert receipt is not None
            assert receipt.status == WritebackStatus.ACCEPTED.value
            assert job_row is not None
            assert job_row.status == ExecutionJobStatus.SUCCESS.value
            assert isinstance(job_row.raw_result, dict)
            assert job_row.raw_result.get("effect_completion", {}).get("writeback_id") == (
                record.writeback_id
            )
            assert job_row.raw_result.get("effect_projection_pending") is False

        observation = await get_mock_tool_provider().state.get_observation(
            "ip_blocks",
            "203.0.113.88",
            include_pending=True,
            job_id=job_id,
        )
        assert observation is not None
        assert observation.status == "blocked"
        assert observation.action_id == action_id
        assert observation.job_id == job_id
        assert observation.connector == locator.connector_id
        assert observation.value.get("writeback_id") == record.writeback_id
        assert observation.value.get("provider_record_id")

        from app.models.tool_meta import ToolResult
        from app.tools.verify._common import MockVerificationRuntime

        verification = ToolResult.model_validate(
            await MockVerificationRuntime(
                observation_state,
                wait_timeout_ms=100,
                poll_interval_ms=1,
            ).execute(
                "check_ip_block_status",
                {
                    "target_type": "ip",
                    "target": "203.0.113.88",
                    "parameters": {"job_id": job_id},
                },
            )
        )
        assert verification.data["is_verified"] is True
        assert verification.data["detail"] == "observed_status:blocked"
        assert await sync.reconcile_pending_entity_effects(limit=1) == 0


@pytest.mark.asyncio
async def test_entity_submit_accepted_without_readback_keeps_job_non_terminal(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-311: ACCEPTED alone must not mark the execution job SUCCESS."""
    from app.models.disposition import EntityEffectCompletion

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    idempotency_key = f"idem-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            action = await session.get(orm.Action, action_id, with_for_update=True)
            assert action is not None
            action.idempotency_key = idempotency_key
    job_id = await _attach_xdr_execution_job(
        session_factory,
        action_id=action_id,
        event_id=event_id,
        idempotency_key=idempotency_key,
    )
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-no-readback",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target_type": "ip",
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": idempotency_key,
            "execution_job_id": job_id,
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )

    async def _not_applied(
        _self: object,
        _command: DispositionCommand,
        receipt: DispositionReceipt,
    ) -> EntityEffectCompletion:
        return EntityEffectCompletion(
            verified=False,
            disposition_id=command.disposition_id,
            writeback_id=receipt.writeback_id,
            provider_writeback_id=str(
                (receipt.raw_result or {}).get("provider_writeback_id") or receipt.writeback_id
            ),
            action_id=command.action_id,
            entity_action_code="block_ip",
            canonical_target="ip:203.0.113.88",
            target_type="ip",
            target="203.0.113.88",
            applied_status="",
            provider_record_id="",
            observed_version=0,
            provider_code="effect_not_applied",
            provider_message="provider-side entity effect not found",
        )

    from app.adapters.mock_xdr import MockXDRDispositionAdapter

    monkeypatch.setattr(
        MockXDRDispositionAdapter,
        "read_entity_effect_completion",
        _not_applied,
    )

    async with session_factory() as session:
        async with session.begin():
            await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    assert await sync.process_ready_outboxes(limit=1) == 1
    async with session_factory() as session:
        job_row = await session.get(orm.ActionExecutionJob, job_id)
        assert job_row is not None
        assert job_row.status == ExecutionJobStatus.RUNNING.value
        assert (job_row.raw_result or {}).get("effect_completion") is None


@pytest.mark.asyncio
async def test_entity_effect_correlation_mismatch_marks_job_unknown(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-311: mismatched effect evidence must not finalize as SUCCESS."""
    from app.adapters.mock_xdr import MockXDRDispositionAdapter
    from app.models.disposition import EntityEffectCompletion

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    idempotency_key = f"idem-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            action = await session.get(orm.Action, action_id, with_for_update=True)
            assert action is not None
            action.idempotency_key = idempotency_key
    job_id = await _attach_xdr_execution_job(
        session_factory,
        action_id=action_id,
        event_id=event_id,
        idempotency_key=idempotency_key,
    )
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-mismatch",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target_type": "ip",
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": idempotency_key,
            "execution_job_id": job_id,
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )

    async def _mismatched(
        _self: object,
        _command: DispositionCommand,
        receipt: DispositionReceipt,
    ) -> EntityEffectCompletion:
        return EntityEffectCompletion(
            verified=True,
            disposition_id=command.disposition_id,
            writeback_id=receipt.writeback_id,
            provider_writeback_id=str(
                (receipt.raw_result or {}).get("provider_writeback_id") or receipt.writeback_id
            ),
            action_id=command.action_id,
            entity_action_code="block_ip",
            canonical_target="ip:198.51.100.1",
            target_type="ip",
            target="198.51.100.1",
            applied_status="blocked",
            provider_record_id="entfx-forged",
            observed_version=1,
            provider_code="effect_readback_verified",
        )

    monkeypatch.setattr(
        MockXDRDispositionAdapter,
        "read_entity_effect_completion",
        _mismatched,
    )

    async with session_factory() as session:
        async with session.begin():
            await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    assert await sync.process_ready_outboxes(limit=1) == 1
    async with session_factory() as session:
        job_row = await session.get(orm.ActionExecutionJob, job_id)
        assert job_row is not None
        assert job_row.status == ExecutionJobStatus.UNKNOWN.value
        assert (job_row.raw_result or {}).get("effect_completion", {}).get("verified") is False
        assert (job_row.raw_result or {}).get("effect_completion", {}).get("provider_code") == (
            "effect_correlation_mismatch"
        )


@pytest.mark.asyncio
async def test_entity_effect_readback_transport_failure_retries_without_false_success(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-311: transport failures stay retryable; never invent Job SUCCESS."""
    from app.adapters.mock_xdr import MockXDRDispositionAdapter
    from app.core.errors import DependencyUnavailableError

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    idempotency_key = f"idem-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            action = await session.get(orm.Action, action_id, with_for_update=True)
            assert action is not None
            action.idempotency_key = idempotency_key
    job_id = await _attach_xdr_execution_job(
        session_factory,
        action_id=action_id,
        event_id=event_id,
        idempotency_key=idempotency_key,
    )
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-transport",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target_type": "ip",
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": idempotency_key,
            "execution_job_id": job_id,
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    calls = {"n": 0}
    original = MockXDRDispositionAdapter.read_entity_effect_completion

    async def _flaky(
        self: MockXDRDispositionAdapter,
        command_arg: DispositionCommand,
        receipt: DispositionReceipt,
    ):
        calls["n"] += 1
        # deliver-time reconcile + process_ready_outboxes reconcile both fail first
        if calls["n"] <= 2:
            raise DependencyUnavailableError(
                "entity effect completion transport failed",
                details={"disposition_id": command_arg.disposition_id},
            )
        return await original(self, command_arg, receipt)

    monkeypatch.setattr(
        MockXDRDispositionAdapter,
        "read_entity_effect_completion",
        _flaky,
    )

    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    assert await sync.process_ready_outboxes(limit=1) == 1
    async with session_factory() as session:
        outbox = await session.get(orm.DispositionOutbox, record.outbox_id)
        job_row = await session.get(orm.ActionExecutionJob, job_id)
        assert outbox is not None
        assert outbox.delivery_status == OutboxDeliveryStatus.DELIVERED.value
        assert job_row is not None
        assert job_row.status == ExecutionJobStatus.RUNNING.value
        assert (job_row.raw_result or {}).get("effect_completion") is None

    assert await sync.reconcile_pending_entity_effects(limit=1) == 1
    async with session_factory() as session:
        job_row = await session.get(orm.ActionExecutionJob, job_id)
        assert job_row is not None
        assert job_row.status == ExecutionJobStatus.SUCCESS.value
        assert (job_row.raw_result or {}).get("effect_completion", {}).get("verified") is True


@pytest.mark.asyncio
async def test_async_provider_job_entity_effect_reconciles_after_job_success(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    mock_xdr_state: MockXDRState,
    cleanup: None,
) -> None:
    """ISSUE-311: async_disposition entity jobs still reach SUCCESS via readback."""
    from app.mock_xdr.models import MockFailureProfile
    from app.providers.tools.mock_provider import (
        MockToolProvider,
        bind_mock_tool_provider,
    )
    from app.tools.mock_state import MockEnvironmentState

    mock_xdr_state.failure_profile = MockFailureProfile(async_disposition=True)
    observation_state = MockEnvironmentState.in_memory()
    with bind_mock_tool_provider(MockToolProvider(observation_state)):
        (
            event_id,
            action_id,
            source_record_id,
            locator,
            concurrency_token,
        ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
        idempotency_key = f"idem-{_sfx()}"
        async with session_factory() as session:
            async with session.begin():
                action = await session.get(orm.Action, action_id, with_for_update=True)
                assert action is not None
                action.idempotency_key = idempotency_key
        job_id = await _attach_xdr_execution_job(
            session_factory,
            action_id=action_id,
            event_id=event_id,
            idempotency_key=idempotency_key,
        )
        sync = _sync_service(session_factory, store, mock_xdr_client)
        factory = DispositionCommandFactory()
        action = Action.model_validate(
            {
                "action_id": action_id,
                "event_id": event_id,
                "plan_revision": 1,
                "action_fingerprint": "fp-async",
                "action_category": ActionCategory.RESPONSE,
                "action_name": "block ip",
                "tool_name": "block_ip",
                "action_level": ActionLevel.L2,
                "execution_owner": ExecutionOwner.XDR_MANAGED,
                "status": ActionStatus.EXECUTING,
                "target_type": "ip",
                "target": "203.0.113.88",
                "writeback_required": True,
                "writeback_applicable": True,
                "writeback_readiness": WritebackReadiness.READY,
                "disposition_source_ref": locator,
                "idempotency_key": idempotency_key,
                "execution_job_id": job_id,
            }
        )
        command = factory.build_entity_action_submit(
            action,
            source_locator=locator,
            source_concurrency_token=concurrency_token,
            operator_id="ActionExecutionService",
            disposition_id=new_disposition_id(),
            writeback_id="pending",
            closure_cycle=1,
            entity_action_code="block_ip",
        )
        async with session_factory() as session:
            async with session.begin():
                record = await sync.enqueue_command(
                    session,
                    command=command,
                    event_id=event_id,
                    source_record_id=source_record_id,
                )
        assert await sync.process_ready_outboxes(limit=1) == 1
        async with session_factory() as session:
            receipt = await session.scalar(
                select(orm.DispositionReceipt)
                .where(orm.DispositionReceipt.writeback_id == record.writeback_id)
                .order_by(orm.DispositionReceipt.sequence.desc())
                .limit(1)
            )
            job_row = await session.get(orm.ActionExecutionJob, job_id)
            assert receipt is not None
            assert receipt.status == WritebackStatus.ACCEPTED.value
            assert receipt.provider_job_id is not None
            assert job_row is not None
            assert job_row.status == ExecutionJobStatus.SUCCESS.value
            assert (job_row.raw_result or {}).get("effect_completion", {}).get("verified") is True
        observation = await observation_state.get_observation(
            "ip_blocks",
            "203.0.113.88",
            include_pending=True,
            job_id=job_id,
        )
        assert observation is not None
        assert observation.status == "blocked"


class _PublishBus:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    async def publish_event(
        self, event_id: str, message_type: str, payload: dict[str, Any] | None = None
    ) -> bool:
        self.events.append((event_id, message_type, dict(payload or {})))
        return True


async def _independent_session_factory() -> tuple[Any, async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    return engine, factory


def test_confirmed_receipt_never_transitions_to_unknown() -> None:
    with pytest.raises(InvalidStateTransitionError):
        from app.models.workflow import validate_writeback_status_transition as _validate

        _validate(
            WritebackStatus.CONFIRMED,
            WritebackStatus.UNKNOWN,
            evidence_adjudication=True,
        )


@pytest.mark.asyncio
async def test_supersede_after_claim_and_approval_check_never_egresses_old_head(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    sync_a, event_id, source_record_id, first_row = await _enqueue_terminal_event_status_update(
        session_factory, store, mock_xdr_client
    )
    engine_b, factory_b = await _independent_session_factory()
    sync_b = _sync_service(factory_b, store, mock_xdr_client)
    claimed = asyncio.Event()
    proceed = asyncio.Event()

    async def _gate(_claim: object) -> None:
        claimed.set()
        await proceed.wait()

    sync_a._after_delivery_claim = _gate  # type: ignore[method-assign]
    adapter = sync_a._adapters.get("mock_xdr")
    assert adapter is not None
    submit_calls: list[str] = []
    original_submit = adapter.submit

    async def _count_submit(command: DispositionCommand) -> DispositionReceipt:
        submit_calls.append(command.disposition_id)
        return await original_submit(command)

    adapter.submit = _count_submit  # type: ignore[method-assign]
    delivery = asyncio.create_task(sync_a._deliver_outbox(first_row.outbox_id))
    await asyncio.wait_for(claimed.wait(), timeout=5)

    factory = DispositionCommandFactory()
    locator = SourceObjectLocator.model_validate(first_row.command_payload["source_locator"])
    action = Action.model_validate(
        {
            "action_id": first_row.action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-terminal-race",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "close event",
            "tool_name": "update_event_disposition",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "event",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-supersede-{_sfx()}",
        }
    )
    command = factory.build_event_status_update(
        action,
        source_locator=locator,
        source_concurrency_token=first_row.command_payload.get("source_concurrency_token"),
        operator_id="test-operator",
        disposition_id=new_disposition_id(),
        closure_cycle=1,
        target_disposition=SourceDisposition.COMPLETED,
    )
    async with factory_b() as session:
        async with session.begin():
            second = await sync_b.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
                logical_slot="terminal",
            )
    proceed.set()
    await delivery
    await engine_b.dispose()

    assert submit_calls == []
    async with session_factory() as session:
        old = await session.get(orm.DispositionOutbox, first_row.outbox_id)
        new = await session.get(orm.DispositionOutbox, second.outbox_id)
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == first_row.writeback_id
                )
            )
        ).all()
        assert old is not None
        assert new is not None
        assert old.superseded_by_disposition_id == second.disposition_id
        assert old.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert new.superseded_by_disposition_id is None
        assert receipts == []


@pytest.mark.asyncio
async def test_approval_revoke_racing_egress_has_deterministic_winner(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    sync_a, event_id, _source_record_id, first_row = await _enqueue_terminal_event_status_update(
        session_factory, store, mock_xdr_client
    )
    engine_b, factory_b = await _independent_session_factory()
    claimed = asyncio.Event()
    proceed = asyncio.Event()

    async def _gate(_claim: object) -> None:
        claimed.set()
        await proceed.wait()

    sync_a._after_delivery_claim = _gate  # type: ignore[method-assign]
    adapter = sync_a._adapters.get("mock_xdr")
    assert adapter is not None
    submit_calls = 0
    original_submit = adapter.submit

    async def _count_submit(command: DispositionCommand) -> DispositionReceipt:
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(command)

    adapter.submit = _count_submit  # type: ignore[method-assign]
    delivery = asyncio.create_task(sync_a._deliver_outbox(first_row.outbox_id))
    await asyncio.wait_for(claimed.wait(), timeout=5)
    async with factory_b() as session:
        async with session.begin():
            await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            action_row = await session.get(
                orm.Action, first_row.action_id, with_for_update=True
            )
            assert action_row is not None
            action_row.status = ActionStatus.REJECTED.value
            action_row.updated_at = datetime.now(UTC)
    proceed.set()
    await delivery
    await engine_b.dispose()

    assert submit_calls == 0
    async with session_factory() as session:
        outbox = await session.get(orm.DispositionOutbox, first_row.outbox_id)
        action_row = await session.get(orm.Action, first_row.action_id)
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == first_row.writeback_id
                )
            )
        ).all()
        assert outbox is not None
        assert action_row is not None
        assert action_row.status == ActionStatus.REJECTED.value
        assert outbox.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert outbox.last_error_code == "approval_revoked_before_submit"
        assert receipts == []
        assert outbox.superseded_by_disposition_id is None


@pytest.mark.asyncio
async def test_approval_change_during_confirmed_submit_preserves_provider_truth(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.models.workflow import CLOSED_TERMINAL_STRONG_CONFIRMATION_EVIDENCE

    bus = _PublishBus()
    sync, event_id, _source_record_id, first_row = await _enqueue_terminal_event_status_update(
        session_factory, store, mock_xdr_client
    )
    sync._bus = bus  # type: ignore[method-assign]
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    submit_started = asyncio.Event()
    release_submit = asyncio.Event()
    original_submit = adapter.submit

    async def _blocked_submit(command: DispositionCommand) -> DispositionReceipt:
        submit_started.set()
        await release_submit.wait()
        return await original_submit(command)

    adapter.submit = _blocked_submit  # type: ignore[method-assign]
    delivery = asyncio.create_task(sync._deliver_outbox(first_row.outbox_id))
    await asyncio.wait_for(submit_started.wait(), timeout=5)
    async with session_factory() as session:
        async with session.begin():
            action_row = await session.get(orm.Action, first_row.action_id, with_for_update=True)
            assert action_row is not None
            action_row.status = ActionStatus.REJECTED.value
            action_row.updated_at = datetime.now(UTC)
    release_submit.set()
    await delivery

    async with session_factory() as session:
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt)
                .where(orm.DispositionReceipt.writeback_id == first_row.writeback_id)
                .order_by(orm.DispositionReceipt.sequence)
            )
        ).all()
        outbox = await session.get(orm.DispositionOutbox, first_row.outbox_id)
        audit = (
            await session.scalars(
                select(orm.EventAuditLog).where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.reason == "authorization_changed_after_egress",
                )
            )
        ).all()
        assert outbox is not None
        statuses = [row.status for row in receipts]
        assert WritebackStatus.UNKNOWN.value not in statuses
        assert statuses[-1] == WritebackStatus.CONFIRMED.value
        confirmed = receipts[-1]
        assert confirmed.confirmation_evidence == ConfirmationEvidence.READBACK_VERIFIED.value
        assert confirmed.simulated is True
        assert ConfirmationEvidence(confirmed.confirmation_evidence) in (
            CLOSED_TERMINAL_STRONG_CONFIRMATION_EVIDENCE
        )
        assert outbox.latest_writeback_status == WritebackStatus.CONFIRMED.value
        assert outbox.last_error_code == "authorization_changed_after_egress"
        assert audit
    assert any(event[1] == "writeback_updated" for event in bus.events)
    assert all(
        event[2].get("status") != WritebackStatus.UNKNOWN.value
        for event in bus.events
        if event[1] == "writeback_updated"
    )


@pytest.mark.asyncio
async def test_expired_paused_lookup_claim_cannot_finalize_or_publish(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    bus = _PublishBus()
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    sync._bus = bus  # type: ignore[method-assign]
    outbox_id = f"obx-{_sfx()}"
    writeback_id = f"wbk-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=writeback_id,
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload=factory_build_min_command(
                        action_id, event_id, locator, concurrency_token
                    ),
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.PAUSED.value,
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )
    claims = await sync._claim_paused_outboxes(limit=1)
    assert len(claims) == 1
    claim = claims[0]
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.DispositionOutbox, outbox_id, with_for_update=True)
            assert row is not None
            row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    found = DispositionReceipt(
        writeback_id=writeback_id,
        sequence=1,
        disposition_id=claim.disposition_id,
        action_id=action_id,
        source_record_id=source_record_id,
        status=WritebackStatus.CONFIRMED,
        confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
        simulated=True,
        observed_at=datetime.now(UTC),
        submitted_at=datetime.now(UTC),
        confirmed_at=datetime.now(UTC),
    )
    from app.services.disposition_sync_service import _PausedLookupKind, _PausedLookupOutcome

    applied, event_out, status = await sync._apply_paused_lookup_outcome(
        claim,
        _PausedLookupOutcome(kind=_PausedLookupKind.FOUND, receipt=found),
    )
    assert applied is False
    assert event_out is None
    assert status is None
    await sync._release_paused_lookup_claim(claim, error_code="expired", detail="expired")
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == writeback_id
                )
            )
        ).all()
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert row.locked_by == claim.token
        assert receipts == []
    assert bus.events == []


@pytest.mark.asyncio
async def test_reclaimed_paused_lookup_rejects_old_worker_success(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    writeback_id = f"wbk-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=writeback_id,
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload=factory_build_min_command(
                        action_id, event_id, locator, concurrency_token
                    ),
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.PAUSED.value,
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )
    first = await sync._claim_paused_outboxes(limit=1)
    assert len(first) == 1
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.DispositionOutbox, outbox_id, with_for_update=True)
            assert row is not None
            row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    second = await sync._claim_paused_outboxes(limit=1)
    assert len(second) == 1
    assert second[0].token != first[0].token
    found = DispositionReceipt(
        writeback_id=writeback_id,
        sequence=1,
        disposition_id=first[0].disposition_id,
        action_id=action_id,
        source_record_id=source_record_id,
        status=WritebackStatus.CONFIRMED,
        confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
        simulated=True,
        observed_at=datetime.now(UTC),
        submitted_at=datetime.now(UTC),
        confirmed_at=datetime.now(UTC),
    )
    from app.services.disposition_sync_service import _PausedLookupKind, _PausedLookupOutcome

    applied, _, _ = await sync._apply_paused_lookup_outcome(
        first[0],
        _PausedLookupOutcome(kind=_PausedLookupKind.FOUND, receipt=found),
    )
    assert applied is False
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == writeback_id
                )
            )
        ).all()
        assert row is not None
        assert row.locked_by == second[0].token
        assert row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert receipts == []


@pytest.mark.asyncio
async def test_later_claim_in_batch_is_revalidated_before_lookup(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    first_seed = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    second_seed = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    for seq, (event_id, action_id, source_record_id, locator, token) in enumerate(
        (first_seed, second_seed), start=1
    ):
        async with session_factory() as session:
            async with session.begin():
                session.add(
                    orm.DispositionOutbox(
                        outbox_id=f"obx-{_sfx()}",
                        writeback_id=f"wbk-{_sfx()}",
                        disposition_id=f"disp-{_sfx()}",
                        action_id=action_id,
                        event_id=event_id,
                        closure_cycle=1,
                        source_record_id=source_record_id,
                        source_locator_hash="hash",
                        source_sequence=seq,
                        intent_kind="entity_action_submit",
                        logical_slot="default",
                        idempotency_key=f"idem-{_sfx()}",
                        command_payload=factory_build_min_command(
                            action_id, event_id, locator, token
                        ),
                        command_payload_sha256="deadbeef",
                        delivery_status=OutboxDeliveryStatus.PAUSED.value,
                        latest_writeback_status=WritebackStatus.UNKNOWN.value,
                    )
                )
    claims = await sync._claim_paused_outboxes(limit=2)
    assert len(claims) == 2
    later = claims[1]
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.DispositionOutbox, later.outbox_id, with_for_update=True)
            assert row is not None
            row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)

    lookups: list[str] = []
    original_lookup = sync._lookup_paused_outbox

    async def _tracked_lookup(claim: object) -> object:
        lookups.append(claim.outbox_id)  # type: ignore[attr-defined]
        return await original_lookup(claim)  # type: ignore[arg-type]

    async def _frozen_claim(*, limit: int) -> list[object]:
        return claims  # type: ignore[return-value]

    sync._lookup_paused_outbox = _tracked_lookup  # type: ignore[method-assign]
    sync._claim_paused_outboxes = _frozen_claim  # type: ignore[method-assign]
    await sync.reconcile_paused_outboxes(limit=2)
    assert later.outbox_id not in lookups
    async with session_factory() as session:
        later_row = await session.get(orm.DispositionOutbox, later.outbox_id)
        assert later_row is not None
        assert later_row.delivery_status == OutboxDeliveryStatus.PAUSED.value
        assert later_row.locked_by == later.token


def _complete_confirmed_receipt(
    writeback_id: str,
    *,
    evidence: ConfirmationEvidence,
    simulated: bool = True,
    provider_record_id: str = "rec-lookup-1",
    provider_job_id: str = "job-lookup-1",
) -> DispositionReceipt:
    now = datetime.now(UTC)
    return DispositionReceipt(
        writeback_id=writeback_id,
        sequence=1,
        disposition_id="disp-lookup",
        action_id="act-lookup",
        source_record_id="src-lookup",
        status=WritebackStatus.CONFIRMED,
        confirmation_evidence=evidence,
        provider_record_id=provider_record_id,
        provider_job_id=provider_job_id,
        observed_at=now,
        submitted_at=now,
        confirmed_at=now,
        simulated=simulated,
        target_results=[
            TargetWritebackResult(
                canonical_target="host:pc-1",
                status=TargetWritebackStatus.CONFIRMED,
            )
        ],
    )


@pytest.mark.asyncio
async def test_operator_retry_lookup_releases_db_lock_before_provider_io(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.UNKNOWN,
    )
    claimed = asyncio.Event()
    proceed = asyncio.Event()
    lock_acquired = asyncio.Event()
    lookup_started = asyncio.Event()

    async def _gate(_claim: object) -> None:
        claimed.set()
        await proceed.wait()

    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_lookup = adapter.lookup_submission

    async def _lookup(*args: Any, **kwargs: Any) -> Any:
        lookup_started.set()
        assert lock_acquired.is_set()
        return await original_lookup(*args, **kwargs)

    sync._after_operator_retry_claim = _gate  # type: ignore[method-assign]
    adapter.lookup_submission = _lookup  # type: ignore[method-assign]
    engine_b, factory_b = await _independent_session_factory()
    task = asyncio.create_task(sync.retry_writeback(writeback_id, operator="operator-1"))
    await asyncio.wait_for(claimed.wait(), timeout=5)
    async with factory_b() as session:
        async with session.begin():
            await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            await session.get(orm.DispositionOutbox, outbox_id, with_for_update=True)
            await session.get(orm.Action, action_id, with_for_update=True)
            lock_acquired.set()
    proceed.set()
    await task
    await asyncio.wait_for(lookup_started.wait(), timeout=5)
    await engine_b.dispose()


@pytest.mark.asyncio
async def test_operator_retry_stale_lookup_claim_cannot_finalize_or_publish(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    bus = _PublishBus()
    resume = AsyncMock()
    sync = _sync_service(
        session_factory, store, mock_xdr_client, resume=resume, event_bus=bus
    )
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.UNKNOWN,
    )
    claimed = asyncio.Event()
    proceed = asyncio.Event()

    async def _gate(_claim: object) -> None:
        claimed.set()
        await proceed.wait()

    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None

    async def _found(*_args: Any, **_kwargs: Any) -> DispositionReceipt:
        return _complete_confirmed_receipt(
            writeback_id, evidence=ConfirmationEvidence.READBACK_VERIFIED
        )

    sync._after_operator_retry_claim = _gate  # type: ignore[method-assign]
    adapter.lookup_submission = _found  # type: ignore[method-assign]
    engine_b, factory_b = await _independent_session_factory()
    task = asyncio.create_task(sync.retry_writeback(writeback_id, operator="operator-1"))
    await asyncio.wait_for(claimed.wait(), timeout=5)
    async with factory_b() as session:
        async with session.begin():
            await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            outbox = await session.get(
                orm.DispositionOutbox, outbox_id, with_for_update=True
            )
            assert outbox is not None
            outbox.locked_by = "stolen-token"
            outbox.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    proceed.set()
    with pytest.raises(WritebackConflictError, match="expired or stolen"):
        await task
    await engine_b.dispose()
    resume.assert_not_called()
    assert bus.events == []
    async with session_factory() as session:
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == writeback_id
                )
            )
        ).all()
        outbox = await session.get(orm.DispositionOutbox, outbox_id)
        assert receipts == []
        assert outbox is not None
        assert outbox.latest_writeback_status == WritebackStatus.UNKNOWN.value


@pytest.mark.asyncio
async def test_operator_retry_never_accepted_requeues_same_outbox_once(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.UNKNOWN,
    )
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    lookups = 0

    async def _never(*_args: Any, **_kwargs: Any) -> None:
        nonlocal lookups
        lookups += 1
        return None

    adapter.lookup_submission = _never  # type: ignore[method-assign]
    first = await sync.retry_writeback(writeback_id, operator="operator-1")
    second = await sync.retry_writeback(writeback_id, operator="operator-1")
    assert first is WritebackStatus.PENDING
    assert second is WritebackStatus.PENDING
    assert lookups == 1
    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(orm.DispositionOutbox).where(
                    orm.DispositionOutbox.writeback_id == writeback_id
                )
            )
        ).all()
        assert len(rows) == 1
        assert rows[0].outbox_id == outbox_id
        assert rows[0].delivery_status == OutboxDeliveryStatus.READY.value
        assert rows[0].latest_writeback_status == WritebackStatus.PENDING.value


@pytest.mark.asyncio
async def test_recovery_lookup_persists_complete_confirmed_receipt(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.UNKNOWN,
    )
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    expected = _complete_confirmed_receipt(
        writeback_id,
        evidence=ConfirmationEvidence.READBACK_VERIFIED,
        simulated=True,
    )

    async def _found(*_args: Any, **_kwargs: Any) -> DispositionReceipt:
        return expected

    adapter.lookup_submission = _found  # type: ignore[method-assign]
    outcome = await sync.reconcile_writeback_lookup(writeback_id)
    assert outcome.kind is WritebackLookupKind.FOUND
    assert outcome.receipt is not None
    assert outcome.receipt.status is WritebackStatus.CONFIRMED
    async with session_factory() as session:
        row = await session.scalar(
            select(orm.DispositionReceipt)
            .where(orm.DispositionReceipt.writeback_id == writeback_id)
            .order_by(orm.DispositionReceipt.sequence.desc())
        )
        assert row is not None
        assert row.status == WritebackStatus.CONFIRMED.value
        assert row.confirmation_evidence == ConfirmationEvidence.READBACK_VERIFIED.value
        assert row.simulated is True
        assert row.provider_record_id == "rec-lookup-1"
        assert row.provider_job_id == "job-lookup-1"
        assert row.confirmed_at is not None
        assert row.target_results


@pytest.mark.asyncio
async def test_recovery_lookup_preserves_confirmation_evidence_and_simulated(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, _outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.UNKNOWN,
    )
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None

    async def _found(*_args: Any, **_kwargs: Any) -> DispositionReceipt:
        return _complete_confirmed_receipt(
            writeback_id,
            evidence=ConfirmationEvidence.MANUAL_CONFIRMED,
            simulated=False,
        )

    adapter.lookup_submission = _found  # type: ignore[method-assign]
    outcome = await sync.reconcile_writeback_lookup(writeback_id)
    assert outcome.kind is WritebackLookupKind.FOUND
    assert outcome.receipt is not None
    assert outcome.receipt.confirmation_evidence is ConfirmationEvidence.MANUAL_CONFIRMED
    assert outcome.receipt.simulated is False
    async with session_factory() as session:
        row = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.writeback_id == writeback_id
            )
        )
        assert row is not None
        assert row.confirmation_evidence == ConfirmationEvidence.MANUAL_CONFIRMED.value
        assert row.simulated is False


@pytest.mark.asyncio
async def test_recovery_lookup_rejects_result_after_claim_expiry(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    bus = _PublishBus()
    resume = AsyncMock()
    sync = _sync_service(
        session_factory, store, mock_xdr_client, resume=resume, event_bus=bus
    )
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.UNKNOWN,
    )
    claimed = asyncio.Event()
    proceed = asyncio.Event()

    async def _gate(_claim: object) -> None:
        claimed.set()
        await proceed.wait()

    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None

    async def _found(*_args: Any, **_kwargs: Any) -> DispositionReceipt:
        return _complete_confirmed_receipt(
            writeback_id, evidence=ConfirmationEvidence.READBACK_VERIFIED
        )

    sync._after_recovery_lookup_claim = _gate  # type: ignore[method-assign]
    adapter.lookup_submission = _found  # type: ignore[method-assign]
    engine_b, factory_b = await _independent_session_factory()
    task = asyncio.create_task(sync.reconcile_writeback_lookup(writeback_id))
    await asyncio.wait_for(claimed.wait(), timeout=5)
    async with factory_b() as session:
        async with session.begin():
            await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            outbox = await session.get(
                orm.DispositionOutbox, outbox_id, with_for_update=True
            )
            assert outbox is not None
            outbox.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    proceed.set()
    outcome = await task
    await engine_b.dispose()
    assert outcome.kind is WritebackLookupKind.STALE_CLAIM
    resume.assert_not_called()
    assert bus.events == []
    async with session_factory() as session:
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == writeback_id
                )
            )
        ).all()
        assert receipts == []


@pytest.mark.asyncio
async def test_recovery_lookup_cannot_overwrite_newer_confirmed_receipt(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.UNKNOWN,
    )
    claimed = asyncio.Event()
    proceed = asyncio.Event()

    async def _gate(_claim: object) -> None:
        claimed.set()
        await proceed.wait()

    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None

    async def _found(*_args: Any, **_kwargs: Any) -> DispositionReceipt:
        return _complete_confirmed_receipt(
            writeback_id,
            evidence=ConfirmationEvidence.ADAPTER_ACKNOWLEDGED,
            provider_record_id="rec-stale",
        )

    sync._after_recovery_lookup_claim = _gate  # type: ignore[method-assign]
    adapter.lookup_submission = _found  # type: ignore[method-assign]
    engine_b, factory_b = await _independent_session_factory()
    task = asyncio.create_task(sync.reconcile_writeback_lookup(writeback_id))
    await asyncio.wait_for(claimed.wait(), timeout=5)
    now = datetime.now(UTC)
    async with factory_b() as session:
        async with session.begin():
            await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            outbox = await session.get(
                orm.DispositionOutbox, outbox_id, with_for_update=True
            )
            assert outbox is not None
            session.add(
                orm.DispositionReceipt(
                    writeback_id=writeback_id,
                    sequence=1,
                    disposition_id=outbox.disposition_id,
                    action_id=action_id,
                    source_record_id=source_record_id,
                    status=WritebackStatus.CONFIRMED.value,
                    confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED.value,
                    provider_record_id="rec-newer",
                    provider_job_id="job-newer",
                    observed_at=now,
                    submitted_at=now,
                    confirmed_at=now,
                    simulated=True,
                    target_results=[],
                    raw_result={},
                    truncated=False,
                )
            )
            outbox.latest_writeback_status = WritebackStatus.CONFIRMED.value
    proceed.set()
    outcome = await task
    await engine_b.dispose()
    assert outcome.kind is WritebackLookupKind.ALREADY_CONFIRMED
    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(orm.DispositionReceipt)
                .where(orm.DispositionReceipt.writeback_id == writeback_id)
                .order_by(orm.DispositionReceipt.sequence.asc())
            )
        ).all()
        assert len(rows) == 1
        assert rows[0].provider_record_id == "rec-newer"
        assert rows[0].confirmation_evidence == ConfirmationEvidence.READBACK_VERIFIED.value


@pytest.mark.asyncio
async def test_recovery_confirmed_without_strong_evidence_cannot_close(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.models.workflow import (
        ClosedGateActionView,
        TerminalEventWritebackView,
        TransitionContext,
        validate_closed_gate,
    )
    from app.models.side_effect_convergence import SideEffectConvergenceSummary

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id, _outbox_id = await _insert_operator_retry_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        delivery_status=OutboxDeliveryStatus.DELIVERED,
        writeback_status=WritebackStatus.UNKNOWN,
    )
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None

    async def _found(*_args: Any, **_kwargs: Any) -> DispositionReceipt:
        return _complete_confirmed_receipt(
            writeback_id, evidence=ConfirmationEvidence.ADAPTER_ACKNOWLEDGED
        )

    adapter.lookup_submission = _found  # type: ignore[method-assign]
    outcome = await sync.reconcile_writeback_lookup(writeback_id)
    assert outcome.kind is WritebackLookupKind.FOUND
    assert outcome.receipt is not None
    receipt = outcome.receipt
    with pytest.raises(InvalidStateTransitionError, match="strong confirmation_evidence"):
        validate_closed_gate(
            TransitionContext(
                disposition_policy=DispositionPolicy.REQUIRED,
                disposition_is_mock=True,
                report_exists=True,
                applicable_required_actions=[
                    ClosedGateActionView(
                        action_id=action_id,
                        action_category=ActionCategory.RESPONSE,
                        writeback_required=True,
                        writeback_applicable=True,
                        writeback_readiness=WritebackReadiness.READY,
                        writeback_status=WritebackStatus.CONFIRMED,
                        has_command=True,
                        all_required_intents_confirmed=True,
                        tool_name="block_ip",
                    )
                ],
                terminal_event_writeback=TerminalEventWritebackView(
                    action_id=action_id,
                    disposition_id=receipt.disposition_id,
                    writeback_id=writeback_id,
                    closure_cycle=1,
                    approved_disposition=SourceDisposition.CONTAINED,
                    actual_disposition=SourceDisposition.CONTAINED,
                    receipt_status=receipt.status,
                    plan_revision=1,
                    simulated=receipt.simulated,
                    confirmation_evidence=receipt.confirmation_evidence,
                ),
                current_plan_revision=1,
                current_closure_cycle=1,
                side_effect_convergence=SideEffectConvergenceSummary(
                    event_id=event_id,
                    current_plan_revision=1,
                ),
            )
        )
