"""Shared helpers for ISSUE-086 system tests."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.response_agent import compute_template_hash
from app.data_generators.scenarios import build_scenario
from app.db import models as orm
from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.state import MockXDRState
from app.models.agent_io import (
    ScoringMode,
    VerificationOverallStatus,
    VerificationPhase,
)
from app.models.disposition import SourceObjectLocator
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
    ExecutionOwner,
    FinalVerdict,
    SourceDisposition,
    SourceObjectKind,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.ids import new_disposition_id
from app.models.source import SourceReference
from app.services.context_service import EventContextStore, append_context_journal_in_session
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService, _action_from_row
from app.services.event_service import EventService
from tests.integration.conftest import FailingLLMClient
from tests.system.scenario_expectations import ScenarioExpectation

ALL_SOURCE_KINDS = [
    SourceObjectKind.INCIDENT,
    SourceObjectKind.ALERT,
    SourceObjectKind.ASSET,
    SourceObjectKind.LOG,
]


async def ingest_scenario_event(
    *,
    scenario_id: str,
    source_adapter: Any,
    source_ingester: SourceIngester,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
) -> str:
    mock_xdr_state.load_scenario(build_scenario(scenario_id, seed=42))
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=10)
    assert summary.rejected == 0, summary.errors
    listed = await event_service.list_events(status=EventStatus.NEW)
    assert listed.total >= 1
    return listed.items[-1].event_id


async def run_rule_fallback_main_chain(
    *,
    event_id: str,
    run_graph_investigation: Any,
    scenario_id: str,
) -> None:
    await run_graph_investigation(
        event_id,
        llm_client=FailingLLMClient(),
        scenario_id=scenario_id,
    )


async def assert_main_chain_expectations(
    *,
    event_service: EventService,
    context_store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    spec: ScenarioExpectation,
) -> None:
    event = await event_service.get_event(event_id)
    assert event is not None

    triage_ctx = await context_store.get(event_id, "triage_result")
    risk_ctx = await context_store.get(event_id, "risk_assessment")
    report_ctx = await context_store.get(event_id, "report")
    assert triage_ctx is not None
    assert triage_ctx.get("degraded") is True
    triage_type = str(triage_ctx.get("event_type") or "")
    assert triage_type in {member.value for member in EventType}
    assert risk_ctx is not None
    assert risk_ctx.get("scoring_mode") == ScoringMode.RULE_ONLY.value
    assert report_ctx is not None

    if spec.expect_reporting:
        assert event.status in {EventStatus.REPORTING, EventStatus.CLOSED}, (
            f"unexpected terminal status {event.status} for {spec.scenario_id}"
        )
        if event.final_verdict is not None:
            assert event.final_verdict in spec.acceptable_verdicts, (
                f"unexpected verdict {event.final_verdict} for {spec.scenario_id}"
            )
        assert 0 <= int(event.risk_score) <= 100
    else:
        assert event.status is EventStatus.CLOSED
        if event.final_verdict is not None:
            assert event.final_verdict in spec.acceptable_verdicts

    analysis_only_complete = await context_store.get(event_id, "analysis_only_complete")
    assert analysis_only_complete is True

    async with session_factory() as session:
        report_row = await session.scalar(select(orm.Report).where(orm.Report.event_id == event_id))
    assert report_row is not None


async def seed_source_object_for_event(
    session_factory: async_sessionmaker[AsyncSession],
    event: Any,
) -> str:
    ref = SourceReference.model_validate(event.creation_source_ref)
    source_record_id = f"src-{ref.source_object_id}"
    async with session_factory() as session:
        existing = await session.scalar(
            select(orm.SourceObject).where(
                orm.SourceObject.source_product == ref.source_product,
                orm.SourceObject.source_tenant_id == ref.source_tenant_id,
                orm.SourceObject.connector_id == ref.connector_id,
                orm.SourceObject.source_kind == ref.source_kind.value,
                orm.SourceObject.source_object_id == ref.source_object_id,
            )
        )
        if existing is not None:
            return existing.source_record_id

        async with session.begin():
            existing_conn = await session.get(orm.SourceConnector, ref.connector_id)
            if existing_conn is None:
                session.add(
                    orm.SourceConnector(
                        connector_id=ref.connector_id,
                        source_product=ref.source_product,
                        display_name="Mock XDR",
                    )
                )
            session.add(
                orm.SourceObject(
                    source_record_id=source_record_id,
                    source_product=ref.source_product,
                    source_tenant_id=ref.source_tenant_id,
                    connector_id=ref.connector_id,
                    source_kind=ref.source_kind.value,
                    source_object_id=ref.source_object_id,
                    next_outbox_sequence=0,
                )
            )
    return source_record_id


async def insert_response_action(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    action_name: str,
    tool_name: str,
    execution_phase: ActionExecutionPhase,
    status: ActionStatus,
    disposition_source_ref: dict[str, Any],
    target: str = "host-target-1",
    activation_condition: str | None = None,
) -> str:
    approved_raw = [
        SourceDisposition.CONTAINED.value,
        SourceDisposition.COMPLETED.value,
        SourceDisposition.IGNORED.value,
    ]
    approved_hash = compute_template_hash(
        [SourceDisposition.CONTAINED, SourceDisposition.COMPLETED, SourceDisposition.IGNORED]
    )
    action_id = f"act-system-{tool_name}-{event_id[-8:]}"
    if isinstance(disposition_source_ref, SourceObjectLocator):
        locator = disposition_source_ref
    elif isinstance(disposition_source_ref, SourceReference):
        locator = SourceObjectLocator(
            source_product=disposition_source_ref.source_product,
            source_tenant_id=disposition_source_ref.source_tenant_id,
            connector_id=disposition_source_ref.connector_id,
            source_kind=disposition_source_ref.source_kind,
            source_object_type=disposition_source_ref.source_object_type,
            source_object_id=disposition_source_ref.source_object_id,
        )
    else:
        ref = SourceReference.model_validate(disposition_source_ref)
        locator = SourceObjectLocator(
            source_product=ref.source_product,
            source_tenant_id=ref.source_tenant_id,
            connector_id=ref.connector_id,
            source_kind=ref.source_kind,
            source_object_type=ref.source_object_type,
            source_object_id=ref.source_object_id,
        )
    safe_disposition_ref = json.loads(locator.model_dump_json())
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-system-{tool_name}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name=action_name,
                    tool_name=tool_name,
                    action_level=ActionLevel.L2.value,
                    execution_phase=execution_phase.value,
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    status=status.value,
                    writeback_required=True,
                    writeback_applicable=True,
                    writeback_readiness=WritebackReadiness.READY.value,
                    idempotency_key=f"idem-system-{tool_name}-{event_id[-8:]}",
                    target=target,
                    parameters={"target": target},
                    reason="ISSUE-086 system full response chain",
                    approved_operation_template_hash=approved_hash,
                    approved_terminal_dispositions=approved_raw,
                    disposition_source_ref=safe_disposition_ref,
                    activation_condition=activation_condition,
                )
            )
    return action_id


async def submit_entity_action_once(
    session_factory: async_sessionmaker[AsyncSession],
    disposition_sync_service: DispositionSyncService,
    *,
    event_id: str,
    action_id: str,
    mock_xdr_state: MockXDRState,
    source_record_id: str,
) -> None:
    request_counter_before = mock_xdr_state.request_counter
    outbox_id: str | None = None
    factory = DispositionCommandFactory()

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            action = _action_from_row(row)
            token_row = await session.get(orm.SourceObject, source_record_id)
            token = token_row.current_concurrency_token if token_row else None
            disposition_id = new_disposition_id()
            command = factory.build_entity_action_submit(
                action,
                source_locator=action.disposition_source_ref,
                source_concurrency_token=token,
                operator_id="system-test",
                disposition_id=disposition_id,
                writeback_id="pending",
                closure_cycle=int(action.plan_revision),
                entity_action_code="contain_device",
            )
            outbox_record = await disposition_sync_service.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
                logical_slot="entity_action",
            )
            outbox_id = outbox_record.outbox_id
            row.status = ActionStatus.EXECUTING.value

    assert outbox_id is not None
    await disposition_sync_service.deliver_outbox(outbox_id)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.SUCCESS.value

    assert mock_xdr_state.request_counter == request_counter_before + 1


async def prepare_event_for_response_chain(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> None:
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            row.final_verdict = FinalVerdict.CONFIRMED_THREAT.value
            row.risk_score = max(int(row.risk_score or 0), 82)
            row.confidence = max(float(row.confidence or 0.0), 0.9)


async def run_full_response_chain(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    event_disposition_service: EventDispositionService,
    disposition_sync_service: DispositionSyncService,
    mock_xdr_state: MockXDRState,
    event_id: str,
) -> None:
    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status is EventStatus.REPORTING, (
        f"expected REPORTING before response chain, got {event.status}"
    )
    assert event.disposition_policy is DispositionPolicy.REQUIRED

    await prepare_event_for_response_chain(session_factory, event_id)
    event = await event_service.get_event(event_id)
    assert event is not None
    disposition_source_ref = (
        event.creation_source_ref.model_dump(mode="json")
        if hasattr(event.creation_source_ref, "model_dump")
        else dict(event.creation_source_ref)
    )

    source_record_id = await seed_source_object_for_event(session_factory, event)

    terminal_action_id = await insert_response_action(
        session_factory,
        event_id=event_id,
        action_name="update_source_event_disposition",
        tool_name="update_source_event_disposition",
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        status=ActionStatus.APPROVED,
        disposition_source_ref=disposition_source_ref,
        activation_condition="after_effect_resolution",
    )
    immediate_action_id = await insert_response_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        status=ActionStatus.APPROVED,
        disposition_source_ref=disposition_source_ref,
    )

    await submit_entity_action_once(
        session_factory,
        disposition_sync_service,
        event_id=event_id,
        action_id=immediate_action_id,
        mock_xdr_state=mock_xdr_state,
        source_record_id=source_record_id,
    )

    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "verification_result",
                {
                    "overall_status": VerificationOverallStatus.SUCCESS.value,
                    "verification_phase": VerificationPhase.EFFECT.value,
                    "results": [],
                },
            )

    result = await event_disposition_service.activate_and_submit(
        event_id,
        plan_revision=1,
        principal_or_system="system-test",
    )
    assert result.activated is True, result.skipped_reason
    assert result.action_id == terminal_action_id

    refreshed = await event_service.get_event(event_id)
    assert refreshed is not None
    assert refreshed.status in {
        EventStatus.REPORTING,
        EventStatus.VERIFYING,
        EventStatus.CLOSED,
    }

    async with session_factory() as session:
        receipt = await session.scalar(
            select(orm.DispositionReceipt)
            .join(orm.Action, orm.Action.action_id == orm.DispositionReceipt.action_id)
            .where(
                orm.Action.event_id == event_id,
                orm.DispositionReceipt.status == WritebackStatus.CONFIRMED.value,
                orm.DispositionReceipt.confirmation_evidence
                == ConfirmationEvidence.READBACK_VERIFIED.value,
            )
        )
        terminal_outbox = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            )
        )
    assert receipt is not None
    assert terminal_outbox == 1
