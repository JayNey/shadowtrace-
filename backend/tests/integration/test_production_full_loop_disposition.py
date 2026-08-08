"""Production-DI smoke for Verify → terminal disposition → legal close."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRDispositionAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.agents.verify_agent import VerifyAgent
from app.api.v1 import deps
from app.core.config import get_settings
from app.db import models as orm
from app.models.action import Action
from app.models.agent_io import (
    ResponsePlan,
    ResponsePlanGeneratedBy,
    TriageResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerifyAgentInput,
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
    FinalVerdict,
    Severity,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.execution import ActionExecutionJob
from app.models.ids import new_disposition_id, new_job_id
from app.orchestration.workflow_graph import NODE_REPORT, invoke_investigation_graph
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService
from app.services.working_memory import WorkingMemory
from tests.helpers.decision_audit import seed_minimum_disposition_audit
from tests.integration.autonomous_e2e.helpers import patch_production_session_factory
from tests.integration.test_verify_agent_eds_integration import (
    _create_event,
    _deferred_action,
    _insert_action,
    _insert_job,
    _MockObservationExecutor,
    _seed_connector_and_source,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("clean_state"),
]


@pytest.mark.asyncio
async def test_production_disposition_di_confirms_terminal_and_closes(
    session_factory: async_sessionmaker[AsyncSession],
    context_store,
    mock_xdr_client,
    redis_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use production service DI; only the replaceable Mock adapter transport is injected."""
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("DISPOSITION_MODE", "mock_xdr")
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "false")
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "false")
    monkeypatch.setenv("ORCHESTRATION_MODE", "graph")
    get_settings.cache_clear()
    deps.reset_deps()
    patch_production_session_factory(monkeypatch, session_factory)

    registry = DispositionAdapterRegistry()
    registry.register(
        "mock_xdr",
        MockXDRDispositionAdapter(
            client=mock_xdr_client,
            read_token="mock-read-token",
            write_token="mock-write-token",
        ),
    )
    monkeypatch.setattr(deps, "_adapter_registry", registry)

    try:
        disposition_sync = await deps.get_disposition_sync()
        disposition_service = await deps.get_event_disposition_service()
        event_service = await deps.get_event_service()

        assert type(disposition_sync) is DispositionSyncService
        assert type(disposition_service) is EventDispositionService

        source_record_id = await _seed_connector_and_source(
            session_factory,
            mock_xdr_client=mock_xdr_client,
        )
        event_id = await _create_event(session_factory, context_store)
        immediate_id = f"act-prod-{uuid.uuid4().hex[:8]}"
        job_id = new_job_id()
        deferred = _deferred_action(event_id=event_id).model_copy(
            update={"action_name": "Deferred terminal disposition"}
        )
        assert deferred.disposition_source_ref is not None
        immediate = Action.model_validate(
            {
                "action_id": immediate_id,
                "event_id": event_id,
                "plan_revision": 1,
                "action_fingerprint": f"fp-{immediate_id}",
                "action_category": ActionCategory.RESPONSE,
                "action_name": "Block the selected address",
                "tool_name": "block_ip",
                "action_level": ActionLevel.L2,
                "execution_owner": ExecutionOwner.DIRECT_TOOL,
                "execution_phase": ActionExecutionPhase.IMMEDIATE,
                "status": ActionStatus.SUCCESS,
                "target_type": "ip",
                "target": "203.0.113.88",
                "writeback_required": True,
                "writeback_applicable": False,
                "writeback_readiness": WritebackReadiness.NOT_REQUIRED,
                "disposition_source_ref": deferred.disposition_source_ref,
                "execution_job_id": job_id,
                "idempotency_key": f"idem-{immediate_id}",
            }
        )
        await _insert_action(session_factory, event_id, immediate)
        await _insert_action(session_factory, event_id, deferred)
        await _insert_job(
            session_factory,
            event_id=event_id,
            action_id=immediate_id,
            job_id=job_id,
        )
        execution_job = ActionExecutionJob(
            job_id=job_id,
            event_id=event_id,
            action_id=immediate_id,
            provider_name="mock_observation",
            idempotency_key=f"idem-{job_id}",
            status=ExecutionJobStatus.SUCCESS,
        )
        async with session_factory() as session:
            async with session.begin():
                source_row = await session.get(orm.SourceObject, source_record_id)
                assert source_row is not None
                execution_result_command = (
                    DispositionCommandFactory().build_execution_result_record(
                        immediate,
                        execution_job,
                        source_locator=deferred.disposition_source_ref,
                        source_concurrency_token=source_row.current_concurrency_token,
                        operator_id="production_disposition_smoke",
                        disposition_id=new_disposition_id(),
                        closure_cycle=1,
                    )
                )
                await disposition_sync.enqueue_command(
                    session,
                    command=execution_result_command,
                    event_id=event_id,
                    source_record_id=source_record_id,
                    logical_slot=f"execution_result:{immediate_id}",
                    guard_context={
                        "approved_action_ids": [immediate_id, deferred.action_id],
                    },
                )
        delivered = await disposition_sync.process_ready_outboxes(limit=10)
        assert delivered >= 1
        await seed_minimum_disposition_audit(session_factory, event_id)

        agent = VerifyAgent(
            tool_executor=_MockObservationExecutor(),
            working_memory=WorkingMemory(
                store=context_store,
                redis=redis_client,
            ).for_writer("VerifyAgent"),
            session_factory=session_factory,
            event_disposition_service=disposition_service,
            disposition_sync_service=disposition_sync,
        )
        result = await agent.execute(
            VerifyAgentInput(
                event_id=event_id,
                response_plan=ResponsePlan(
                    plan_id=f"plan-{uuid.uuid4().hex[:8]}",
                    actions=[immediate, deferred],
                    strategy_summary="production DI smoke",
                    generated_by=ResponsePlanGeneratedBy.TEMPLATE,
                ),
                verification_phase=VerificationPhase.EFFECT,
            )
        )
        async with session_factory() as session:
            receipt_diagnostics = [
                {
                    "writeback_id": row.writeback_id,
                    "sequence": row.sequence,
                    "status": row.status,
                    "evidence": row.confirmation_evidence,
                    "provider_code": row.provider_code,
                }
                for row in (
                    await session.scalars(
                        select(orm.DispositionReceipt)
                        .join(
                            orm.DispositionOutbox,
                            orm.DispositionOutbox.writeback_id
                            == orm.DispositionReceipt.writeback_id,
                        )
                        .where(orm.DispositionOutbox.event_id == event_id)
                        .order_by(
                            orm.DispositionReceipt.writeback_id,
                            orm.DispositionReceipt.sequence,
                        )
                    )
                ).all()
            ]
        assert result.overall_status is VerificationOverallStatus.SUCCESS, {
            "result": result.model_dump(mode="json"),
            "receipts": receipt_diagnostics,
        }

        async with session_factory() as session:
            execution_outbox = await session.scalar(
                select(orm.DispositionOutbox).where(
                    orm.DispositionOutbox.event_id == event_id,
                    orm.DispositionOutbox.action_id == immediate_id,
                    orm.DispositionOutbox.intent_kind
                    == DispositionIntentKind.EXECUTION_RESULT_RECORD.value,
                )
            )
            execution_receipt = await session.scalar(
                select(orm.DispositionReceipt)
                .join(
                    orm.DispositionOutbox,
                    orm.DispositionOutbox.writeback_id == orm.DispositionReceipt.writeback_id,
                )
                .where(
                    orm.DispositionOutbox.event_id == event_id,
                    orm.DispositionOutbox.action_id == immediate_id,
                    orm.DispositionOutbox.intent_kind
                    == DispositionIntentKind.EXECUTION_RESULT_RECORD.value,
                )
                .order_by(orm.DispositionReceipt.sequence.desc())
                .limit(1)
            )
            terminal_count = int(
                await session.scalar(
                    select(func.count())
                    .select_from(orm.DispositionOutbox)
                    .join(orm.Action, orm.Action.action_id == orm.DispositionOutbox.action_id)
                    .where(
                        orm.DispositionOutbox.event_id == event_id,
                        orm.DispositionOutbox.intent_kind
                        == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                        orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                        orm.Action.plan_revision == 1,
                        orm.Action.superseded_by_revision.is_(None),
                    )
                )
                or 0
            )
            terminal_receipt = await session.scalar(
                select(orm.DispositionReceipt)
                .join(
                    orm.DispositionOutbox,
                    orm.DispositionOutbox.writeback_id == orm.DispositionReceipt.writeback_id,
                )
                .join(orm.Action, orm.Action.action_id == orm.DispositionOutbox.action_id)
                .where(
                    orm.DispositionOutbox.event_id == event_id,
                    orm.DispositionOutbox.intent_kind
                    == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                    orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                    orm.Action.plan_revision == 1,
                    orm.Action.superseded_by_revision.is_(None),
                )
                .order_by(orm.DispositionReceipt.sequence.desc())
                .limit(1)
            )
        assert execution_outbox is not None
        assert execution_outbox.delivery_status == "delivered"
        assert execution_receipt is not None
        assert execution_receipt.status == WritebackStatus.ACCEPTED.value
        assert terminal_count == 1
        assert terminal_receipt is not None
        assert terminal_receipt.status == WritebackStatus.CONFIRMED.value
        assert (
            terminal_receipt.confirmation_evidence == ConfirmationEvidence.READBACK_VERIFIED.value
        )

        await event_service.transition_status(
            event_id,
            EventStatus.REPORTING,
            operator="production_disposition_smoke",
            reason="verification complete",
        )
        async with session_factory() as session:
            async with session.begin():
                session.add(
                    orm.Report(
                        report_id=f"rpt-{uuid.uuid4().hex[:8]}",
                        event_id=event_id,
                        title="Production disposition smoke report",
                        sections=[],
                    )
                )
        super_agent = await deps.get_super_agent()
        production_graph = getattr(super_agent, "_investigation_graph", None)
        assert production_graph is not None
        graph_config = {"configurable": {"thread_id": event_id}}
        triage = TriageResult(
            event_type=EventType.OTHER,
            severity=Severity.HIGH,
            need_investigation=True,
            reasoning="production disposition smoke",
        )
        await production_graph.aupdate_state(
            graph_config,
            {
                "event_id": event_id,
                "event_status": EventStatus.REPORTING.value,
                "disposition_policy": DispositionPolicy.REQUIRED.value,
                "triage_result": triage.model_dump(mode="json"),
                "final_verdict": FinalVerdict.CONFIRMED_THREAT.value,
                "need_investigation": True,
                "generate_report": True,
                "report_generated": True,
                "verify_overall_status": VerificationOverallStatus.SUCCESS.value,
                "halted": False,
                "degraded_flags": [],
                "node_trace": [],
            },
            as_node=NODE_REPORT,
        )
        await invoke_investigation_graph(production_graph, None, graph_config)
        closed = await event_service.get_event(event_id)
        assert closed is not None
        assert closed.status is EventStatus.CLOSED
    finally:
        deps.reset_deps()
        get_settings.cache_clear()
