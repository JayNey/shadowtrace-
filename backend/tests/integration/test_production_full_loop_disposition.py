"""Production-DI smoke for Verify → terminal disposition → legal close."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRDispositionAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.api.v1 import deps
from app.core.config import get_settings
from app.db import models as orm
from app.models.action import Action
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    RiskAssessment,
    ScoringMode,
    TriageResult,
    VerificationOverallStatus,
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
from app.orchestration.workflow_graph import NODE_EXECUTE, invoke_investigation_graph
from app.services.decision_record_service import DecisionRecordService
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService
from tests.integration.autonomous_e2e.helpers import patch_production_session_factory
from tests.integration.test_verify_agent_eds_integration import (
    _create_event,
    _deferred_action,
    _insert_action,
    _insert_job,
    _seed_connector_and_source,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("clean_state"),
]

ARTIFACT_PATH = (
    Path(__file__).resolve().parent / "artifacts" / "latest_production_disposition_audit.json"
)


async def _write_closure_diagnostics(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: Any,
    event_id: str | None,
    graph: Any,
    *,
    failure: Exception | None = None,
) -> None:
    payload: dict[str, Any] = {
        "event_id": event_id,
        "result": "failed" if failure is not None else "passed",
    }
    if failure is not None:
        payload["failure"] = {
            "type": type(failure).__name__,
            "message": str(failure)[:500],
        }
    if event_id is not None:
        payload["verification_result"] = await context_store.get(
            event_id,
            "verification_result",
        )
        async with session_factory() as session:
            event = await session.get(orm.SecurityEvent, event_id)
            outboxes = list(
                await session.scalars(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.event_id == event_id)
                    .order_by(
                        orm.DispositionOutbox.created_at,
                        orm.DispositionOutbox.writeback_id,
                    )
                )
            )
            receipts = list(
                await session.scalars(
                    select(orm.DispositionReceipt)
                    .join(
                        orm.DispositionOutbox,
                        orm.DispositionOutbox.writeback_id == orm.DispositionReceipt.writeback_id,
                    )
                    .where(orm.DispositionOutbox.event_id == event_id)
                    .order_by(
                        orm.DispositionReceipt.writeback_id,
                        orm.DispositionReceipt.sequence,
                    )
                )
            )
        payload["event_status"] = event.status if event is not None else None
        payload["outboxes"] = [
            {
                "writeback_id": row.writeback_id,
                "action_id": row.action_id,
                "intent_kind": row.intent_kind,
                "delivery_status": row.delivery_status,
                "latest_writeback_status": row.latest_writeback_status,
                "last_error_code": row.last_error_code,
            }
            for row in outboxes
        ]
        payload["receipts"] = [
            {
                "writeback_id": row.writeback_id,
                "sequence": row.sequence,
                "status": row.status,
                "confirmation_evidence": row.confirmation_evidence,
                "provider_code": row.provider_code,
            }
            for row in receipts
        ]
        if graph is not None:
            try:
                snapshot = await graph.aget_state({"configurable": {"thread_id": event_id}})
                values = dict(snapshot.values or {})
                payload["checkpoint"] = {
                    key: values.get(key)
                    for key in (
                        "event_status",
                        "execution_substate",
                        "halted",
                        "verify_overall_status",
                        "verify_need_action_replan",
                        "verify_need_writeback_recovery",
                        "verify_need_manual_resolution",
                        "node_trace",
                    )
                }
            except Exception as exc:  # noqa: BLE001 - preserve primary gate failure
                payload["checkpoint"] = {"collection_error": type(exc).__name__}
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH.write_text(
        json.dumps(payload, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


@pytest.mark.asyncio
async def test_production_disposition_di_confirms_terminal_and_closes(
    session_factory: async_sessionmaker[AsyncSession],
    context_store,
    mock_xdr_client,
    tool_executor,
    mock_provider,
    job_store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use production service DI; only the replaceable Mock adapter transport is injected."""
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("DISPOSITION_MODE", "mock_xdr")
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "false")
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "false")
    monkeypatch.setenv("ORCHESTRATION_MODE", "graph")
    monkeypatch.setenv("BUDGET_ENABLED", "false")
    monkeypatch.setattr("app.tools.executor.get_tool_executor", lambda: tool_executor)
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

    event_id: str | None = None
    production_graph: Any = None
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
        await job_store.seed_job(
            ActionExecutionJob(
                job_id=job_id,
                event_id=event_id,
                action_id=immediate_id,
                provider_name="mock_tool_provider",
                idempotency_key=immediate.idempotency_key,
                status=ExecutionJobStatus.QUEUED,
            )
        )
        await _insert_job(
            session_factory,
            event_id=event_id,
            action_id=immediate_id,
            job_id=job_id,
        )
        queued = await tool_executor.call(
            "block_ip",
            {
                "target_type": "ip",
                "target": immediate.target,
                "parameters": {},
            },
            event_id,
            action_id=immediate_id,
            execution_job_id=job_id,
            idempotency_key=immediate.idempotency_key,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        completed = await mock_provider.run_job(queued.job_id)
        assert completed.status is ExecutionJobStatus.SUCCESS
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
        triage = TriageResult(
            event_type=EventType.OTHER,
            severity=Severity.HIGH,
            need_investigation=True,
            reasoning="production disposition smoke",
        )
        evidence = EvidenceOutput(collection_status=CollectionStatus.COMPLETED)
        risk = RiskAssessment(
            risk_score=80,
            severity=Severity.HIGH,
            confidence=0.9,
            scoring_mode=ScoringMode.RULE_ONLY,
        )
        response_plan = ResponsePlan(
            plan_id=f"plan-{uuid.uuid4().hex[:8]}",
            actions=[immediate, deferred],
            strategy_summary="production DI smoke",
            generated_by=ResponsePlanGeneratedBy.TEMPLATE,
        )
        await DecisionRecordService(session_factory).persist_from_agent_trace(
            event_id=event_id,
            agent_name="triage_agent",
            trace_id=f"trc-{uuid.uuid4().hex[:8]}",
            input_data={"event_id": event_id},
            output_data=triage,
        )

        super_agent = await deps.get_super_agent()
        production_graph = getattr(super_agent, "_investigation_graph", None)
        assert production_graph is not None
        graph_config = {"configurable": {"thread_id": event_id}}
        await production_graph.aupdate_state(
            graph_config,
            {
                "event_id": event_id,
                "event_status": EventStatus.VERIFYING.value,
                "disposition_policy": DispositionPolicy.REQUIRED.value,
                "triage_result": triage.model_dump(mode="json"),
                "evidence_output": evidence.model_dump(mode="json"),
                "risk_assessment": risk.model_dump(mode="json"),
                "response_plan": response_plan.model_dump(mode="json"),
                "plan_revision": 1,
                "final_verdict": FinalVerdict.CONFIRMED_THREAT.value,
                "need_investigation": True,
                "execution_ok": True,
                "generate_report": True,
                "halted": False,
                "degraded_flags": [],
                "node_trace": [],
            },
            # The next production node must be Verify; the test does not invoke
            # VerifyAgent, report, or close directly.
            as_node=NODE_EXECUTE,
        )
        await invoke_investigation_graph(production_graph, None, graph_config)
        graph_snapshot = await production_graph.aget_state(graph_config)
        assert graph_snapshot.values.get("verify_overall_status") == (
            VerificationOverallStatus.SUCCESS.value
        )

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
            terminal_outbox = await session.scalar(
                select(orm.DispositionOutbox)
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
            terminal_confirmed_count = int(
                await session.scalar(
                    select(func.count())
                    .select_from(orm.DispositionReceipt)
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
                        orm.DispositionReceipt.status == WritebackStatus.CONFIRMED.value,
                        orm.DispositionReceipt.confirmation_evidence
                        == ConfirmationEvidence.READBACK_VERIFIED.value,
                    )
                )
                or 0
            )
        assert execution_outbox is not None
        assert execution_outbox.delivery_status == "delivered"
        assert execution_receipt is not None
        assert execution_receipt.status == WritebackStatus.ACCEPTED.value
        assert terminal_count == 1
        assert terminal_outbox is not None
        assert terminal_outbox.delivery_status == "delivered"
        assert terminal_confirmed_count == 1
        assert terminal_receipt is not None
        assert terminal_receipt.status == WritebackStatus.CONFIRMED.value
        assert (
            terminal_receipt.confirmation_evidence == ConfirmationEvidence.READBACK_VERIFIED.value
        )

        closed = await event_service.get_event(event_id)
        assert closed is not None
        assert closed.status is EventStatus.CLOSED
        async with session_factory() as session:
            status_sequence = list(
                await session.scalars(
                    select(orm.EventAuditLog.to_status)
                    .where(
                        orm.EventAuditLog.event_id == event_id,
                        orm.EventAuditLog.to_status.is_not(None),
                    )
                    .order_by(
                        orm.EventAuditLog.created_at.asc(),
                        orm.EventAuditLog.id.asc(),
                    )
                )
            )
        assert EventStatus.REPORTING.value in status_sequence
        assert EventStatus.CLOSED.value in status_sequence
        assert status_sequence.index(EventStatus.REPORTING.value) < status_sequence.index(
            EventStatus.CLOSED.value
        )
        await _write_closure_diagnostics(
            session_factory,
            context_store,
            event_id,
            production_graph,
        )
    except Exception as exc:
        await _write_closure_diagnostics(
            session_factory,
            context_store,
            event_id,
            production_graph,
            failure=exc,
        )
        raise
    finally:
        deps.reset_deps()
        get_settings.cache_clear()
