"""Adversarial production full loop through SuperAgent graph and disposition writeback.

Uses production ``execute_investigation(include_response_execution=True)`` wiring.
Does **not** inject APPROVED actions via ``run_full_response_chain`` or verify-tail shims.

ISSUE-203 quality gates (hard failures):
- Terminal ``REPORTING``/``CLOSED`` with non-empty report
- ``response_agent``/``verify_agent`` traces (snake_case agent_name)
- Response plan covers enforced ``GROUND_TRUTH.must_response_targets`` (DB host gated)
- Mock writeback ``CONFIRMED(readback_verified)`` + terminal outbox enqueued
- ``sunset_shims_used`` must be empty; intentional adversarial DI is reported separately.

Default runner timeout: ~120s (Mock). Override with ``ADVERSARIAL_FULL_LOOP_TIMEOUT_S``
(Live ``LLM_MODE=openai_compatible`` defaults to 600s unless overridden).

    cd backend
    export DATABASE_URL=postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace
    export REDIS_URL=redis://localhost:6379/0
    uv run --frozen python -m pytest \\
        tests/adversarial/test_agent_adversarial_full_loop.py -m adversarial_audit -v -s -o addopts=

Artifact: ``tests/adversarial/artifacts/latest_full_loop_audit.json``
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import get_super_agent
from app.core.config import get_settings
from app.db import models as orm
from app.models.agent_io import ResponsePlan, ResponsePlanGeneratedBy
from app.models.enums import EventStatus
from app.services.context_service import EventContextStore
from app.services.event_service import EventService
from tests.adversarial.audit_report import (
    AdversarialAuditChecks,
    coerce_quality_scores,
    normalize_enum,
    resolve_observed_severity,
)
from tests.adversarial.full_loop_runner import run_production_full_loop
from tests.adversarial.helpers import (
    assert_opaque_alert_quality,
    audit_required_signals,
    block_ip_reason_destination_mislabels,
    build_alert_corpus,
    build_narrative_corpus,
    ingest_true_positive_event,
    missing_response_targets,
    opaque_scorecard_tokens,
    response_plan_targets,
    strict_disposition_targets_enabled,
)
from tests.adversarial.scenario_credential_db_staging_exfil import GROUND_TRUTH, HOST_DB

pytestmark = [pytest.mark.integration, pytest.mark.adversarial_audit]

ARTIFACT_PATH = Path(__file__).resolve().parent / "artifacts" / "latest_full_loop_audit.json"
_GENERATED_BY_VALUES = {item.value for item in ResponsePlanGeneratedBy}


def _action_status_by_id(rows: list[Any]) -> dict[str, str]:
    by_id: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        action_id = str(row.get("action_id") or "")
        if not action_id:
            continue
        by_id[action_id] = str(row.get("status") or "").lower()
    return by_id


async def _assert_artifact_matches_action_table_and_keeps_snapshot(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_id: str,
    artifact_actions: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> None:
    """ISSUE-342: overlay Action-table status; do not mutate the store snapshot."""
    snapshot_raw = await context_store.get(event_id, "response_plan")
    if isinstance(snapshot_raw, ResponsePlan):
        snapshot_raw = snapshot_raw.model_dump(mode="json")
    snapshot_rows = snapshot_raw.get("actions") if isinstance(snapshot_raw, dict) else []
    snapshot_by_id = _action_status_by_id(snapshot_rows if isinstance(snapshot_rows, list) else [])
    artifact_by_id = _action_status_by_id(list(artifact_actions))
    async with session_factory() as session:
        orm_rows = list(
            await session.scalars(select(orm.Action).where(orm.Action.event_id == event_id))
        )
    orm_by_id = {row.action_id: str(row.status or "").lower() for row in orm_rows}

    assert artifact_by_id, "full_loop artifact must include response_plan_actions"
    executed = [status for status in artifact_by_id.values() if status != "pending"]
    assert executed, (
        "ISSUE-342: artifact response_plan_actions must overlay Action-table runtime "
        f"status after execute; got statuses={list(artifact_by_id.values())}"
    )
    pending_snapshots: list[str] = []
    for action_id, artifact_status in artifact_by_id.items():
        orm_status = orm_by_id.get(action_id)
        assert orm_status is not None, f"ISSUE-342: missing Action row for {action_id}"
        assert artifact_status == orm_status, (
            f"ISSUE-342: artifact status for {action_id}={artifact_status} "
            f"must match Action table {orm_status}"
        )
        if artifact_status != "pending":
            snapshot_status = snapshot_by_id.get(action_id)
            assert snapshot_status == "pending", (
                "ISSUE-342: context-store ResponsePlan.actions must remain the "
                f"generation-time snapshot; {action_id} store={snapshot_status} "
                f"artifact={artifact_status}"
            )
            pending_snapshots.append(action_id)
    assert pending_snapshots, (
        "ISSUE-342: expected at least one executed action whose store snapshot stayed pending"
    )


async def _audit_status_sequence(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> list[str]:
    async with session_factory() as session:
        rows = list(
            await session.scalars(
                select(orm.EventAuditLog)
                .where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.to_status.is_not(None),
                )
                .order_by(orm.EventAuditLog.created_at.asc(), orm.EventAuditLog.id.asc())
            )
        )
    return [row.to_status for row in rows if row.to_status]


def _report_excerpt(report_ctx: dict[str, Any]) -> str:
    title = str(report_ctx.get("title") or "")
    summary = str(report_ctx.get("summary") or "")
    return (title + "\n" + summary).strip()[:1200]


def _parse_action_status_counts(blob: str) -> tuple[int, dict[str, int]] | None:
    match = re.search(r"RESPONSE 动作共 (\d+) 个（([^）]+)）", blob)
    if match is None:
        return None
    total = int(match.group(1))
    counts: dict[str, int] = {}
    for part in match.group(2).split(","):
        bit = part.strip()
        if "=" not in bit:
            continue
        name, raw = bit.split("=", 1)
        counts[name.strip()] = int(raw)
    return total, counts


def _assert_executed_report_not_all_pending(sections: list[Any]) -> None:
    """ISSUE-329: executed phase must not show pending=all RESPONSE counts.

    Prefer builder ``data`` (survives LLM chapter rewrite). Content is a
    fallback for the original Q-6 one-line / two-line summary.
    """
    blobs: list[str] = []
    data_counts: dict[str, int] | None = None
    for section in sections:
        if not isinstance(section, dict):
            continue
        content = str(section.get("content") or "")
        data = section.get("data") if isinstance(section.get("data"), dict) else {}
        blobs.append(content)
        summary = data.get("actions_status_summary")
        if isinstance(summary, str) and summary.strip():
            blobs.append(summary)
        raw_counts = data.get("action_status_counts")
        if isinstance(raw_counts, dict) and raw_counts:
            data_counts = {str(k): int(v) for k, v in raw_counts.items()}

    blob = "\n".join(blobs)
    if data_counts:
        total = sum(data_counts.values())
        pending = data_counts.get("pending", 0)
        if total > 0:
            assert pending < total, f"ISSUE-329: report data still pending=all ({data_counts})"
        return

    parsed = _parse_action_status_counts(blob)
    if parsed is None:
        return
    total, counts = parsed
    if "处置阶段状态=executed" not in blob:
        return
    pending = counts.get("pending", 0)
    assert pending < total, (
        f"ISSUE-329: report still shows executed + pending=all ({counts}); content={blob[:500]}"
    )


def _assert_entity_writeback_not_claimed_applicable(sections: list[Any]) -> None:
    """ISSUE-331: entity required=true rows must not claim applicable=true.

    Prefer builder ``data.writeback_rows`` (survives LLM chapter rewrite).
    Content is a fallback for entity_side_effect lines.
    """
    for section in sections:
        if not isinstance(section, dict):
            continue
        data = section.get("data") if isinstance(section.get("data"), dict) else {}
        rows = data.get("writeback_rows")
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                if (
                    row.get("writeback_required") is True
                    and row.get("writeback_applicable") is False
                ):
                    assert row.get("writeback_applicable") is not True, (
                        f"ISSUE-331: entity writeback_row claimed applicable=true ({row})"
                    )
        content = str(section.get("content") or "")
        for line in content.splitlines():
            if "writeback_not_applicable_reason=entity_side_effect" in line:
                assert "writeback_applicable=true" not in line, (
                    f"ISSUE-331: entity report line claimed applicable=true: {line}"
                )
                assert "writeback_applicable=false" in line, (
                    f"ISSUE-331: entity report line missing applicable=false: {line}"
                )


async def _closure_diagnostics(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_id: str,
) -> dict[str, Any]:
    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        outboxes = list(
            await session.scalars(
                select(orm.DispositionOutbox)
                .where(orm.DispositionOutbox.event_id == event_id)
                .order_by(orm.DispositionOutbox.created_at, orm.DispositionOutbox.writeback_id)
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
    checkpoint: dict[str, Any] = {}
    try:
        agent = await get_super_agent()
        graph = getattr(agent, "_investigation_graph", None)
        if graph is not None:
            snapshot = await graph.aget_state({"configurable": {"thread_id": event_id}})
            values = dict(snapshot.values or {})
            checkpoint = {
                key: values.get(key)
                for key in (
                    "event_status",
                    "execution_substate",
                    "halted",
                    "verify_overall_status",
                    "verify_need_action_replan",
                    "verify_need_writeback_recovery",
                    "verify_need_manual_resolution",
                    "verify_recoverable_writeback_ids",
                    "verify_pending_writeback_action_ids",
                    "node_trace",
                )
            }
    except Exception as exc:  # noqa: BLE001 - preserve original gate failure
        checkpoint = {"collection_error": type(exc).__name__}
    return {
        "event_id": event_id,
        "event_status": event.status if event is not None else None,
        "execution_substate": await context_store.get(event_id, "execution_substate"),
        "verification_result": await context_store.get(event_id, "verification_result"),
        "checkpoint": checkpoint,
        "outboxes": [
            {
                "writeback_id": row.writeback_id,
                "action_id": row.action_id,
                "intent_kind": row.intent_kind,
                "delivery_status": row.delivery_status,
                "latest_writeback_status": row.latest_writeback_status,
                "last_error_code": row.last_error_code,
            }
            for row in outboxes
        ],
        "receipts": [
            {
                "writeback_id": row.writeback_id,
                "sequence": row.sequence,
                "status": row.status,
                "confirmation_evidence": row.confirmation_evidence,
                "provider_code": row.provider_code,
            }
            for row in receipts
        ],
    }


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_adversarial_noisy_production_full_response_closed_loop(
    monkeypatch: pytest.MonkeyPatch,
    adversarial_source_adapter,
    source_ingester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
    context_store: EventContextStore,
    e2e_tool_executor,
    adversarial_disposition_sync_service,
    adversarial_event_disposition_service,
) -> None:
    """Ingest noisy mock XDR data, run production full loop, audit all subsystems."""
    event_id = await ingest_true_positive_event(
        adversarial_source_adapter,
        source_ingester,
        event_service,
    )

    event_before = await event_service.get_event(event_id)
    assert event_before is not None
    new_events = await event_service.list_events(status=EventStatus.NEW)
    print(
        f"\n[adversarial-full-loop] target event_id={event_id} "
        f"title={event_before.title!r} NEW queue={new_events.total}"
    )

    try:
        loop_result = await run_production_full_loop(
            monkeypatch=monkeypatch,
            session_factory=session_factory,
            redis_client=redis_client,
            event_service=event_service,
            context_store=context_store,
            adversarial_disposition_sync_service=adversarial_disposition_sync_service,
            adversarial_event_disposition_service=adversarial_event_disposition_service,
            e2e_tool_executor=e2e_tool_executor,
            event_id=event_id,
        )
    except Exception as exc:
        failure_report = {
            "scenario": GROUND_TRUTH["scenario"],
            "event_id": event_id,
            "result": "failed_before_audit",
            "failure": {
                "type": type(exc).__name__,
                "message": str(exc)[:500],
            },
            "closure_diagnostics": await _closure_diagnostics(
                session_factory,
                context_store,
                event_id,
            ),
        }
        ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT_PATH.write_text(
            json.dumps(failure_report, indent=2, default=str),
            encoding="utf-8",
        )
        raise
    print(
        f"[adversarial-full-loop] production loop finished in {loop_result.elapsed_s:.1f}s "
        f"status={loop_result.investigate_status!r} approvals={loop_result.approval_rounds}"
    )

    event_final = await event_service.get_event(event_id)
    assert event_final is not None

    triage_ctx = await context_store.get(event_id, "triage_result") or {}
    evidence_ctx = await context_store.get(event_id, "evidence_output") or {}
    report_ctx = await context_store.get(event_id, "report") or {}
    risk_ctx = await context_store.get(event_id, "risk_assessment") or {}
    quality_scores = coerce_quality_scores(await context_store.get(event_id, "quality_scores"))
    status_sequence = await _audit_status_sequence(session_factory, event_id)
    disposition_gaps_enforced = missing_response_targets(
        ground_truth=GROUND_TRUTH,
        actions=list(loop_result.response_plan_actions),
    )
    disposition_gaps_all = missing_response_targets(
        ground_truth=GROUND_TRUTH,
        actions=list(loop_result.response_plan_actions),
        enforce_gated=True,
    )
    block_ip_reason_gaps = block_ip_reason_destination_mislabels(
        loop_result.response_plan_actions,
        triage_ctx=triage_ctx if isinstance(triage_ctx, dict) else None,
    )

    event_payload = event_final.model_dump(mode="json")
    alert_corpus = build_alert_corpus(
        alert_text=str(event_final.title or ""),
        event_payload=event_payload,
    )
    narrative_corpus = build_narrative_corpus(
        triage_ctx=triage_ctx,
        evidence_ctx=evidence_ctx,
        report_ctx=report_ctx,
    )
    entity_audit = audit_required_signals(
        required=list(GROUND_TRUTH["must_identify_entities"]),
        alert_corpus=alert_corpus,
        triage_ctx=triage_ctx,
        narrative_corpus=narrative_corpus,
    )
    indicator_audit = audit_required_signals(
        required=list(GROUND_TRUTH["must_identify_indicators"]),
        alert_corpus=alert_corpus,
        triage_ctx=triage_ctx,
        narrative_corpus=narrative_corpus,
    )
    entities_found = list(entity_audit.text_understanding_hits)
    indicators_found = list(indicator_audit.text_understanding_hits)

    outward_severity, triage_severity = resolve_observed_severity(
        risk_ctx=risk_ctx if isinstance(risk_ctx, dict) else None,
        event_severity=event_final.severity,
        triage_ctx=triage_ctx if isinstance(triage_ctx, dict) else None,
    )

    async with session_factory() as session:
        action_count = await session.scalar(
            select(func.count()).select_from(orm.Action).where(orm.Action.event_id == event_id)
        )
        report_row = await session.scalar(select(orm.Report).where(orm.Report.event_id == event_id))
        se_row = await session.get(orm.SecurityEvent, event_id)
        durable_snapshot = (
            dict(se_row.event_context_snapshot)
            if se_row is not None and isinstance(se_row.event_context_snapshot, dict)
            else {}
        )
    report_sections = list(report_row.sections or []) if report_row is not None else []
    snapshot_quality = durable_snapshot.get("report_quality")
    orm_quality = str(report_row.report_quality) if report_row is not None else None
    if report_row is not None:
        assert snapshot_quality == orm_quality
    report_quality = str(snapshot_quality) if snapshot_quality is not None else orm_quality

    checks = AdversarialAuditChecks(
        ground_truth=GROUND_TRUTH,
        event_type=normalize_enum(triage_ctx.get("event_type") or event_final.event_type),
        severity=outward_severity,
        triage_severity=triage_severity,
        risk_score=int(event_final.risk_score or 0),
        final_verdict=normalize_enum(event_final.final_verdict),
        entities_found=entities_found,
        indicators_found=indicators_found,
        report_excerpt=_report_excerpt(report_ctx),
        report_quality=report_quality,
        triage_summary=str(triage_ctx.get("decision_summary") or ""),
        evidence_collection_status=str(
            evidence_ctx.get("collection_status") or evidence_ctx.get("status") or ""
        ),
        evidence_gaps=(
            list(evidence_ctx.get("gaps") or [])
            if isinstance(evidence_ctx.get("gaps"), list)
            else None
        ),
        status_sequence=status_sequence,
        audit_mode="full_loop",
        quality_scores=quality_scores,
        output_quality_blocking=get_settings().output_quality_blocking,
    )
    report = checks.to_dict()
    obs = loop_result.observability
    report["full_loop"] = {
        "mode": "production_graph",
        "elapsed_s": round(loop_result.elapsed_s, 2),
        "investigate_status": loop_result.investigate_status,
        "terminal_status": event_final.status.value,
        "approval_rounds": loop_result.approval_rounds,
        "approved_action_ids": list(loop_result.approved_action_ids),
        "approval_records": loop_result.approval_records,
        "response_plan_present": loop_result.response_plan_present,
        "response_plan_actions": list(loop_result.response_plan_actions),
        "response_plan_generated_by": loop_result.response_plan_generated_by,
        "response_plan_strategy_summary": loop_result.response_plan_strategy_summary,
        "response_agent_traced": loop_result.response_agent_traced,
        "verification_present": loop_result.verification_present,
        "verify_agent_traced": loop_result.verify_agent_traced,
        "writeback_confirmed": loop_result.writeback_confirmed,
        "terminal_outbox_enqueued": loop_result.terminal_outbox_enqueued,
        "response_actions_present": int(action_count or 0) > 0,
        "tool_call_count": loop_result.tool_call_count,
        "llm_call_count": loop_result.llm_call_count,
        "agent_trace_count": obs.agent_trace_count,
        "disposition_outbox_count": obs.disposition_outbox_count,
        "execution_job_count": obs.execution_job_count,
        "execution_ran": loop_result.execution_ran,
        "resume_attempts": loop_result.resume_attempts,
        "sunset_shims_used": list(loop_result.sunset_shims_used),
        "adversarial_di_overrides": list(loop_result.adversarial_di_overrides),
        "disposition_target_gaps": disposition_gaps_all,
        "disposition_target_gaps_enforced": disposition_gaps_enforced,
        "disposition_target_gaps_strict_pending": [
            gap for gap in disposition_gaps_all if gap not in disposition_gaps_enforced
        ],
        "strict_disposition_targets_enabled": strict_disposition_targets_enabled(),
        "block_ip_reason_destination_mislabels": block_ip_reason_gaps,
        "status_sequence_includes_closed": EventStatus.CLOSED.value in status_sequence,
        "status_sequence_includes_reporting": EventStatus.REPORTING.value in status_sequence,
        "status_sequence_includes_planning": EventStatus.PLANNING_RESPONSE.value in status_sequence,
        "status_sequence_includes_waiting_approval": EventStatus.WAITING_APPROVAL.value
        in status_sequence,
        "status_sequence_includes_executing": EventStatus.EXECUTING_RESPONSE.value
        in status_sequence,
        "status_sequence_includes_verifying": EventStatus.VERIFYING.value in status_sequence,
        "notes": loop_result.notes,
    }
    report["quality_audit"] = {
        "alert_corpus_excerpt": alert_corpus[:400],
        "entities": {
            "text_understanding_hits": list(entity_audit.text_understanding_hits),
            "source_projection_hits": list(entity_audit.source_projection_hits),
            "echo_only_hits": list(entity_audit.echo_only_hits),
            "text_understanding_missing": list(entity_audit.text_understanding_missing),
        },
        "indicators": {
            "text_understanding_hits": list(indicator_audit.text_understanding_hits),
            "source_projection_hits": list(indicator_audit.source_projection_hits),
            "echo_only_hits": list(indicator_audit.echo_only_hits),
            "text_understanding_missing": list(indicator_audit.text_understanding_missing),
        },
    }
    report["production_checks"] = {
        "response_agent_ran": loop_result.response_agent_traced,
        "approval_flow_ran": loop_result.approval_records > 0 or loop_result.approval_rounds > 0,
        "execution_ran": loop_result.execution_ran,
        "verify_agent_ran": loop_result.verify_agent_traced,
        "verify_agent_traced": loop_result.verify_agent_traced,
        "verification_context_present": loop_result.verification_present,
        "disposition_writeback_ok": loop_result.writeback_confirmed,
        "disposition_targets_aligned": not disposition_gaps_enforced,
        "disposition_targets_strict_aligned": not disposition_gaps_all,
        "no_sunset_shims": len(loop_result.sunset_shims_used) == 0,
        "tools_invoked": loop_result.tool_call_count > 0,
        "llm_invoked": loop_result.llm_call_count > 0,
        "block_ip_reason_destination_mislabels": block_ip_reason_gaps,
    }
    report["closure_diagnostics"] = await _closure_diagnostics(
        session_factory,
        context_store,
        event_id,
    )
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("\n[adversarial-full-loop] human verdict:", report["verdict_for_human"])
    print(
        "[adversarial-full-loop] production_checks:",
        json.dumps(report["production_checks"], indent=2),
    )
    print("[adversarial-full-loop] full_loop:", json.dumps(report["full_loop"], indent=2))
    print(f"[adversarial-full-loop] artifact → {ARTIFACT_PATH}")

    prod = report["production_checks"]
    assert prod["no_sunset_shims"], (
        f"ISSUE-204: sunset_shims_used must be empty, got {loop_result.sunset_shims_used}"
    )
    assert prod["response_agent_ran"], "expected response_agent trace"
    assert prod["execution_ran"], "expected ActionExecution jobs after approval"
    assert prod["verify_agent_ran"], "expected verify_agent trace"
    assert prod["disposition_targets_aligned"], (
        "ISSUE-198/334: response plan must cover enforced GROUND_TRUTH targets; "
        f"missing={disposition_gaps_enforced}, all_gaps={disposition_gaps_all}"
    )
    if strict_disposition_targets_enabled():
        assert prod["disposition_targets_strict_aligned"], (
            "ISSUE-328 strict mode: response plan must also cover gated DB isolation targets; "
            f"missing={disposition_gaps_all}"
        )
    else:
        plan_targets = response_plan_targets(list(loop_result.response_plan_actions))
        if HOST_DB.lower() not in plan_targets:
            assert HOST_DB in disposition_gaps_all, (
                "ISSUE-334: missing DB isolation must be an explicit gap until ISSUE-328; "
                f"all_gaps={disposition_gaps_all}"
            )
            assert HOST_DB not in disposition_gaps_enforced
    assert_opaque_alert_quality(
        alert_corpus=alert_corpus,
        entity_audit=entity_audit,
        indicator_audit=indicator_audit,
        opaque_tokens=opaque_scorecard_tokens(GROUND_TRUTH),
    )
    assert prod["tools_invoked"], "expected tool_call_log rows from evidence/verify/execute"
    assert prod["llm_invoked"], "expected llm_call_log rows from live/mock LLM agents"
    assert prod["disposition_writeback_ok"], (
        "expected CONFIRMED+readback_verified disposition receipt on Mock path"
    )
    assert "AdversarialDispositionSyncService" not in loop_result.adversarial_di_overrides
    assert "AdversarialTerminalDispositionResolver" not in loop_result.adversarial_di_overrides
    assert any(note == "approval_resume: production callback" for note in loop_result.notes)
    assert not any(
        marker in note
        for note in loop_result.notes
        for marker in (
            "runner owns",
            "production_verify_rerun",
            "legal_close_after",
            "loop_timeout",
            "outbox_delivery_failed",
        )
    )
    assert loop_result.terminal_outbox_enqueued, "expected terminal EVENT_STATUS_UPDATE outbox row"
    assert event_final.status is EventStatus.CLOSED
    assert EventStatus.REPORTING.value in status_sequence
    assert EventStatus.CLOSED.value in status_sequence
    assert status_sequence.index(EventStatus.REPORTING.value) < status_sequence.index(
        EventStatus.CLOSED.value
    )
    assert _report_excerpt(report_ctx).strip(), (
        "ISSUE-196: full loop must reach REPORTING/CLOSED with non-empty report"
    )
    assert report_sections, "ISSUE-329: persisted report must include sections"
    _assert_executed_report_not_all_pending(report_sections)
    _assert_entity_writeback_not_claimed_applicable(report_sections)
    # ISSUE-342: artifact must expose plan provenance and runtime action statuses.
    assert loop_result.response_plan_generated_by in _GENERATED_BY_VALUES, (
        "full_loop artifact must include response_plan.generated_by for audit provenance"
    )
    assert report["full_loop"]["response_plan_generated_by"] == (
        loop_result.response_plan_generated_by
    )
    assert loop_result.response_plan_strategy_summary, (
        "full_loop artifact must include response_plan.strategy_summary"
    )
    assert report["full_loop"]["response_plan_strategy_summary"] == (
        loop_result.response_plan_strategy_summary
    )
    await _assert_artifact_matches_action_table_and_keeps_snapshot(
        session_factory,
        context_store,
        event_id,
        loop_result.response_plan_actions,
    )
    assert EventStatus.EXECUTING_RESPONSE.value in status_sequence, (
        "expected audited transition through executing_response"
    )
    assert report["checks"]["verdict_matches_expected"]
    assert report["checks"]["risk_score_at_least_minimum"]
    if isinstance(risk_ctx, dict) and risk_ctx.get("severity"):
        assert report["observed"]["severity"] == normalize_enum(risk_ctx.get("severity"))
    if triage_severity and report["observed"]["severity"] != triage_severity:
        assert report["observed"]["triage_severity"] == triage_severity
    # ISSUE-319: lock full-loop scorecard assembly (not only helper unit tests).
    assert report["audit_mode"] == "full_loop"
    assert report["checks"]["closed_reached"] is True
    assert report["checks"]["evidence_collection_ok"] is True
    assert report["score"]["total_dimensions"] == 7
    assert report["score"]["passed"] == 7
    assert report["verdict_for_human"].startswith("PASS")
    assert "CLOSED" in report["verdict_for_human"]
    quality_bucket = report["unscored"]["output_quality"]
    assert quality_bucket["present"] is True
    assert quality_bucket["blocking_profile"] is False
    assert quality_bucket["summary"]["agents_evaluated"] >= 1
    assert "output_quality" not in report["checks"]
