"""DecisionTraceService: unified decision trace from 8 data sources (ISSUE-063).

Aggregates agent executions, tool calls, LLM calls, state transitions,
approvals, action executions, dispositions, and writeback receipts into a
single timestamp-ordered timeline for explainability and auditing.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.models.decision_trace import DecisionTrace, DecisionTraceEntry, DecisionTraceSummary
from app.models.enums import DecisionTraceEntryType

logger = logging.getLogger(__name__)

# Fixed ordering for entries sharing the same timestamp.
_ENTRY_TYPE_ORDER: dict[DecisionTraceEntryType, int] = {
    DecisionTraceEntryType.AGENT_EXECUTION: 0,
    DecisionTraceEntryType.TOOL_CALL: 1,
    DecisionTraceEntryType.LLM_CALL: 2,
    DecisionTraceEntryType.STATE_TRANSITION: 3,
    DecisionTraceEntryType.APPROVAL: 4,
    DecisionTraceEntryType.ACTION_EXECUTION: 5,
    DecisionTraceEntryType.DISPOSITION: 6,
    DecisionTraceEntryType.WRITEBACK: 7,
}


def _new_entry_id() -> str:
    return f"dte-{secrets.token_hex(4)}"


def _ts(obj: Any, *attrs: str) -> datetime | None:
    """Extract the first non-None timestamp from the given attribute names."""
    for attr in attrs:
        val = getattr(obj, attr, None)
        if isinstance(val, datetime):
            return val
    return None


# --------------------------------------------------------------------------- #
# Per-source normalizers
# --------------------------------------------------------------------------- #


def _normalize_agent_traces(rows: list[orm.AgentTrace]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        ts = _ts(row, "started_at", "completed_at")
        if ts is None:
            continue
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.AGENT_EXECUTION,
                timestamp=ts,
                actor=row.agent_name,
                title=f"{row.agent_name} completed: status={row.status}",
                detail={
                    "agent_name": row.agent_name,
                    "status": row.status,
                    "duration_ms": row.duration_ms,
                    "tokens_used": row.llm_tokens_used,
                    "model": row.llm_model,
                },
                ref_id=row.trace_id,
            )
        )
    return entries


def _normalize_tool_calls(rows: list[orm.ToolCallLog]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        ts = _ts(row, "started_at", "completed_at")
        if ts is None:
            continue
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.TOOL_CALL,
                timestamp=ts,
                actor=row.tool_name,
                title=f"{row.tool_name} completed: status={row.status}",
                detail={
                    "tool_name": row.tool_name,
                    "tool_category": row.tool_category,
                    "status": row.status,
                    "duration_ms": row.duration_ms,
                    "retry_count": row.retry_count,
                },
                ref_id=row.call_id,
            )
        )
    return entries


def _normalize_llm_calls(rows: list[orm.LLMCallLog]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.LLM_CALL,
                timestamp=row.created_at,
                actor=row.agent_name,
                title=f"{row.agent_name} LLM call ({row.model_name}): {row.total_tokens} tokens",
                detail={
                    "agent_name": row.agent_name,
                    "model_name": row.model_name,
                    "prompt_key": row.prompt_key,
                    "prompt_tokens": row.prompt_tokens,
                    "completion_tokens": row.completion_tokens,
                    "total_tokens": row.total_tokens,
                    "latency_ms": row.latency_ms,
                    "status": row.status,
                },
                ref_id=str(row.id),
            )
        )
    return entries


def _normalize_state_transitions(rows: list[orm.EventAuditLog]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        from_s = row.from_status or "?"
        to_s = row.to_status or "?"
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.STATE_TRANSITION,
                timestamp=row.created_at,
                actor=row.operator or "system",
                title=f"{from_s} → {to_s}",
                detail={
                    "from_status": row.from_status,
                    "to_status": row.to_status,
                    "operator": row.operator,
                    "reason": row.reason,
                },
                ref_id=str(row.id),
            )
        )
    return entries


def _normalize_approvals(
    approval_records: list[dict[str, Any]],
) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for rec in approval_records:
        ts_raw = rec.get("created_at") or rec.get("decided_at") or rec.get("timestamp")
        ts: datetime | None = None
        if isinstance(ts_raw, str):
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        elif isinstance(ts_raw, datetime):
            ts = ts_raw
        if ts is None:
            continue

        decision = rec.get("decision") or rec.get("status") or "unknown"
        operator = rec.get("operator") or rec.get("reviewed_by") or "system"
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.APPROVAL,
                timestamp=ts,
                actor=str(operator),
                title=f"Approval by {operator}: {decision}",
                detail={
                    "decision": decision,
                    "operator": str(operator),
                    "reason": rec.get("reason"),
                    "action_id": rec.get("action_id"),
                    "plan_revision": rec.get("plan_revision"),
                },
                ref_id=rec.get("decision_id") or rec.get("approval_id"),
            )
        )
    return entries


def _normalize_action_executions(rows: list[orm.ActionExecutionJob]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        ts = _ts(row, "created_at", "started_at")
        if ts is None:
            continue
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.ACTION_EXECUTION,
                timestamp=ts,
                actor=row.provider_name,
                title=f"Action {row.action_id}: {row.status}",
                detail={
                    "job_id": row.job_id,
                    "action_id": row.action_id,
                    "provider_name": row.provider_name,
                    "status": row.status,
                    "attempt": row.attempt,
                    "provider_code": row.provider_code,
                    "provider_message": row.provider_message,
                },
                ref_id=row.job_id,
            )
        )
    return entries


def _normalize_dispositions(rows: list[orm.DispositionOutbox]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        ts = _ts(row, "created_at", "delivered_at")
        if ts is None:
            continue
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.DISPOSITION,
                timestamp=ts,
                actor="system",
                title=f"Disposition {row.disposition_id}: {row.intent_kind}",
                detail={
                    "disposition_id": row.disposition_id,
                    "action_id": row.action_id,
                    "intent_kind": row.intent_kind,
                    "delivery_status": row.delivery_status,
                    "writeback_status": row.latest_writeback_status,
                    "closure_cycle": row.closure_cycle,
                    "attempt": row.attempt,
                },
                ref_id=row.outbox_id,
            )
        )
    return entries


def _normalize_writebacks(rows: list[orm.DispositionReceipt]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        ts = _ts(row, "confirmed_at", "submitted_at", "observed_at")
        if ts is None:
            continue
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.WRITEBACK,
                timestamp=ts,
                actor="system",
                title=f"Writeback {row.writeback_id}: {row.status}",
                detail={
                    "writeback_id": row.writeback_id,
                    "disposition_id": row.disposition_id,
                    "action_id": row.action_id,
                    "status": row.status,
                    "confirmation_evidence": row.confirmation_evidence,
                    "simulated": row.simulated,
                    "sequence": row.sequence,
                },
                ref_id=row.writeback_id,
            )
        )
    return entries


# --------------------------------------------------------------------------- #
# Sorting key
# --------------------------------------------------------------------------- #


def _sort_key(entry: DecisionTraceEntry) -> tuple[datetime, int, str]:
    return (
        entry.timestamp,
        _ENTRY_TYPE_ORDER.get(entry.entry_type, 99),
        entry.entry_id,
    )


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #


class DecisionTraceService:
    """Aggregate 8 data sources into a unified decision trace timeline."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_decision_trace(self, event_id: str) -> DecisionTrace:
        """Build the full decision trace for *event_id*.

        Sources that fail are skipped and recorded in ``missing_sources``;
        the remaining entries are still returned.
        """
        all_entries: list[DecisionTraceEntry] = []
        missing: list[str] = []
        approval_records: list[dict[str, Any]] = []

        async with self._session_factory() as session:
            # 1. Agent traces
            try:
                agent_rows = await self._fetch_agent_traces(session, event_id)
                all_entries.extend(_normalize_agent_traces(agent_rows))
            except Exception as exc:
                logger.warning("Failed to fetch agent traces for %s: %s", event_id, exc)
                missing.append("agent_trace")

            # 2. Tool calls
            try:
                tool_rows = await self._fetch_tool_calls(session, event_id)
                all_entries.extend(_normalize_tool_calls(tool_rows))
            except Exception as exc:
                logger.warning("Failed to fetch tool calls for %s: %s", event_id, exc)
                missing.append("tool_call_log")

            # 3. LLM calls
            try:
                llm_rows = await self._fetch_llm_calls(session, event_id)
                all_entries.extend(_normalize_llm_calls(llm_rows))
            except Exception as exc:
                logger.warning("Failed to fetch LLM calls for %s: %s", event_id, exc)
                missing.append("llm_call_log")

            # 4. State transitions (event_audit_log)
            try:
                audit_rows = await self._fetch_audit_logs(session, event_id)
                all_entries.extend(_normalize_state_transitions(audit_rows))
            except Exception as exc:
                logger.warning("Failed to fetch audit logs for %s: %s", event_id, exc)
                missing.append("event_audit_log")

            # 5. Approvals (from event_context_snapshot JSONB)
            try:
                approval_records = await self._fetch_approval_records(session, event_id)
                all_entries.extend(_normalize_approvals(approval_records))
            except Exception as exc:
                logger.warning("Failed to fetch approvals for %s: %s", event_id, exc)
                missing.append("approval_records")

            # 6. Action execution jobs
            try:
                job_rows = await self._fetch_action_jobs(session, event_id)
                all_entries.extend(_normalize_action_executions(job_rows))
            except Exception as exc:
                logger.warning("Failed to fetch action jobs for %s: %s", event_id, exc)
                missing.append("action_execution_job")

            # 7. Dispositions (outbox)
            try:
                disp_rows = await self._fetch_dispositions(session, event_id)
                all_entries.extend(_normalize_dispositions(disp_rows))
            except Exception as exc:
                logger.warning("Failed to fetch dispositions for %s: %s", event_id, exc)
                missing.append("disposition_outbox")

            # 8. Writeback receipts
            try:
                wb_rows = await self._fetch_writebacks(session, event_id)
                all_entries.extend(_normalize_writebacks(wb_rows))
            except Exception as exc:
                logger.warning("Failed to fetch writebacks for %s: %s", event_id, exc)
                missing.append("disposition_receipt")

        # Sort: timestamp ascending, then entry_type order, then entry_id.
        all_entries.sort(key=_sort_key)

        # Compute summary from the full (unfiltered) set.
        summary = self._compute_summary(all_entries, approval_records)

        # Compute total_duration_ms from first to last entry.
        if all_entries:
            first_ts = all_entries[0].timestamp
            last_ts = all_entries[-1].timestamp
            summary.total_duration_ms = max(0, int((last_ts - first_ts).total_seconds() * 1000))

        return DecisionTrace(
            event_id=event_id,
            entries=all_entries,
            summary=summary,
            missing_sources=missing,
        )

    # ------------------------------------------------------------------ #
    # Internal fetchers
    # ------------------------------------------------------------------ #

    async def _fetch_agent_traces(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.AgentTrace]:
        rows = await session.scalars(
            select(orm.AgentTrace)
            .where(orm.AgentTrace.event_id == event_id)
            .order_by(orm.AgentTrace.started_at.asc().nulls_last())
        )
        return list(rows)

    async def _fetch_tool_calls(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.ToolCallLog]:
        rows = await session.scalars(
            select(orm.ToolCallLog)
            .where(orm.ToolCallLog.event_id == event_id)
            .order_by(orm.ToolCallLog.started_at.asc().nulls_last())
        )
        return list(rows)

    async def _fetch_llm_calls(self, session: AsyncSession, event_id: str) -> list[orm.LLMCallLog]:
        rows = await session.scalars(
            select(orm.LLMCallLog)
            .where(orm.LLMCallLog.event_id == event_id)
            .order_by(orm.LLMCallLog.created_at.asc())
        )
        return list(rows)

    async def _fetch_audit_logs(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.EventAuditLog]:
        rows = await session.scalars(
            select(orm.EventAuditLog)
            .where(orm.EventAuditLog.event_id == event_id)
            .order_by(orm.EventAuditLog.created_at.asc())
        )
        return list(rows)

    async def _fetch_approval_records(
        self, session: AsyncSession, event_id: str
    ) -> list[dict[str, Any]]:
        row = await session.get(orm.SecurityEvent, event_id)
        if row is None or row.event_context_snapshot is None:
            return []
        ctx = row.event_context_snapshot
        records = ctx.get("approval_records")
        if isinstance(records, list):
            return records
        return []

    async def _fetch_action_jobs(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.ActionExecutionJob]:
        rows = await session.scalars(
            select(orm.ActionExecutionJob)
            .where(orm.ActionExecutionJob.event_id == event_id)
            .order_by(orm.ActionExecutionJob.created_at.asc())
        )
        return list(rows)

    async def _fetch_dispositions(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.DispositionOutbox]:
        rows = await session.scalars(
            select(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
            .order_by(orm.DispositionOutbox.created_at.asc())
        )
        return list(rows)

    async def _fetch_writebacks(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.DispositionReceipt]:
        rows = await session.scalars(
            select(orm.DispositionReceipt)
            .where(
                orm.DispositionReceipt.action_id.in_(
                    select(orm.Action.action_id).where(orm.Action.event_id == event_id)
                )
            )
            .order_by(orm.DispositionReceipt.confirmed_at.asc().nulls_last())
        )
        return list(rows)

    # ------------------------------------------------------------------ #
    # Summary
    # ------------------------------------------------------------------ #

    @staticmethod
    def _compute_summary(
        entries: list[DecisionTraceEntry],
        approval_records: list[dict[str, Any]],
    ) -> DecisionTraceSummary:
        summary = DecisionTraceSummary()
        for entry in entries:
            if entry.entry_type == DecisionTraceEntryType.AGENT_EXECUTION:
                summary.agent_count += 1
            elif entry.entry_type == DecisionTraceEntryType.TOOL_CALL:
                summary.tool_call_count += 1
            elif entry.entry_type == DecisionTraceEntryType.LLM_CALL:
                summary.llm_call_count += 1
                tokens = entry.detail.get("total_tokens", 0)
                if isinstance(tokens, int):
                    summary.total_tokens += tokens
            elif entry.entry_type == DecisionTraceEntryType.STATE_TRANSITION:
                summary.state_transition_count += 1
            elif entry.entry_type == DecisionTraceEntryType.APPROVAL:
                summary.approval_count += 1
            elif entry.entry_type == DecisionTraceEntryType.ACTION_EXECUTION:
                summary.action_execution_count += 1
            elif entry.entry_type == DecisionTraceEntryType.DISPOSITION:
                summary.disposition_count += 1
            elif entry.entry_type == DecisionTraceEntryType.WRITEBACK:
                summary.writeback_count += 1

        # approval_count should reflect the actual records even if some lack timestamps.
        if summary.approval_count < len(approval_records):
            summary.approval_count = len(approval_records)

        return summary


__all__ = ["DecisionTraceService"]
