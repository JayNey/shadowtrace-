"""Trajectory quality analyser (ISSUE-066).

Operates on the unified decision trace produced by ``DecisionTraceService``
and computes structured metrics plus human-readable findings for post-hoc
evaluation of multi-agent investigation efficiency.
"""

from __future__ import annotations

import logging
from collections import Counter

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.decision_trace import DecisionTraceEntry
from app.models.enums import DecisionTraceEntryType, TrajectoryMetric
from app.models.trajectory import TrajectoryReport
from app.services.decision_trace_service import DecisionTraceService

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Thresholds
# --------------------------------------------------------------------------- #

_DUPLICATE_TOOL_THRESHOLD = 3  # same tool called ≥N times → redundant
_LOOP_MIN_RUN = 5  # consecutive same-agent entries → suspected loop

_VERIFY_FAILED_STATUSES = frozenset({"failed", "error", "partial", "manual_resolution", "waiting"})
_VERIFY_SUCCESS_STATUSES = frozenset({"success"})


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #


class TrajectoryAnalyzer:
    """Derive structured quality metrics from a ``DecisionTrace``."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def analyze(self, event_id: str) -> TrajectoryReport:
        """Produce a ``TrajectoryReport`` for *event_id*.

        Returns an empty report with ``insufficient_trace=True`` when the
        decision trace contains no entries. Infrastructure failures
        (``SQLAlchemyError`` / ``OSError``) propagate to the API as 503.
        """
        trace_service = DecisionTraceService(self._session_factory)
        trace = await trace_service.get_decision_trace(event_id)

        if not trace.entries:
            logger.info("No decision trace entries for event=%s", event_id)
            return TrajectoryReport(
                event_id=event_id,
                insufficient_trace=True,
            )

        entries = trace.entries
        report = TrajectoryReport(
            event_id=event_id,
            total_steps=len(entries),
            agent_invocations=sum(
                1 for e in entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
            ),
            tool_calls=sum(1 for e in entries if e.entry_type == DecisionTraceEntryType.TOOL_CALL),
            llm_calls=sum(1 for e in entries if e.entry_type == DecisionTraceEntryType.LLM_CALL),
        )

        report.metrics = {
            TrajectoryMetric.REDUNDANT_TOOL_CALLS: _compute_redundant_tool_calls(entries),
            TrajectoryMetric.LOOP_SUSPECTED: _compute_loop_suspected(entries),
            TrajectoryMetric.REPLAN_EFFECTIVENESS: _compute_replan_effectiveness(entries),
            TrajectoryMetric.AVG_AGENT_LATENCY_MS: _compute_avg_agent_latency_ms(entries),
            TrajectoryMetric.EVIDENCE_YIELD: _compute_evidence_yield(entries),
            TrajectoryMetric.STEPS_TO_VERDICT: _compute_steps_to_verdict(entries),
        }

        report.findings = _generate_findings(report.metrics, entries)
        return report


# --------------------------------------------------------------------------- #
# Metric functions
# --------------------------------------------------------------------------- #


def _tool_fingerprint(entry: DecisionTraceEntry) -> str:
    """Stable fingerprint for a tool-call entry.

    Uses ``actor`` (tool_name) as the grouping key.  The decision-trace
    detail for tool calls does not include raw parameters, so the
    fingerprint relies on the tool identity alone.
    """
    return entry.actor


def _verify_failed(entry: DecisionTraceEntry) -> bool:
    detail = entry.detail
    agent_status = str(detail.get("status", "")).lower()
    if agent_status in {"failed", "error"}:
        return True
    if detail.get("need_action_replan") is True:
        return True
    overall = str(detail.get("overall_status", "")).lower()
    return overall in _VERIFY_FAILED_STATUSES


def _verify_succeeded(entry: DecisionTraceEntry) -> bool:
    detail = entry.detail
    if _verify_failed(entry):
        return False
    overall = str(detail.get("overall_status", "")).lower()
    if overall in _VERIFY_SUCCESS_STATUSES:
        return True
    agent_status = str(detail.get("status", "")).lower()
    return agent_status == "completed" and detail.get("need_action_replan") is not True


def _compute_redundant_tool_calls(entries: list[DecisionTraceEntry]) -> float:
    """Count excess tool calls beyond the duplicate threshold per tool."""
    tool_entries = [e for e in entries if e.entry_type == DecisionTraceEntryType.TOOL_CALL]
    if not tool_entries:
        return 0.0

    counts = Counter(_tool_fingerprint(e) for e in tool_entries)
    redundant = sum(
        count - _DUPLICATE_TOOL_THRESHOLD + 1
        for count in counts.values()
        if count >= _DUPLICATE_TOOL_THRESHOLD
    )
    return float(redundant)


def _compute_loop_suspected(entries: list[DecisionTraceEntry]) -> float:
    """Detect consecutive repetitions of the same agent (suspected loop).

    Returns the run length when the longest same-agent streak reaches
    *_LOOP_MIN_RUN*, otherwise 0.
    """
    agent_entries = [e for e in entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION]
    if len(agent_entries) < _LOOP_MIN_RUN:
        return 0.0

    max_run = 0
    current_run = 1
    for i in range(1, len(agent_entries)):
        if agent_entries[i].actor == agent_entries[i - 1].actor:
            current_run += 1
        else:
            max_run = max(max_run, current_run)
            current_run = 1
    max_run = max(max_run, current_run)
    return float(max_run) if max_run >= _LOOP_MIN_RUN else 0.0


def _compute_replan_effectiveness(entries: list[DecisionTraceEntry]) -> float:
    """Measure whether a re-plan improved verification outcome.

    Compares VerifyAgent entries before vs after the last PlannerAgent run.
    Uses ``overall_status`` / ``need_action_replan`` projected by
    ``DecisionTraceService`` (agent ``status`` alone is ``completed`` even
    when verification failed).
    """
    agent_entries = [
        (idx, entry)
        for idx, entry in enumerate(entries)
        if entry.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
    ]
    planner_indices = [idx for idx, entry in agent_entries if "planner" in entry.actor.lower()]
    verify_entries = [
        (idx, entry) for idx, entry in agent_entries if "verify" in entry.actor.lower()
    ]

    if len(planner_indices) < 2 or len(verify_entries) < 2:
        return 0.0

    last_planner_idx = planner_indices[-1]
    pre_planner = [entry for idx, entry in verify_entries if idx < last_planner_idx]
    post_planner = [entry for idx, entry in verify_entries if idx > last_planner_idx]

    if not pre_planner or not post_planner:
        return 0.0

    pre_failed = any(_verify_failed(entry) for entry in pre_planner)
    post_success = all(_verify_succeeded(entry) for entry in post_planner)
    return 1.0 if pre_failed and post_success else 0.0


def _compute_avg_agent_latency_ms(entries: list[DecisionTraceEntry]) -> float:
    """Average agent execution latency in milliseconds."""
    agent_entries = [e for e in entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION]
    latencies = [e.detail.get("duration_ms", 0) or 0 for e in agent_entries]
    if not latencies:
        return 0.0
    return round(sum(latencies) / len(latencies), 1)


def _evidence_effective(entry: DecisionTraceEntry) -> bool:
    detail = entry.detail
    if detail.get("collection_status") == "completed":
        return True
    evidence_list = detail.get("evidence_list")
    if isinstance(evidence_list, list) and evidence_list:
        return True
    return str(detail.get("status", "")).lower() == "completed"


def _compute_evidence_yield(entries: list[DecisionTraceEntry]) -> float:
    """Evidence yield = effective evidence passes / query tool calls."""
    evidence_entries = [
        e
        for e in entries
        if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION and "evidence" in e.actor.lower()
    ]
    query_entries = [
        e
        for e in entries
        if e.entry_type == DecisionTraceEntryType.TOOL_CALL
        and str(e.detail.get("tool_category", "")).lower() == "query"
    ]
    if not query_entries:
        return 0.0

    effective = sum(1 for e in evidence_entries if _evidence_effective(e))
    return round(effective / len(query_entries), 2)


def _compute_steps_to_verdict(entries: list[DecisionTraceEntry]) -> float:
    """Total steps until the first final verdict is observed."""
    terminal_statuses = {"reporting", "closed"}
    for i, entry in enumerate(entries, start=1):
        if entry.entry_type == DecisionTraceEntryType.STATE_TRANSITION:
            to_status = str(entry.detail.get("to_status", "")).lower()
            if to_status in terminal_statuses:
                return float(i)
    return float(len(entries))


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _generate_findings(
    metrics: dict[str, float],
    entries: list[DecisionTraceEntry],
) -> list[str]:
    findings: list[str] = []

    redundant = metrics.get(TrajectoryMetric.REDUNDANT_TOOL_CALLS, 0)
    if redundant > 0:
        findings.append(
            f"检测到 {int(redundant)} 次冗余工具调用"
            f"（相同工具超出 {_DUPLICATE_TOOL_THRESHOLD} 次阈值）"
        )

    loop = metrics.get(TrajectoryMetric.LOOP_SUSPECTED, 0)
    if loop > 0:
        findings.append(f"疑似循环：同一 Agent 连续执行 {int(loop)} 次（阈值 {_LOOP_MIN_RUN}）")

    replan = metrics.get(TrajectoryMetric.REPLAN_EFFECTIVENESS, 0)
    if replan > 0:
        findings.append("重规划有效：Verification 由失败转为成功")
    else:
        planner_count = sum(
            1
            for e in entries
            if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
            and "planner" in e.actor.lower()
        )
        if planner_count >= 2:
            findings.append("重规划未带来改善：多次规划但 Verification 未恢复")

    evidence_yield = metrics.get(TrajectoryMetric.EVIDENCE_YIELD, 0)
    if evidence_yield < 0.5 and any(
        e.entry_type == DecisionTraceEntryType.TOOL_CALL
        and str(e.detail.get("tool_category", "")).lower() == "query"
        for e in entries
    ):
        findings.append(f"证据产出率偏低（{evidence_yield:.2f}），大量查询未产生有效证据")

    steps = metrics.get(TrajectoryMetric.STEPS_TO_VERDICT, 0)
    total = len(entries)
    if steps >= total and total > 0:
        findings.append("未检测到终态（REPORTING/CLOSED），研判可能未完成")

    if not findings:
        findings.append("轨迹分析未发现异常")

    return findings


__all__ = ["TrajectoryAnalyzer"]
