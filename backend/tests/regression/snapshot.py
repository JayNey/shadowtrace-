"""Golden-path snapshot recorder and differ (ISSUE-087)."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.models.enums import ActionCategory, ActionStatus
from app.services.context_service import EventContextStore
from app.services.output_quality_evaluator import OutputQualityEvaluator
from app.services.trajectory_analyzer import TrajectoryAnalyzer
from tests.regression.scenarios import SNAPSHOT_SCHEMA_VERSION

DriftSeverity = Literal["block", "warn"]

RISK_SCORE_TOLERANCE = 5
METRIC_DRIFT_RATIO = 0.20
ZERO_BASELINE_METRIC_ABS_TOLERANCE = 0.05

_BASELINE_DIR = Path(__file__).resolve().parent / "baseline"

# Wall-clock latency is environment-specific; keep in snapshot for inspection only.
_EXCLUDED_TRAJECTORY_METRICS = frozenset({"avg_agent_latency_ms"})

# Count only terminal success states. EXECUTING / APPROVED are in-flight and
# intentionally excluded until a response action completes; align with ISSUE-086
# system tests when extending golden chains that transition through those states.
_EXECUTED_ACTION_STATUSES = frozenset(
    {
        ActionStatus.SUCCESS.value,
        ActionStatus.PARTIAL_SUCCESS.value,
    }
)

_REQUIRED_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "scenario_id",
        "final_verdict",
        "risk_score",
        "executed_actions",
        "dispositions",
        "trajectory_metrics",
        "quality_scores",
    }
)


@dataclass(frozen=True)
class Drift:
    field: str
    baseline_value: Any
    current_value: Any
    severity: DriftSeverity


def baseline_path(scenario_id: str) -> Path:
    return _BASELINE_DIR / f"{scenario_id}.json"


def load_baseline(scenario_id: str) -> dict[str, Any] | None:
    path = baseline_path(scenario_id)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_baseline(scenario_id: str, snapshot: dict[str, Any]) -> Path:
    _BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    path = baseline_path(scenario_id)
    path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _round_float(value: float, *, places: int = 4) -> float:
    return round(float(value), places)


def _normalize_metrics(raw: dict[str, float]) -> dict[str, float]:
    return {
        key: _round_float(value)
        for key, value in sorted(raw.items())
        if key not in _EXCLUDED_TRAJECTORY_METRICS
    }


def _normalize_quality_scores(raw: dict[str, Any]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for agent_name, payload in sorted(raw.items()):
        if isinstance(payload, dict) and "score" in payload:
            scores[agent_name] = _round_float(float(payload["score"]))
        elif isinstance(payload, (int, float)):
            scores[agent_name] = _round_float(float(payload))
    return scores


def _normalize_action_set(values: list[str] | tuple[str, ...] | None) -> list[str]:
    return sorted(set(values or []))


def _normalize_dispositions(
    items: list[dict[str, str | None]] | None,
) -> list[dict[str, str | None]]:
    normalized = [
        {
            "operation": item.get("operation"),
            "execution_owner": item.get("execution_owner"),
            "writeback_status": item.get("writeback_status"),
        }
        for item in (items or [])
    ]
    return sorted(
        normalized,
        key=lambda item: (
            item["operation"] or "",
            item["execution_owner"] or "",
            item["writeback_status"] or "",
        ),
    )


class SnapshotRecorder:
    """Assemble a deterministic investigation snapshot after the main chain."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        context_store: EventContextStore,
    ) -> None:
        self._session_factory = session_factory
        self._context_store = context_store
        self._trajectory = TrajectoryAnalyzer(session_factory)
        self._quality = OutputQualityEvaluator(judge_enabled=False)

    async def record(self, event_id: str, scenario_id: str | None = None) -> dict[str, Any]:
        """Build a snapshot dict for *event_id*.

        Args:
            event_id: Security event primary key (Issue contract).
            scenario_id: Optional scenario label stored in the snapshot for baseline
                file naming and drift reports (extension beyond Issue minimum).
        """
        async with self._session_factory() as session:
            event = await session.get(orm.SecurityEvent, event_id)
            if event is None:
                raise ValueError(f"security_event not found: {event_id}")
            actions = list(
                await session.scalars(
                    select(orm.Action)
                    .where(orm.Action.event_id == event_id)
                    .order_by(orm.Action.created_at.asc(), orm.Action.action_id.asc())
                )
            )
            outbox_rows = list(
                await session.scalars(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.event_id == event_id)
                    .order_by(orm.DispositionOutbox.created_at.asc())
                )
            )

        context_payload = await self._build_event_context(event_id)
        quality_raw = await self._quality.evaluate_all(context_payload)
        trajectory = await self._trajectory.analyze(event_id)

        executed_actions = _normalize_action_set(
            row.tool_name
            for row in actions
            if row.action_category == ActionCategory.RESPONSE.value
            and row.status in _EXECUTED_ACTION_STATUSES
        )

        dispositions = _extract_dispositions(actions, outbox_rows)
        quality_scores = _normalize_quality_scores(
            {agent: score.model_dump(mode="json") for agent, score in quality_raw.items()}
        )

        snapshot: dict[str, Any] = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "event_id": event_id,
            "event_status": str(event.status),
            "final_verdict": event.final_verdict,
            "risk_score": int(event.risk_score or 0),
            "executed_actions": executed_actions,
            "dispositions": dispositions,
            "trajectory_metrics": _normalize_metrics(dict(trajectory.metrics)),
            "quality_scores": quality_scores,
            "insufficient_trace": bool(trajectory.insufficient_trace),
        }
        if scenario_id is not None:
            snapshot["scenario_id"] = scenario_id
        return snapshot

    async def _build_event_context(self, event_id: str) -> dict[str, Any]:
        keys = (
            "triage_result",
            "evidence_output",
            "risk_assessment",
            "report",
            "rag_output",
        )
        context: dict[str, Any] = {"event_id": event_id}
        for key in keys:
            value = await self._context_store.get(event_id, key)
            if value is not None:
                context[key] = value
        return context


def _extract_dispositions(
    actions: list[orm.Action],
    outbox_rows: list[orm.DispositionOutbox],
) -> list[dict[str, str | None]]:
    by_action = {row.action_id: row for row in outbox_rows}
    items: list[dict[str, str | None]] = []
    for action in actions:
        if not action.writeback_required and action.tool_name != "update_source_event_disposition":
            continue
        outbox = by_action.get(action.action_id)
        operation = action.tool_name
        payload = outbox.command_payload if outbox is not None else {}
        if isinstance(payload, dict):
            params = payload.get("operation_params")
            params_code = params.get("operation_code") if isinstance(params, dict) else None
            operation = str(payload.get("operation_code") or params_code or action.tool_name)
        writeback_status = action.writeback_status
        if outbox is not None and outbox.latest_writeback_status:
            writeback_status = outbox.latest_writeback_status
        items.append(
            {
                "operation": operation,
                "execution_owner": action.execution_owner,
                "writeback_status": writeback_status,
            }
        )
    return _normalize_dispositions(items)


class SnapshotDiffer:
    """Compare snapshots using ISSUE-087 tolerances.

    Block severity:
    - ``schema_version`` and required snapshot keys
    - ``final_verdict``, ``executed_actions`` (set equality), ``risk_score`` (±5)
    - ``dispositions`` (writeback semantics; block drift beyond Issue table)

    Warn severity:
    - ``trajectory_metrics.*`` and ``quality_scores.*`` when drift exceeds 20%

    Recorded for audit but intentionally not diffed:
    - ``event_id``, ``event_status``, ``insufficient_trace``, ``scenario_id``
    """

    def diff(self, baseline: dict[str, Any], current: dict[str, Any]) -> list[Drift]:
        drifts: list[Drift] = []
        self._validate_schema_version(drifts, baseline=baseline, current=current)
        self._validate_required_fields(drifts, baseline=baseline, current=current)
        self._compare_exact(
            drifts,
            field="final_verdict",
            baseline=baseline.get("final_verdict"),
            current=current.get("final_verdict"),
        )
        self._compare_action_set(
            drifts,
            baseline=baseline.get("executed_actions") or [],
            current=current.get("executed_actions") or [],
        )
        self._compare_dispositions(
            drifts,
            baseline=baseline.get("dispositions") or [],
            current=current.get("dispositions") or [],
        )
        self._compare_risk_score(
            drifts,
            baseline=int(baseline.get("risk_score") or 0),
            current=int(current.get("risk_score") or 0),
        )
        self._compare_metric_map(
            drifts,
            field_prefix="trajectory_metrics",
            baseline=baseline.get("trajectory_metrics") or {},
            current=current.get("trajectory_metrics") or {},
        )
        self._compare_metric_map(
            drifts,
            field_prefix="quality_scores",
            baseline=baseline.get("quality_scores") or {},
            current=current.get("quality_scores") or {},
        )
        return drifts

    @staticmethod
    def blocking_drifts(drifts: list[Drift]) -> list[Drift]:
        return [item for item in drifts if item.severity == "block"]

    @staticmethod
    def warn_drifts(drifts: list[Drift]) -> list[Drift]:
        return [item for item in drifts if item.severity == "warn"]

    def _validate_schema_version(
        self,
        drifts: list[Drift],
        *,
        baseline: dict[str, Any],
        current: dict[str, Any],
    ) -> None:
        base_version = baseline.get("schema_version")
        cur_version = current.get("schema_version")
        if base_version != cur_version:
            drifts.append(
                Drift(
                    field="schema_version",
                    baseline_value=base_version,
                    current_value=cur_version,
                    severity="block",
                )
            )

    def _validate_required_fields(
        self,
        drifts: list[Drift],
        *,
        baseline: dict[str, Any],
        current: dict[str, Any],
    ) -> None:
        for field in sorted(_REQUIRED_SNAPSHOT_FIELDS):
            if field not in baseline:
                drifts.append(
                    Drift(
                        field=f"baseline.{field}",
                        baseline_value=None,
                        current_value=current.get(field),
                        severity="block",
                    )
                )
            if field not in current:
                drifts.append(
                    Drift(
                        field=f"current.{field}",
                        baseline_value=baseline.get(field),
                        current_value=None,
                        severity="block",
                    )
                )

    def _compare_exact(
        self,
        drifts: list[Drift],
        *,
        field: str,
        baseline: Any,
        current: Any,
    ) -> None:
        if baseline != current:
            drifts.append(
                Drift(
                    field=field,
                    baseline_value=baseline,
                    current_value=current,
                    severity="block",
                )
            )

    def _compare_action_set(
        self,
        drifts: list[Drift],
        *,
        baseline: list[str] | tuple[str, ...],
        current: list[str] | tuple[str, ...],
    ) -> None:
        base_set = _normalize_action_set(list(baseline))
        cur_set = _normalize_action_set(list(current))
        if base_set != cur_set:
            drifts.append(
                Drift(
                    field="executed_actions",
                    baseline_value=base_set,
                    current_value=cur_set,
                    severity="block",
                )
            )

    def _compare_dispositions(
        self,
        drifts: list[Drift],
        *,
        baseline: list[dict[str, str | None]],
        current: list[dict[str, str | None]],
    ) -> None:
        base_items = _normalize_dispositions(baseline)
        cur_items = _normalize_dispositions(current)
        if base_items != cur_items:
            drifts.append(
                Drift(
                    field="dispositions",
                    baseline_value=base_items,
                    current_value=cur_items,
                    severity="block",
                )
            )

    def _compare_risk_score(
        self,
        drifts: list[Drift],
        *,
        baseline: int,
        current: int,
    ) -> None:
        if abs(current - baseline) > RISK_SCORE_TOLERANCE:
            drifts.append(
                Drift(
                    field="risk_score",
                    baseline_value=baseline,
                    current_value=current,
                    severity="block",
                )
            )

    def _compare_metric_map(
        self,
        drifts: list[Drift],
        *,
        field_prefix: str,
        baseline: dict[str, float],
        current: dict[str, float],
    ) -> None:
        keys = sorted(set(baseline) | set(current))
        for key in keys:
            if field_prefix == "trajectory_metrics" and key in _EXCLUDED_TRAJECTORY_METRICS:
                continue
            base_val = float(baseline.get(key, 0.0))
            cur_val = float(current.get(key, 0.0))
            if _metric_drift_exceeds(base_val, cur_val):
                drifts.append(
                    Drift(
                        field=f"{field_prefix}.{key}",
                        baseline_value=_round_float(base_val),
                        current_value=_round_float(cur_val),
                        severity="warn",
                    )
                )


def _metric_drift_exceeds(baseline: float, current: float) -> bool:
    if math.isclose(baseline, current, rel_tol=0.0, abs_tol=1e-9):
        return False
    if baseline == 0.0:
        return abs(current) > ZERO_BASELINE_METRIC_ABS_TOLERANCE
    return abs(current - baseline) / abs(baseline) > METRIC_DRIFT_RATIO


def format_drifts(drifts: list[Drift]) -> str:
    lines = []
    for item in drifts:
        lines.append(
            f"[{item.severity}] {item.field}: baseline={item.baseline_value!r} "
            f"current={item.current_value!r}"
        )
    return "\n".join(lines)
