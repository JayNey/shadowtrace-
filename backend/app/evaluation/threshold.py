"""Threshold/baseline manifest loading and fail-closed gate evaluation (#608)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.errors import ValidationError
from app.evaluation.scorers.registry import ScorerRegistry
from app.models.evaluation_run import (
    EvaluationAggregateMetrics,
    EvaluationCaseResult,
    EvaluationGateDiff,
    EvaluationGateResult,
    EvaluationQuarantinePolicy,
    EvaluationThresholdManifest,
    EvaluationThresholdRule,
    GateVerdict,
    ScorerOutcome,
)


def load_threshold_manifest(path: Path) -> EvaluationThresholdManifest:
    if not path.is_file():
        raise ValidationError(
            "threshold manifest not found",
            details={"path": str(path)},
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValidationError("threshold manifest must be a JSON object")
    return EvaluationThresholdManifest.model_validate(payload)


def validate_threshold_manifest_for_run(
    manifest: EvaluationThresholdManifest,
    *,
    dataset_id: str,
    dataset_version: str,
) -> None:
    """Ensure threshold manifest targets the dataset under evaluation."""
    if manifest.dataset_id != dataset_id:
        raise ValidationError(
            "threshold manifest dataset_id mismatch",
            details={
                "expected": dataset_id,
                "actual": manifest.dataset_id,
            },
        )
    if manifest.dataset_version is not None and manifest.dataset_version != dataset_version:
        raise ValidationError(
            "threshold manifest dataset_version mismatch",
            details={
                "expected": dataset_version,
                "actual": manifest.dataset_version,
            },
        )


def _metric_value(metric: str, aggregates: EvaluationAggregateMetrics) -> float | int:
    mapping: dict[str, float | int] = {
        "pass_rate": aggregates.pass_rate,
        "pass_count": aggregates.pass_count,
        "fail_count": aggregates.fail_count,
        "unevaluable_count": aggregates.unevaluable_count,
        "error_count": aggregates.error_count,
        "case_count": aggregates.case_count,
        "required_scorer_error_count": aggregates.required_scorer_error_count,
    }
    if metric not in mapping:
        raise ValidationError(
            f"unknown threshold metric: {metric}",
            details={"metric": metric},
        )
    return mapping[metric]


def _compare(op: str, actual: Any, expected: float) -> bool:
    if op == "gte":
        return float(actual) >= expected
    if op == "lte":
        return float(actual) <= expected
    if op == "eq":
        return float(actual) == expected
    raise ValidationError(f"unsupported threshold op: {op}", details={"op": op})


def _scorer_applies_to_case(
    scorer_id: str,
    case: EvaluationCaseResult,
    registry: ScorerRegistry,
) -> bool:
    registration = registry.get(scorer_id)
    return case.slice_type in registration.scorer.supported_slices


def _case_has_scorer_result(case: EvaluationCaseResult, scorer_id: str) -> bool:
    return any(result.scorer_id == scorer_id for result in case.scorer_results)


def _evaluate_rule(
    rule: EvaluationThresholdRule,
    aggregates: EvaluationAggregateMetrics,
) -> EvaluationGateDiff | None:
    actual = _metric_value(rule.metric, aggregates)
    if _compare(rule.op, actual, rule.value):
        return None
    return EvaluationGateDiff(
        field=rule.metric,
        expected=rule.value,
        actual=actual,
        reason=f"{rule.metric} {rule.op} {rule.value} failed",
    )


def _quarantine_diff(
    quarantine: EvaluationQuarantinePolicy,
    *,
    now: datetime,
) -> tuple[EvaluationGateDiff, bool]:
    """Return quarantine diff and whether quarantine is expired."""
    if quarantine.expires_at is not None and quarantine.expires_at < now:
        return (
            EvaluationGateDiff(
                field="quarantine",
                expected="active",
                actual="expired",
                reason=(
                    f"quarantine expired at {quarantine.expires_at.isoformat()} "
                    f"(owner={quarantine.owner})"
                ),
            ),
            True,
        )
    detail = quarantine.reason or "flaky gate quarantined"
    return (
        EvaluationGateDiff(
            field="quarantine",
            expected="blocking",
            actual="active",
            reason=f"quarantine active (owner={quarantine.owner}): {detail}",
        ),
        False,
    )


def _collect_threshold_diffs(
    manifest: EvaluationThresholdManifest,
    *,
    aggregates: EvaluationAggregateMetrics,
    case_results: list[EvaluationCaseResult],
    registry: ScorerRegistry,
) -> list[EvaluationGateDiff]:
    diffs: list[EvaluationGateDiff] = []

    registered = set(registry.scorer_ids)
    for scorer_id in manifest.required_scorers:
        if scorer_id not in registered:
            diffs.append(
                EvaluationGateDiff(
                    field="required_scorers",
                    expected=scorer_id,
                    actual="missing",
                    reason=f"required scorer not registered: {scorer_id}",
                )
            )

    for scorer_id in manifest.required_scorers:
        if scorer_id not in registered:
            continue
        for case in case_results:
            if not _scorer_applies_to_case(scorer_id, case, registry):
                continue
            if not _case_has_scorer_result(case, scorer_id):
                diffs.append(
                    EvaluationGateDiff(
                        field=f"scorer:{scorer_id}",
                        expected="executed",
                        actual="missing",
                        reason=(
                            f"required scorer did not run on case {case.case_id} "
                            f"(slice={case.slice_type.value})"
                        ),
                    )
                )
                continue
            for result in case.scorer_results:
                if result.scorer_id != scorer_id:
                    continue
                if result.outcome == ScorerOutcome.ERROR:
                    diffs.append(
                        EvaluationGateDiff(
                            field=f"scorer:{scorer_id}",
                            expected="pass_or_unevaluable",
                            actual=result.outcome.value,
                            reason=(
                                f"required scorer error on case {case.case_id}: "
                                f"{result.reason_code}"
                            ),
                        )
                    )

    if aggregates.pass_rate < manifest.min_pass_rate:
        diffs.append(
            EvaluationGateDiff(
                field="pass_rate",
                expected=manifest.min_pass_rate,
                actual=aggregates.pass_rate,
                reason="pass_rate below manifest minimum",
            )
        )

    if aggregates.error_count > manifest.max_error_count:
        diffs.append(
            EvaluationGateDiff(
                field="error_count",
                expected=manifest.max_error_count,
                actual=aggregates.error_count,
                reason="error_count above manifest maximum",
            )
        )

    for rule in manifest.thresholds:
        delta = _evaluate_rule(rule, aggregates)
        if delta is not None:
            diffs.append(delta)

    return diffs


def evaluate_gate(
    manifest: EvaluationThresholdManifest | None,
    *,
    aggregates: EvaluationAggregateMetrics,
    case_results: list[EvaluationCaseResult],
    registry: ScorerRegistry,
    manifest_path: str | None = None,
    now: datetime | None = None,
) -> EvaluationGateResult:
    """Evaluate versioned thresholds; missing manifest fail-closes when required."""
    if manifest is None:
        if manifest_path is not None:
            return EvaluationGateResult(
                verdict=GateVerdict.FAIL_CLOSED,
                manifest_path=manifest_path,
                diffs=[
                    EvaluationGateDiff(
                        field="threshold_manifest",
                        expected="present",
                        actual="missing",
                        reason="threshold manifest path provided but manifest could not be loaded",
                    )
                ],
            )
        return EvaluationGateResult(
            verdict=GateVerdict.PASS,
            manifest_version="",
            manifest_path=None,
            diffs=[],
        )

    evaluated_at = now or datetime.now(tz=UTC)
    diffs = _collect_threshold_diffs(
        manifest,
        aggregates=aggregates,
        case_results=case_results,
        registry=registry,
    )

    if manifest.quarantine is not None:
        quarantine_diff, expired = _quarantine_diff(manifest.quarantine, now=evaluated_at)
        diffs.insert(0, quarantine_diff)
        if expired:
            return EvaluationGateResult(
                verdict=GateVerdict.FAIL_CLOSED,
                manifest_version=manifest.manifest_version,
                manifest_path=manifest_path,
                diffs=diffs,
                quarantine_active=False,
            )
        return EvaluationGateResult(
            verdict=GateVerdict.PASS,
            manifest_version=manifest.manifest_version,
            manifest_path=manifest_path,
            diffs=diffs,
            quarantine_active=True,
        )

    if diffs:
        verdict = GateVerdict.FAIL_CLOSED if manifest.required_gate else GateVerdict.FAIL
    else:
        verdict = GateVerdict.PASS

    return EvaluationGateResult(
        verdict=verdict,
        manifest_version=manifest.manifest_version,
        manifest_path=manifest_path,
        diffs=diffs,
    )


__all__ = [
    "evaluate_gate",
    "load_threshold_manifest",
    "validate_threshold_manifest_for_run",
]
