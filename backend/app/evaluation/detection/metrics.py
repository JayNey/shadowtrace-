"""Detection evaluation quality and resource metrics (ISSUE-126 / #631 Phase A)."""

from __future__ import annotations

import math

from app.models.detection_evaluation import (
    DetectionCaseResult,
    DetectionResourceSummary,
    DetectionTenantSafetyProbe,
    DetectionTenantSafetySummary,
)
from app.models.evaluation_quality import (
    ConfidenceInterval,
    EvaluationQualityReport,
    MetricDenominator,
    QualityMetricStatus,
    QualityMetricValue,
)
from app.models.evaluation_run import EvaluationReleaseRefs, ScorerOutcome
from app.models.evaluation_truth import SliceType


def _wilson_interval(
    successes: int,
    total: int,
    *,
    level: float = 0.95,
) -> ConfidenceInterval | None:
    if total <= 0:
        return None
    z = 1.96 if level >= 0.95 else 1.645
    phat = successes / total
    z2 = z * z
    centre = (successes + z2 / 2) / (total + z2)
    margin = z * math.sqrt((phat * (1 - phat) + z2 / (4 * total)) / (total + z2))
    lower = max(0.0, centre - margin)
    upper = min(1.0, centre + margin)
    return ConfidenceInterval(lower=lower, upper=upper, level=level)


def _metric_value(
    metric_id: str,
    *,
    numerator: int,
    denominator: int,
    missing_truth_count: int,
    error_count: int,
    insufficient_sample: bool = False,
) -> QualityMetricValue:
    if error_count > 0:
        return QualityMetricValue(
            metric_id=metric_id,
            value=None,
            status=QualityMetricStatus.FAIL_CLOSED,
            denominator=MetricDenominator(
                numerator=numerator,
                denominator=denominator,
                missing_truth_count=missing_truth_count,
                error_count=error_count,
            ),
            reason="scorer error or missing truth; metric withheld",
        )
    if denominator <= 0 or insufficient_sample:
        return QualityMetricValue(
            metric_id=metric_id,
            value=None,
            status=QualityMetricStatus.INSUFFICIENT_SAMPLE,
            denominator=MetricDenominator(
                numerator=numerator,
                denominator=denominator,
                missing_truth_count=missing_truth_count,
                error_count=error_count,
            ),
            reason="insufficient sample for metric",
        )
    value = numerator / denominator
    return QualityMetricValue(
        metric_id=metric_id,
        value=value,
        status=QualityMetricStatus.COMPUTED,
        denominator=MetricDenominator(
            numerator=numerator,
            denominator=denominator,
            missing_truth_count=missing_truth_count,
            error_count=error_count,
        ),
        confidence_interval=_wilson_interval(numerator, denominator),
    )


def _primary_detection_outcome(case: DetectionCaseResult) -> ScorerOutcome | None:
    label_scorers = {
        SliceType.THREAT: "threat_detection",
        SliceType.BENIGN: "benign_detection",
        SliceType.UNEVALUABLE: "unevaluable_coverage",
    }
    scorer_id = label_scorers.get(case.slice_type)
    if scorer_id is None:
        return None
    for result in case.scorer_results:
        if result.scorer_id == scorer_id:
            return result.outcome
    return None


def _is_predicted_detection(case: DetectionCaseResult) -> bool:
    return bool(case.observation.candidates)


def build_detection_quality_report(
    *,
    dataset_id: str,
    dataset_version: str,
    dataset_content_hash: str,
    code_sha: str,
    release_refs: EvaluationReleaseRefs,
    case_results: list[DetectionCaseResult],
) -> EvaluationQualityReport:
    """Compute fail-closed detection quality metrics for one evaluation run."""
    sample_counts = {
        "total": len(case_results),
        "threat": sum(1 for c in case_results if c.slice_type == SliceType.THREAT),
        "benign": sum(1 for c in case_results if c.slice_type == SliceType.BENIGN),
        "unevaluable": sum(1 for c in case_results if c.slice_type == SliceType.UNEVALUABLE),
    }

    threat_tp = threat_fn = threat_errors = threat_missing = 0
    predicted_tp = predicted_fp = 0
    benign_tn = benign_fp = benign_errors = benign_missing = 0
    unevaluable_ok = unevaluable_bad = unevaluable_errors = unevaluable_missing = 0

    for case in case_results:
        outcome = _primary_detection_outcome(case)
        if case.slice_type == SliceType.THREAT:
            if outcome == ScorerOutcome.ERROR:
                threat_errors += 1
            elif outcome == ScorerOutcome.UNEVALUABLE:
                threat_missing += 1
                threat_fn += 1
            elif outcome == ScorerOutcome.PASS:
                threat_tp += 1
            else:
                threat_fn += 1
            if _is_predicted_detection(case):
                predicted_tp += 1
        elif case.slice_type == SliceType.BENIGN:
            if outcome == ScorerOutcome.ERROR:
                benign_errors += 1
            elif outcome == ScorerOutcome.UNEVALUABLE:
                benign_missing += 1
            elif outcome == ScorerOutcome.PASS:
                benign_tn += 1
            else:
                benign_fp += 1
            if _is_predicted_detection(case):
                predicted_fp += 1
        elif case.slice_type == SliceType.UNEVALUABLE:
            if outcome == ScorerOutcome.ERROR:
                unevaluable_errors += 1
            elif outcome == ScorerOutcome.UNEVALUABLE:
                unevaluable_ok += 1
            elif outcome is None:
                unevaluable_missing += 1
                unevaluable_bad += 1
            else:
                unevaluable_bad += 1

    threat_denominator = threat_tp + threat_fn
    precision_denominator = predicted_tp + predicted_fp
    benign_denominator = benign_tn + benign_fp
    unevaluable_denominator = unevaluable_ok + unevaluable_bad

    metrics = [
        _metric_value(
            "threat_recall",
            numerator=threat_tp,
            denominator=threat_denominator,
            missing_truth_count=threat_missing,
            error_count=threat_errors,
            insufficient_sample=threat_denominator < 1,
        ),
        _metric_value(
            "threat_precision",
            numerator=predicted_tp,
            denominator=precision_denominator,
            missing_truth_count=0,
            error_count=threat_errors,
            insufficient_sample=precision_denominator < 1,
        ),
        _metric_value(
            "benign_specificity",
            numerator=benign_tn,
            denominator=benign_denominator,
            missing_truth_count=benign_missing,
            error_count=benign_errors,
            insufficient_sample=benign_denominator < 1,
        ),
        _metric_value(
            "benign_fpr",
            numerator=benign_fp,
            denominator=benign_denominator,
            missing_truth_count=benign_missing,
            error_count=benign_errors,
            insufficient_sample=benign_denominator < 1,
        ),
        _metric_value(
            "unevaluable_coverage",
            numerator=unevaluable_ok,
            denominator=unevaluable_denominator,
            missing_truth_count=unevaluable_missing,
            error_count=unevaluable_errors,
            insufficient_sample=unevaluable_denominator < 1,
        ),
    ]

    return EvaluationQualityReport(
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        dataset_content_hash=dataset_content_hash,
        code_sha=code_sha,
        release_refs=release_refs,
        sample_counts=sample_counts,
        metrics=metrics,
        grouping_scorer_summaries=[],
    )


def quality_report_has_blocking_metrics(
    quality_report: EvaluationQualityReport | None,
) -> bool:
    """Return True when any metric is fail-closed or under-sampled."""
    if quality_report is None:
        return False
    return any(
        metric.status in {QualityMetricStatus.FAIL_CLOSED, QualityMetricStatus.INSUFFICIENT_SAMPLE}
        for metric in quality_report.metrics
    )


def build_resource_summary(case_results: list[DetectionCaseResult]) -> DetectionResourceSummary:
    total_rules = total_scanned = total_errors = total_candidates = max_scanned = 0
    total_duration = max_duration = 0
    for case in case_results:
        metrics = case.observation.resource_metrics
        total_rules += metrics.rules_evaluated
        total_scanned += metrics.observations_scanned
        total_errors += metrics.runtime_error_count
        total_candidates += metrics.candidate_count
        max_scanned = max(max_scanned, metrics.observations_scanned)
        total_duration += metrics.replay_duration_ms
        max_duration = max(max_duration, metrics.replay_duration_ms)
    return DetectionResourceSummary(
        total_rules_evaluated=total_rules,
        total_observations_scanned=total_scanned,
        total_runtime_errors=total_errors,
        total_candidates=total_candidates,
        max_observations_scanned_per_case=max_scanned,
        total_replay_duration_ms=total_duration,
        max_replay_duration_ms_per_case=max_duration,
    )


def build_tenant_safety_summary(probes: list[DetectionTenantSafetyProbe]) -> DetectionTenantSafetySummary:
    pass_count = sum(1 for probe in probes if probe.passed)
    return DetectionTenantSafetySummary(
        probe_count=len(probes),
        pass_count=pass_count,
        fail_count=len(probes) - pass_count,
        probes=probes,
    )


__all__ = [
    "build_detection_quality_report",
    "build_resource_summary",
    "build_tenant_safety_summary",
    "quality_report_has_blocking_metrics",
]
