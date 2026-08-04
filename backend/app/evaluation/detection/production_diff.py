"""Shadow vs production outcome comparison (ISSUE-126 / #631 Phase B)."""

from __future__ import annotations

from app.models.detection_context_snapshot import DetectionContextSnapshot
from app.models.detection_evaluation import DetectionCaseResult, DetectionEvaluationArtifact
from app.models.detection_production_comparison import (
    DetectionProductionCaseBinding,
    DetectionProductionCaseComparison,
    DetectionProductionCoverageDrift,
    DetectionProductionOutcomeStatus,
    DetectionProductionRecommendationKind,
)
from app.models.detection_promotion import DetectionPromotionRecord, DetectionPromotionStatus
from app.models.evaluation_truth import SliceType


def _primary_candidate_id(case: DetectionCaseResult) -> str | None:
    if case.observation.candidates:
        return case.observation.candidates[0].candidate_detection_id
    return None


def _coverage_ready_ratio(snapshot: DetectionContextSnapshot) -> float | None:
    coverage = snapshot.coverage
    total = coverage.feature_snapshot_count
    if total <= 0:
        return None
    return coverage.ready_snapshot_count / total


def compare_production_case(
    case: DetectionCaseResult,
    binding: DetectionProductionCaseBinding | None,
    promotion: DetectionPromotionRecord | None,
    snapshot: DetectionContextSnapshot | None,
    *,
    phase_a_artifact: DetectionEvaluationArtifact,
) -> DetectionProductionCaseComparison:
    expect_promotion = (
        binding.expect_promotion
        if binding is not None
        else (case.slice_type == SliceType.THREAT and bool(case.observation.candidates))
    )
    candidate_id = _primary_candidate_id(case)
    shadow_candidate_count = len(case.observation.candidates)
    drift_reasons: list[str] = []

    if not expect_promotion:
        if promotion is not None and promotion.status == DetectionPromotionStatus.COMPLETED:
            return DetectionProductionCaseComparison(
                case_id=case.case_id,
                slice_type=case.slice_type,
                shadow_case_status=case.case_status,
                shadow_candidate_count=shadow_candidate_count,
                outcome_status=DetectionProductionOutcomeStatus.UNEXPECTED_PROMOTION,
                promotion_id=promotion.promotion_id,
                event_id=promotion.event_id,
                candidate_detection_id=candidate_id,
                drift_reasons=["unexpected completed promotion for non-promotion case"],
            )
        return DetectionProductionCaseComparison(
            case_id=case.case_id,
            slice_type=case.slice_type,
            shadow_case_status=case.case_status,
            shadow_candidate_count=shadow_candidate_count,
            outcome_status=DetectionProductionOutcomeStatus.NOT_APPLICABLE,
            candidate_detection_id=candidate_id,
        )

    if promotion is None:
        return DetectionProductionCaseComparison(
            case_id=case.case_id,
            slice_type=case.slice_type,
            shadow_case_status=case.case_status,
            shadow_candidate_count=shadow_candidate_count,
            outcome_status=DetectionProductionOutcomeStatus.MISSING_PROMOTION,
            candidate_detection_id=candidate_id,
            drift_reasons=["expected completed promotion not found"],
        )

    if promotion.status != DetectionPromotionStatus.COMPLETED:
        drift_reasons.append(f"promotion status is {promotion.status.value}")
        return DetectionProductionCaseComparison(
            case_id=case.case_id,
            slice_type=case.slice_type,
            shadow_case_status=case.case_status,
            shadow_candidate_count=shadow_candidate_count,
            outcome_status=DetectionProductionOutcomeStatus.DRIFT,
            promotion_id=promotion.promotion_id,
            event_id=promotion.event_id,
            candidate_detection_id=candidate_id,
            drift_reasons=drift_reasons,
        )

    if snapshot is None:
        return DetectionProductionCaseComparison(
            case_id=case.case_id,
            slice_type=case.slice_type,
            shadow_case_status=case.case_status,
            shadow_candidate_count=shadow_candidate_count,
            outcome_status=DetectionProductionOutcomeStatus.SNAPSHOT_MISSING,
            promotion_id=promotion.promotion_id,
            event_id=promotion.event_id,
            candidate_detection_id=candidate_id,
            drift_reasons=["completed promotion missing trusted context snapshot"],
        )

    if case.candidate_refs is not None:
        if promotion.package_content_hash != case.candidate_refs.package_content_hash:
            drift_reasons.append("package_content_hash mismatch")
    if case.observation.candidates:
        expected_hash = case.observation.candidates[0].content_hash
        if promotion.candidate_content_hash != expected_hash:
            drift_reasons.append("candidate_content_hash mismatch")

    eval_refs = snapshot.evaluation_refs
    if eval_refs.artifact_hash != phase_a_artifact.artifact_hash:
        drift_reasons.append("context snapshot evaluation artifact hash mismatch")
    if eval_refs.evaluation_id != phase_a_artifact.evaluation_id:
        drift_reasons.append("context snapshot evaluation_id mismatch")

    production_severity = snapshot.scores.severity
    if binding is not None and binding.expected_production_severity is not None:
        if production_severity != binding.expected_production_severity:
            drift_reasons.append(
                f"production severity {production_severity!r} != "
                f"expected {binding.expected_production_severity!r}"
            )

    ready_ratio = _coverage_ready_ratio(snapshot)
    min_ratio = binding.min_coverage_ready_ratio if binding is not None else None
    if min_ratio is not None and ready_ratio is not None and ready_ratio < min_ratio:
        drift_reasons.append(
            f"coverage ready ratio {ready_ratio:.3f} below minimum {min_ratio:.3f}"
        )

    if shadow_candidate_count == 0 and case.slice_type == SliceType.THREAT:
        drift_reasons.append("shadow produced no candidates for threat case")

    outcome = (
        DetectionProductionOutcomeStatus.DRIFT
        if drift_reasons
        else DetectionProductionOutcomeStatus.ALIGNED
    )
    return DetectionProductionCaseComparison(
        case_id=case.case_id,
        slice_type=case.slice_type,
        shadow_case_status=case.case_status,
        shadow_candidate_count=shadow_candidate_count,
        outcome_status=outcome,
        promotion_id=promotion.promotion_id,
        event_id=promotion.event_id,
        candidate_detection_id=candidate_id,
        production_severity=production_severity,
        coverage_ready_count=snapshot.coverage.ready_snapshot_count,
        coverage_total_count=snapshot.coverage.feature_snapshot_count,
        drift_reasons=drift_reasons,
    )


def summarize_coverage_drift(
    comparisons: list[DetectionProductionCaseComparison],
    snapshots: list[DetectionContextSnapshot],
) -> DetectionProductionCoverageDrift:
    compared = [
        item
        for item in comparisons
        if item.outcome_status
        not in {
            DetectionProductionOutcomeStatus.NOT_APPLICABLE,
            DetectionProductionOutcomeStatus.MISSING_PROMOTION,
        }
    ]
    ready_total = sum(snapshot.coverage.ready_snapshot_count for snapshot in snapshots)
    feature_total = sum(snapshot.coverage.feature_snapshot_count for snapshot in snapshots)
    insufficient_total = sum(
        snapshot.coverage.insufficient_coverage_count for snapshot in snapshots
    )
    drift_reasons: list[str] = []
    drift_detected = False
    if feature_total > 0:
        ratio = ready_total / feature_total
        if ratio < 0.5:
            drift_detected = True
            drift_reasons.append(f"aggregate coverage ready ratio {ratio:.3f} below 0.5")
    if insufficient_total > 0:
        drift_detected = True
        drift_reasons.append(
            f"{insufficient_total} insufficient coverage snapshot(s) in production"
        )
    if any(item.outcome_status == DetectionProductionOutcomeStatus.DRIFT for item in compared):
        drift_detected = True
        drift_reasons.append("one or more case comparisons drifted")
    return DetectionProductionCoverageDrift(
        compared_case_count=len(compared),
        production_ready_snapshot_total=ready_total,
        production_feature_snapshot_total=feature_total,
        production_insufficient_coverage_total=insufficient_total,
        drift_detected=drift_detected,
        drift_reasons=drift_reasons,
    )


def derive_production_recommendation(
    comparisons: list[DetectionProductionCaseComparison],
    coverage_drift: DetectionProductionCoverageDrift,
) -> tuple[DetectionProductionRecommendationKind, list[str]]:
    reasons: list[str] = []
    missing = [
        item
        for item in comparisons
        if item.outcome_status == DetectionProductionOutcomeStatus.MISSING_PROMOTION
    ]
    if missing:
        reasons.append(f"{len(missing)} case(s) missing expected completed promotion")
        return DetectionProductionRecommendationKind.INSUFFICIENT_DATA, reasons

    snapshot_missing = [
        item
        for item in comparisons
        if item.outcome_status == DetectionProductionOutcomeStatus.SNAPSHOT_MISSING
    ]
    if snapshot_missing:
        reasons.append(f"{len(snapshot_missing)} case(s) missing trusted context snapshot")
        return DetectionProductionRecommendationKind.INSUFFICIENT_DATA, reasons

    drift_cases = [
        item
        for item in comparisons
        if item.outcome_status
        in {
            DetectionProductionOutcomeStatus.DRIFT,
            DetectionProductionOutcomeStatus.UNEXPECTED_PROMOTION,
        }
    ]
    threat_drifts = [item for item in drift_cases if item.slice_type == SliceType.THREAT]
    if threat_drifts:
        reasons.append(f"{len(threat_drifts)} threat case(s) drifted in production")
        return DetectionProductionRecommendationKind.ROLLBACK_RECOMMENDED, reasons

    if drift_cases:
        reasons.append(f"{len(drift_cases)} non-threat case(s) drifted in production")
        return DetectionProductionRecommendationKind.MONITOR, reasons

    if coverage_drift.drift_detected:
        reasons.extend(coverage_drift.drift_reasons)
        return DetectionProductionRecommendationKind.MONITOR, reasons

    reasons.append("production outcomes aligned with shadow evaluation")
    return DetectionProductionRecommendationKind.CONTINUE, reasons


__all__ = [
    "compare_production_case",
    "derive_production_recommendation",
    "summarize_coverage_drift",
]
