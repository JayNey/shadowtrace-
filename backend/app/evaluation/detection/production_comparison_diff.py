"""Post-promotion comparison baseline diff (ISSUE-126 / #631 Phase B)."""

from __future__ import annotations

from typing import Any

from app.evaluation.detection.production_artifact import finalize_production_comparison_artifact
from app.models.detection_production_comparison import DetectionProductionComparisonArtifact
from app.models.evaluation_run import EvaluationGateDiff


def _scalar_diff(field: str, left: Any, right: Any, *, reason: str) -> EvaluationGateDiff | None:
    if left == right:
        return None
    return EvaluationGateDiff(
        field=field,
        expected=left,
        actual=right,
        reason=reason,
    )


def diff_production_comparison_artifacts(
    baseline: DetectionProductionComparisonArtifact,
    candidate: DetectionProductionComparisonArtifact,
) -> list[EvaluationGateDiff]:
    diffs: list[EvaluationGateDiff] = []

    for field, reason in (
        ("schema_version", "comparison schema version changed"),
        ("recommendation", "recommendation changed"),
    ):
        delta = _scalar_diff(
            field,
            getattr(baseline, field),
            getattr(candidate, field),
            reason=reason,
        )
        if delta is not None:
            diffs.append(delta)

    if baseline.config.binding_manifest_hash != candidate.config.binding_manifest_hash:
        diffs.append(
            EvaluationGateDiff(
                field="config.binding_manifest_hash",
                expected=baseline.config.binding_manifest_hash,
                actual=candidate.config.binding_manifest_hash,
                reason="binding manifest hash changed",
            )
        )

    if baseline.coverage_drift.drift_detected != candidate.coverage_drift.drift_detected:
        diffs.append(
            EvaluationGateDiff(
                field="coverage_drift.drift_detected",
                expected=baseline.coverage_drift.drift_detected,
                actual=candidate.coverage_drift.drift_detected,
                reason="coverage drift signal changed",
            )
        )

    if baseline.status != candidate.status:
        diffs.append(
            EvaluationGateDiff(
                field="status",
                expected=baseline.status.value,
                actual=candidate.status.value,
                reason="comparison run status changed",
            )
        )

    baseline_cases = {item.case_id: item for item in baseline.case_comparisons}
    candidate_cases = {item.case_id: item for item in candidate.case_comparisons}
    for case_id in sorted(set(baseline_cases) | set(candidate_cases)):
        left = baseline_cases.get(case_id)
        right = candidate_cases.get(case_id)
        if left is None or right is None:
            diffs.append(
                EvaluationGateDiff(
                    field=f"case:{case_id}",
                    expected="present",
                    actual="missing",
                    reason=f"case {case_id} missing from one comparison artifact",
                )
            )
            continue
        if left.outcome_status != right.outcome_status:
            diffs.append(
                EvaluationGateDiff(
                    field=f"case:{case_id}.outcome_status",
                    expected=left.outcome_status.value,
                    actual=right.outcome_status.value,
                    reason=f"outcome status changed for case {case_id}",
                )
            )

    return diffs


def diff_production_comparison_against_baseline(
    baseline: DetectionProductionComparisonArtifact,
    candidate: DetectionProductionComparisonArtifact,
) -> list[EvaluationGateDiff]:
    aligned = candidate.model_copy(update={"code_sha": baseline.code_sha})
    aligned = finalize_production_comparison_artifact(aligned)
    return diff_production_comparison_artifacts(baseline, aligned)


__all__ = [
    "diff_production_comparison_against_baseline",
    "diff_production_comparison_artifacts",
]
