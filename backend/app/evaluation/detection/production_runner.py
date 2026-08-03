"""Post-promotion detection comparison runner (ISSUE-126 / #631 Phase B)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.evaluation.detection.production_artifact import finalize_production_comparison_artifact
from app.evaluation.detection.production_collector import (
    list_completed_promotions_by_candidate,
    load_latest_snapshot_for_promotion,
)
from app.evaluation.detection.production_diff import (
    compare_production_case,
    derive_production_recommendation,
    summarize_coverage_drift,
)
from app.evaluation.detection.production_fixture_loader import binding_by_case_id
from app.models.detection_context_snapshot import DetectionContextEvaluationRefs
from app.models.detection_evaluation import DetectionEvaluationArtifact
from app.models.detection_production_comparison import (
    DetectionProductionBindingManifest,
    DetectionProductionComparisonArtifact,
    DetectionProductionComparisonConfig,
    DetectionProductionRecommendationKind,
)
from app.models.evaluation_run import EvaluationRunStatus
from app.services.detection_context_service import DetectionContextService


def _phase_a_evaluation_refs(
    artifact: DetectionEvaluationArtifact,
) -> DetectionContextEvaluationRefs:
    return DetectionContextEvaluationRefs(
        evaluation_id=artifact.evaluation_id,
        artifact_hash=artifact.artifact_hash,
        dataset_id=artifact.dataset_id,
        dataset_version=artifact.dataset_version,
        dataset_content_hash=artifact.dataset_content_hash,
        code_sha=artifact.code_sha,
    )


def _candidate_ids_from_phase_a(artifact: DetectionEvaluationArtifact) -> set[str]:
    ids: set[str] = set()
    for case in artifact.case_results:
        for candidate in case.observation.candidates:
            ids.add(candidate.candidate_detection_id)
    return ids


def _comparison_status(
    recommendation: DetectionProductionRecommendationKind,
    errors: list[str],
) -> EvaluationRunStatus:
    if errors:
        return EvaluationRunStatus.FAILED
    if recommendation is DetectionProductionRecommendationKind.INSUFFICIENT_DATA:
        return EvaluationRunStatus.UNEVALUABLE
    if recommendation is DetectionProductionRecommendationKind.ROLLBACK_RECOMMENDED:
        return EvaluationRunStatus.FAILED
    return EvaluationRunStatus.COMPLETED


@dataclass(frozen=True, slots=True)
class DetectionProductionComparisonRunRequest:
    phase_a_artifact: DetectionEvaluationArtifact
    binding_manifest: DetectionProductionBindingManifest
    code_sha: str
    seed: int = 0


class DetectionProductionComparisonRunner:
    """Compare completed promotions against a pinned Phase A evaluation artifact."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        context_service: DetectionContextService | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._context_service = context_service or DetectionContextService(session_factory)

    async def run(
        self,
        request: DetectionProductionComparisonRunRequest,
    ) -> DetectionProductionComparisonArtifact:
        started_at = datetime.now(tz=UTC)
        phase_a = request.phase_a_artifact
        bindings = binding_by_case_id(request.binding_manifest)

        if request.binding_manifest.shadow_dataset_id != phase_a.dataset_id:
            raise ValidationError(
                "binding manifest dataset_id mismatch",
                details={
                    "expected": phase_a.dataset_id,
                    "actual": request.binding_manifest.shadow_dataset_id,
                },
            )
        if request.binding_manifest.shadow_dataset_version != phase_a.dataset_version:
            raise ValidationError(
                "binding manifest dataset_version mismatch",
                details={
                    "expected": phase_a.dataset_version,
                    "actual": request.binding_manifest.shadow_dataset_version,
                },
            )

        candidate_ids = _candidate_ids_from_phase_a(phase_a)
        promotions = await list_completed_promotions_by_candidate(
            self._session_factory,
            tenant_id=phase_a.tenant_id,
            candidate_detection_ids=candidate_ids,
        )

        comparisons = []
        snapshots = []
        # Fail-fast: collector/loader errors propagate; errors stays empty unless extended.
        errors: list[str] = []

        for case in phase_a.case_results:
            binding = bindings.get(case.case_id)
            candidates = case.observation.candidates
            candidate_id = candidates[0].candidate_detection_id if candidates else None
            promotion = promotions.get(candidate_id) if candidate_id else None
            snapshot = None
            if promotion is not None:
                snapshot = await load_latest_snapshot_for_promotion(
                    self._context_service,
                    tenant_id=phase_a.tenant_id,
                    promotion_id=promotion.promotion_id,
                )
                if snapshot is not None:
                    snapshots.append(snapshot)
            comparisons.append(
                compare_production_case(
                    case,
                    binding,
                    promotion,
                    snapshot,
                    phase_a_artifact=phase_a,
                )
            )

        coverage_drift = summarize_coverage_drift(comparisons, snapshots)
        recommendation, recommendation_reasons = derive_production_recommendation(
            comparisons,
            coverage_drift,
        )
        status = _comparison_status(recommendation, errors)
        completed_at = datetime.now(tz=UTC)

        artifact = DetectionProductionComparisonArtifact(
            comparison_id=f"det-prod-cmp-{uuid.uuid4()}",
            tenant_id=phase_a.tenant_id,
            code_sha=request.code_sha,
            phase_a_refs=_phase_a_evaluation_refs(phase_a),
            config=DetectionProductionComparisonConfig(
                phase_a_artifact_hash=phase_a.artifact_hash,
                phase_a_evaluation_id=phase_a.evaluation_id,
                binding_manifest_hash=request.binding_manifest.content_hash,
                seed=request.seed,
            ),
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            case_comparisons=comparisons,
            coverage_drift=coverage_drift,
            recommendation=recommendation,
            recommendation_reasons=recommendation_reasons,
            errors=errors,
        )
        return finalize_production_comparison_artifact(artifact)


async def run_production_comparison(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    phase_a_artifact: DetectionEvaluationArtifact,
    binding_manifest: DetectionProductionBindingManifest,
    code_sha: str,
    seed: int = 0,
) -> DetectionProductionComparisonArtifact:
    runner = DetectionProductionComparisonRunner(session_factory)
    return await runner.run(
        DetectionProductionComparisonRunRequest(
            phase_a_artifact=phase_a_artifact,
            binding_manifest=binding_manifest,
            code_sha=code_sha,
            seed=seed,
        )
    )


__all__ = [
    "DetectionProductionComparisonRunRequest",
    "DetectionProductionComparisonRunner",
    "run_production_comparison",
]
