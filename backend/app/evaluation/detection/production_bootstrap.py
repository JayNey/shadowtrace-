"""Bootstrap completed promotions for post-promotion comparison (ISSUE-126 Phase B)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.auth import Principal
from app.core.redis_client import RedisClient
from app.evaluation.detection.production_collector import list_completed_promotions_by_candidate
from app.evaluation.detection.production_fixture_loader import binding_by_case_id
from app.ingestion.source_ingester import SourceIngester
from app.models.detection_evaluation import DetectionEvaluationArtifact
from app.models.detection_governance import (
    DetectionGovernanceDecisionKind,
    DetectionGovernanceDecisionRequest,
)
from app.models.detection_production_comparison import (
    DetectionProductionBindingManifest,
    DetectionProductionCaseBinding,
)
from app.models.detection_promotion import DetectionPromotionRequest
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.detection_context_projector import DetectionContextProjector
from app.services.detection_governance_service import DetectionGovernanceService
from app.services.detection_promotion_service import DetectionPromotionService
from app.services.event_service import EventService


@dataclass(frozen=True, slots=True)
class ProductionPromotionBootstrapResult:
    promoted_case_ids: tuple[str, ...]
    skipped_case_ids: tuple[str, ...]


def _reviewer_principal(tenant_id: str) -> Principal:
    return Principal(subject="detection-production-bootstrap", roles=["admin"], tenant_id=tenant_id)


def _expect_promotion(
    binding: DetectionProductionCaseBinding | None,
    *,
    has_candidates: bool,
    slice_type_value: str,
) -> bool:
    if binding is not None:
        return binding.expect_promotion
    return slice_type_value == "threat" and has_candidates


def _candidate_ids_for_promotion(
    artifact: DetectionEvaluationArtifact,
    bindings: dict[str, DetectionProductionCaseBinding],
) -> dict[str, str]:
    """Map case_id -> candidate_detection_id for cases expecting promotion."""
    expected: dict[str, str] = {}
    for case in artifact.case_results:
        binding = bindings.get(case.case_id)
        if not _expect_promotion(
            binding,
            has_candidates=bool(case.observation.candidates),
            slice_type_value=case.slice_type.value,
        ):
            continue
        if not case.observation.candidates:
            raise ValueError(
                f"case {case.case_id!r} expects promotion but Phase A artifact has no candidates"
            )
        expected[case.case_id] = case.observation.candidates[0].candidate_detection_id
    return expected


async def bootstrap_production_promotions(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
    *,
    phase_a_artifact: DetectionEvaluationArtifact,
    binding_manifest: DetectionProductionBindingManifest,
    threshold_manifest_path: Path,
) -> ProductionPromotionBootstrapResult:
    """Approve and promote candidates referenced by a pinned Phase A artifact."""
    bindings = binding_by_case_id(binding_manifest)
    expected = _candidate_ids_for_promotion(phase_a_artifact, bindings)
    if not expected:
        return ProductionPromotionBootstrapResult(promoted_case_ids=(), skipped_case_ids=())

    existing = await list_completed_promotions_by_candidate(
        session_factory,
        tenant_id=phase_a_artifact.tenant_id,
        candidate_detection_ids=set(expected.values()),
    )

    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    events = EventService(session_factory, store, degraded_flags=degraded)
    ingester = SourceIngester(events, session_factory, source_mode="mock_xdr")
    promotion_service = DetectionPromotionService(
        session_factory,
        event_service=events,
        source_ingester=ingester,
        context_projector=DetectionContextProjector(session_factory),
    )
    governance = DetectionGovernanceService(session_factory)

    promoted: list[str] = []
    skipped: list[str] = []
    decision = await governance.record_decision(
        _reviewer_principal(phase_a_artifact.tenant_id),
        phase_a_artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            reason_note="detection production comparison bootstrap",
            expires_at=datetime.now(tz=UTC) + timedelta(hours=1),
        ),
        threshold_manifest_path=threshold_manifest_path,
    )

    for case_id, candidate_id in sorted(expected.items()):
        if candidate_id in existing:
            skipped.append(case_id)
            continue
        await promotion_service.promote_candidate(
            phase_a_artifact,
            DetectionPromotionRequest(
                tenant_id=phase_a_artifact.tenant_id,
                candidate_detection_id=candidate_id,
                decision_id=decision.decision_id,
            ),
        )
        promoted.append(case_id)

    return ProductionPromotionBootstrapResult(
        promoted_case_ids=tuple(promoted),
        skipped_case_ids=tuple(skipped),
    )


__all__ = [
    "ProductionPromotionBootstrapResult",
    "bootstrap_production_promotions",
]
