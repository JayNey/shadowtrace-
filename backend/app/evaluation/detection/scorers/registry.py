"""Detection scorer registration (ISSUE-126 / #631 Phase A)."""

from __future__ import annotations

from app.core.errors import ValidationError
from app.evaluation.detection.scorers.base import DetectionScorerRegistration
from app.models.evaluation_truth import SliceType


class DetectionScorerRegistry:
    """In-memory detection scorer registry."""

    def __init__(self) -> None:
        self._scorers: dict[str, DetectionScorerRegistration] = {}

    def register(self, registration: DetectionScorerRegistration) -> None:
        if registration.scorer_id in self._scorers:
            raise ValidationError(
                f"detection scorer already registered: {registration.scorer_id}",
                details={"scorer_id": registration.scorer_id},
            )
        self._scorers[registration.scorer_id] = registration

    def replace_scorer(self, registration: DetectionScorerRegistration) -> None:
        if registration.scorer_id not in self._scorers:
            raise ValidationError(
                f"detection scorer not registered: {registration.scorer_id}",
                details={"scorer_id": registration.scorer_id},
            )
        self._scorers[registration.scorer_id] = registration

    def get(self, scorer_id: str) -> DetectionScorerRegistration:
        reg = self._scorers.get(scorer_id)
        if reg is None:
            raise ValidationError(
                f"unknown detection scorer: {scorer_id}",
                details={"scorer_id": scorer_id},
            )
        return reg

    def list_for_slice(self, slice_type: SliceType) -> list[DetectionScorerRegistration]:
        return [reg for reg in self._scorers.values() if slice_type in reg.scorer.supported_slices]

    def all_required_ids(self) -> list[str]:
        return [reg.scorer_id for reg in self._scorers.values() if reg.required]

    @property
    def scorer_ids(self) -> list[str]:
        return sorted(self._scorers)


def default_detection_scorer_registry() -> DetectionScorerRegistry:
    from app.evaluation.detection.scorers.safety_scorers import (
        ResourceBudgetScorer,
        TenantIsolationScorer,
    )
    from app.evaluation.detection.scorers.slice_scorers import (
        BenignDetectionScorer,
        ThreatDetectionScorer,
        UnevaluableDetectionScorer,
    )

    registry = DetectionScorerRegistry()
    for scorer, required in (
        (ThreatDetectionScorer(), True),
        (BenignDetectionScorer(), True),
        (UnevaluableDetectionScorer(), True),
        (TenantIsolationScorer(), True),
        (ResourceBudgetScorer(), False),
    ):
        registry.register(
            DetectionScorerRegistration(
                scorer_id=scorer.scorer_id,
                scorer=scorer,
                required=required,
            )
        )
    return registry


__all__ = ["DetectionScorerRegistry", "default_detection_scorer_registry"]
