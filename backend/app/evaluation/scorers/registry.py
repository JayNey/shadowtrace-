"""Scorer registration for the evaluation runner (ISSUE-105 / #608)."""

from __future__ import annotations

from app.core.errors import ValidationError
from app.evaluation.scorers.base import ScorerRegistration
from app.models.evaluation_truth import SliceType


class ScorerRegistry:
    """In-memory scorer registry; #618B/#642 register additional scorers here."""

    def __init__(self) -> None:
        self._scorers: dict[str, ScorerRegistration] = {}

    def register(self, registration: ScorerRegistration) -> None:
        if registration.scorer_id in self._scorers:
            raise ValidationError(
                f"scorer already registered: {registration.scorer_id}",
                details={"scorer_id": registration.scorer_id},
            )
        self._scorers[registration.scorer_id] = registration

    def replace_scorer(self, registration: ScorerRegistration) -> None:
        """Replace an existing scorer registration (tests and controlled overrides)."""
        if registration.scorer_id not in self._scorers:
            raise ValidationError(
                f"scorer not registered: {registration.scorer_id}",
                details={"scorer_id": registration.scorer_id},
            )
        self._scorers[registration.scorer_id] = registration

    def get(self, scorer_id: str) -> ScorerRegistration:
        reg = self._scorers.get(scorer_id)
        if reg is None:
            raise ValidationError(
                f"unknown scorer: {scorer_id}",
                details={"scorer_id": scorer_id},
            )
        return reg

    def list_for_slice(self, slice_type: SliceType) -> list[ScorerRegistration]:
        return [reg for reg in self._scorers.values() if slice_type in reg.scorer.supported_slices]

    def all_required_ids(self) -> list[str]:
        return [reg.scorer_id for reg in self._scorers.values() if reg.required]

    @property
    def scorer_ids(self) -> list[str]:
        return sorted(self._scorers)


def default_scorer_registry() -> ScorerRegistry:
    """Built-in Phase A scorers for threat/benign/unevaluable slices."""
    from app.evaluation.scorers.slice_scorers import (
        BenignSliceScorer,
        ThreatSliceScorer,
        UnevaluableSliceScorer,
    )

    registry = ScorerRegistry()
    for scorer, required in (
        (ThreatSliceScorer(), True),
        (BenignSliceScorer(), True),
        (UnevaluableSliceScorer(), True),
    ):
        registry.register(
            ScorerRegistration(
                scorer_id=scorer.scorer_id,
                scorer=scorer,
                required=required,
            )
        )
    return registry


__all__ = ["ScorerRegistry", "default_scorer_registry"]
