"""Evaluation scorer plugin interface (ISSUE-105 / #608)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from app.models.evaluation_run import CaseObservation, EvaluationScorerResult
from app.models.evaluation_truth import EvaluationCaseTruth, SliceType


@dataclass(frozen=True, slots=True)
class ScorerContext:
    """Immutable context passed to every scorer invocation."""

    seed: int
    dataset_id: str
    dataset_version: str
    replay_mode: str = "mock_deterministic"


class EvaluationScorer(Protocol):
    """Slice-aware scorer registered into the evaluation runner."""

    scorer_id: str
    supported_slices: frozenset[SliceType]

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: CaseObservation,
        ctx: ScorerContext,
    ) -> EvaluationScorerResult: ...


@dataclass
class ScorerRegistration:
    scorer_id: str
    scorer: EvaluationScorer
    required: bool = True
    version: str = "1.0"
    metadata: dict[str, str] = field(default_factory=dict)


__all__ = [
    "EvaluationScorer",
    "ScorerContext",
    "ScorerRegistration",
]
