"""Detection evaluation scorer plugin interface (ISSUE-126 / #631 Phase A)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from app.models.detection_evaluation import DetectionCaseObservation
from app.models.evaluation_run import EvaluationScorerResult
from app.models.evaluation_truth import EvaluationCaseTruth, SliceType


@dataclass(frozen=True, slots=True)
class DetectionScorerContext:
    """Immutable context passed to every detection scorer invocation."""

    seed: int
    dataset_id: str
    dataset_version: str
    replay_mode: str = "detection_shadow"
    source_tenant_id: str = ""
    probe_tenant_id: str | None = None
    expected_rule_ids: tuple[str, ...] = ()
    max_observations_scanned: int | None = None


class DetectionEvaluationScorer(Protocol):
    """Slice-aware scorer for detection shadow replay observations."""

    scorer_id: str
    supported_slices: frozenset[SliceType]

    def score(
        self,
        truth: EvaluationCaseTruth,
        observation: DetectionCaseObservation,
        ctx: DetectionScorerContext,
    ) -> EvaluationScorerResult: ...


@dataclass
class DetectionScorerRegistration:
    scorer_id: str
    scorer: DetectionEvaluationScorer
    required: bool = True
    version: str = "1.0"
    metadata: dict[str, str] = field(default_factory=dict)


__all__ = [
    "DetectionEvaluationScorer",
    "DetectionScorerContext",
    "DetectionScorerRegistration",
]
