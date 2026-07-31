"""Built-in evaluation scorers (ISSUE-105 / #608)."""

from app.evaluation.scorers.base import EvaluationScorer, ScorerContext, ScorerRegistration
from app.evaluation.scorers.registry import ScorerRegistry, default_scorer_registry
from app.evaluation.scorers.slice_scorers import (
    BenignSliceScorer,
    ThreatSliceScorer,
    UnevaluableSliceScorer,
)

__all__ = [
    "BenignSliceScorer",
    "EvaluationScorer",
    "ScorerContext",
    "ScorerRegistration",
    "ScorerRegistry",
    "ThreatSliceScorer",
    "UnevaluableSliceScorer",
    "default_scorer_registry",
]
