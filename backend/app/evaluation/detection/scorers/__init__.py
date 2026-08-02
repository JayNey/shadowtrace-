"""Detection scorer package (ISSUE-126 / #631 Phase A)."""

from app.evaluation.detection.scorers.registry import (
    DetectionScorerRegistry,
    default_detection_scorer_registry,
)

__all__ = ["DetectionScorerRegistry", "default_detection_scorer_registry"]
