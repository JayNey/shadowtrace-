"""Detection offline/shadow evaluation package (ISSUE-126 / #631 Phase A)."""

from app.evaluation.detection.runner import (
    DetectionEvaluationRunner,
    DetectionEvaluationRunRequest,
    run_fixture_detection_evaluation,
)

__all__ = [
    "DetectionEvaluationRunRequest",
    "DetectionEvaluationRunner",
    "run_fixture_detection_evaluation",
]
