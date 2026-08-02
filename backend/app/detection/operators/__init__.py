"""Phase A detection rule operators (ISSUE-121 / #626)."""

from __future__ import annotations

from app.detection.operators.event_count import EventCountOperator
from app.detection.operators.event_match import EventMatchOperator
from app.detection.operators.registry import OperatorRegistry
from app.detection.operators.statistical_anomaly import StatisticalAnomalyOperator
from app.detection.operators.value_count import ValueCountOperator


def default_operator_registry() -> OperatorRegistry:
    registry = OperatorRegistry()
    registry.register(EventMatchOperator())
    registry.register(EventCountOperator())
    registry.register(ValueCountOperator())
    registry.register(StatisticalAnomalyOperator())
    return registry


__all__ = ["default_operator_registry", "OperatorRegistry"]
