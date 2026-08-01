"""Operator registry for detection rule runtime."""

from __future__ import annotations

from typing import Protocol

from app.core.errors import ValidationError
from app.detection.operators.base import OperatorExecutionContext, OperatorMatch
from app.models.detection_rule import DetectionRuleDefinition


class RuleOperator(Protocol):
    operator_kind: str

    def evaluate(
        self,
        rule: DetectionRuleDefinition,
        context: OperatorExecutionContext,
    ) -> list[OperatorMatch]: ...


class OperatorRegistry:
    def __init__(self) -> None:
        self._operators: dict[str, RuleOperator] = {}

    def register(self, operator: RuleOperator) -> None:
        kind = operator.operator_kind
        if kind in self._operators:
            raise ValidationError(
                f"operator already registered: {kind}",
                details={"operator": kind},
            )
        self._operators[kind] = operator

    def get(self, operator_kind: str) -> RuleOperator:
        operator = self._operators.get(operator_kind)
        if operator is None:
            raise ValidationError(
                f"unknown rule operator: {operator_kind}",
                details={"operator": operator_kind},
            )
        return operator
