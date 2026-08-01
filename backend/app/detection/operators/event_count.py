"""event_count operator — fires when grouped observation count meets threshold."""

from __future__ import annotations

from app.detection.operators.base import (
    OperatorExecutionContext,
    OperatorMatch,
    bounded_observations,
    group_key_from_observation,
    handle_missing_group_key,
    should_process_observation,
)
from app.models.detection_rule import DetectionRuleDefinition, RuleOperatorKind


class EventCountOperator:
    operator_kind = RuleOperatorKind.EVENT_COUNT.value

    def evaluate(
        self,
        rule: DetectionRuleDefinition,
        context: OperatorExecutionContext,
    ) -> list[OperatorMatch]:
        observations = bounded_observations(
            context.observations,
            max_scan=rule.max_observation_scan,
        )
        grouped: dict[tuple[tuple[str, str], ...], list[str]] = {}
        for observation in observations:
            if not should_process_observation(rule, observation):
                continue
            group_key = group_key_from_observation(
                observation,
                group_key_fields=rule.group_key_fields,
            )
            if group_key is None:
                handle_missing_group_key(rule)
                continue
            key_tuple = tuple(sorted(group_key.items()))
            grouped.setdefault(key_tuple, []).append(observation.observation_id)

        matches: list[OperatorMatch] = []
        for key_tuple, observation_ids in grouped.items():
            count = float(len(observation_ids))
            if count < rule.threshold:
                continue
            matches.append(
                OperatorMatch(
                    group_key=dict(key_tuple),
                    matched_value=count,
                    observation_ids=observation_ids,
                    snapshot_ids=[],
                    window_start=context.window_start,
                    window_end=context.window_end,
                )
            )
        return matches
