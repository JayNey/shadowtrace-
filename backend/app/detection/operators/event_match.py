"""event_match operator — fires when criteria match at least one observation."""

from __future__ import annotations

from app.detection.operators.base import (
    OperatorExecutionContext,
    OperatorMatch,
    bounded_observations,
    group_key_from_observation,
    handle_missing_group_key,
    observation_matches_criteria,
    should_process_observation,
)
from app.models.detection_rule import DetectionRuleDefinition, RuleOperatorKind


class EventMatchOperator:
    operator_kind = RuleOperatorKind.EVENT_MATCH.value

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
            if not observation_matches_criteria(observation, rule.match_criteria):
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
            matched_value = float(len(observation_ids))
            if matched_value < rule.threshold:
                continue
            matches.append(
                OperatorMatch(
                    group_key=dict(key_tuple),
                    matched_value=matched_value,
                    observation_ids=observation_ids,
                    snapshot_ids=[],
                    window_start=context.window_start,
                    window_end=context.window_end,
                )
            )
        return matches
