"""value_count operator — fires when snapshot feature value meets threshold."""

from __future__ import annotations

from app.detection.operators.base import (
    OperatorExecutionContext,
    OperatorMatch,
    apply_missing_data_policy,
    group_key_from_snapshot,
)
from app.models.detection_rule import DetectionRuleDefinition, MissingDataPolicy, RuleOperatorKind
from app.models.feature_snapshot import FeatureSnapshotStatus


class ValueCountOperator:
    operator_kind = RuleOperatorKind.VALUE_COUNT.value

    def evaluate(
        self,
        rule: DetectionRuleDefinition,
        context: OperatorExecutionContext,
    ) -> list[OperatorMatch]:
        if not rule.value_field:
            apply_missing_data_policy(
                policy=MissingDataPolicy.FAIL,
                rule_id=rule.rule_id,
                reason="value_field is required for value_count",
            )
            return []

        if len(context.snapshots) > rule.max_observation_scan:
            apply_missing_data_policy(
                policy=MissingDataPolicy.FAIL,
                rule_id=rule.rule_id,
                reason="snapshot scan cost limit exceeded",
            )

        matches: list[OperatorMatch] = []
        for snapshot in context.snapshots:
            if snapshot.status is not FeatureSnapshotStatus.READY:
                if rule.missing_data_policy is MissingDataPolicy.SKIP:
                    continue
                apply_missing_data_policy(
                    policy=rule.missing_data_policy,
                    rule_id=rule.rule_id,
                    reason="snapshot not ready",
                )
                continue

            raw_value = snapshot.features.get(rule.value_field)
            if raw_value is None:
                if rule.missing_data_policy is MissingDataPolicy.TREAT_AS_ZERO:
                    value = 0.0
                elif rule.missing_data_policy is MissingDataPolicy.SKIP:
                    continue
                else:
                    apply_missing_data_policy(
                        policy=rule.missing_data_policy,
                        rule_id=rule.rule_id,
                        reason=f"missing feature field {rule.value_field}",
                    )
                    continue
            else:
                try:
                    value = float(raw_value)
                except (TypeError, ValueError):
                    if rule.missing_data_policy is MissingDataPolicy.SKIP:
                        continue
                    apply_missing_data_policy(
                        policy=rule.missing_data_policy,
                        rule_id=rule.rule_id,
                        reason=f"non-numeric feature field {rule.value_field}",
                    )
                    continue

            if value < rule.threshold:
                continue

            group_key = group_key_from_snapshot(
                snapshot,
                group_key_fields=rule.group_key_fields,
            )
            if group_key is None:
                if rule.missing_data_policy is MissingDataPolicy.SKIP:
                    continue
                apply_missing_data_policy(
                    policy=rule.missing_data_policy,
                    rule_id=rule.rule_id,
                    reason="unable to derive group key from snapshot",
                )
                continue

            matches.append(
                OperatorMatch(
                    group_key=group_key,
                    matched_value=value,
                    observation_ids=[],
                    snapshot_ids=[snapshot.snapshot_id],
                    window_start=snapshot.window_start,
                    window_end=snapshot.window_end,
                )
            )
        return matches
