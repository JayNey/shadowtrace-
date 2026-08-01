"""Shared operator types for detection rule runtime."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.core.errors import ValidationError
from app.models.behavior_observation import BehaviorObservation
from app.models.detection_rule import DetectionRuleDefinition, MissingDataPolicy
from app.models.feature_snapshot import FeatureSnapshot


@dataclass(frozen=True)
class OperatorMatch:
    group_key: dict[str, str]
    matched_value: float
    observation_ids: list[str]
    snapshot_ids: list[str]
    window_start: datetime | None = None
    window_end: datetime | None = None


@dataclass(frozen=True)
class OperatorExecutionContext:
    source_tenant_id: str
    cutoff_at: datetime
    observations: list[BehaviorObservation]
    snapshots: list[FeatureSnapshot]
    window_start: datetime | None = None
    window_end: datetime | None = None


def group_key_from_observation(
    observation: BehaviorObservation,
    *,
    group_key_fields: list[str],
) -> dict[str, str] | None:
    values: dict[str, str] = {}
    for field_name in group_key_fields:
        if field_name == "entity_type":
            if not observation.entity_refs:
                return None
            values[field_name] = observation.entity_refs[0].entity_type
        elif field_name == "entity_id":
            if not observation.entity_refs:
                return None
            values[field_name] = observation.entity_refs[0].entity_id
        elif field_name == "category":
            if not observation.category:
                return None
            values[field_name] = observation.category
        elif field_name == "action":
            if not observation.action:
                return None
            values[field_name] = observation.action
        else:
            return None
    return values


def group_key_from_snapshot(
    snapshot: FeatureSnapshot,
    *,
    group_key_fields: list[str],
) -> dict[str, str] | None:
    values: dict[str, str] = {}
    for field_name in group_key_fields:
        if field_name == "entity_type":
            values[field_name] = snapshot.entity_type
        elif field_name == "entity_id":
            values[field_name] = snapshot.entity_id
        elif field_name == "category":
            counts = snapshot.features.get("category_counts")
            if not isinstance(counts, dict) or not counts:
                return None
            values[field_name] = max(counts.items(), key=lambda item: (item[1], item[0]))[0]
        elif field_name == "action":
            counts = snapshot.features.get("action_counts")
            if not isinstance(counts, dict) or not counts:
                return None
            values[field_name] = max(counts.items(), key=lambda item: (item[1], item[0]))[0]
        else:
            return None
    return values


def apply_missing_data_policy(
    *,
    policy: MissingDataPolicy,
    rule_id: str,
    reason: str,
) -> None:
    if policy is MissingDataPolicy.FAIL:
        raise ValidationError(
            f"missing required data for rule {rule_id}: {reason}",
            details={"rule_id": rule_id, "reason": reason},
        )


def observation_missing_required_field(
    observation: BehaviorObservation,
    field_name: str,
) -> bool:
    if field_name == "action":
        return not observation.action
    if field_name == "category":
        return not observation.category
    if field_name == "entity_type":
        return not observation.entity_refs
    if field_name == "entity_id":
        return not observation.entity_refs
    if field_name == "detection_score":
        return observation.detection_score is None
    if field_name == "observation_count":
        return True
    return True


def should_process_observation(
    rule: DetectionRuleDefinition,
    observation: BehaviorObservation,
) -> bool:
    """Apply required_fields + missing_data_policy before grouping."""
    for field_name in rule.required_fields:
        if observation_missing_required_field(observation, field_name):
            if rule.missing_data_policy is MissingDataPolicy.SKIP:
                return False
            if rule.missing_data_policy is MissingDataPolicy.TREAT_AS_ZERO:
                return False
            apply_missing_data_policy(
                policy=rule.missing_data_policy,
                rule_id=rule.rule_id,
                reason=f"missing required field {field_name}",
            )
    return True


def handle_missing_group_key(rule: DetectionRuleDefinition) -> None:
    if rule.missing_data_policy is MissingDataPolicy.FAIL:
        apply_missing_data_policy(
            policy=MissingDataPolicy.FAIL,
            rule_id=rule.rule_id,
            reason="unable to derive group key from observation",
        )


def bounded_observations(
    observations: list[BehaviorObservation],
    *,
    max_scan: int,
) -> list[BehaviorObservation]:
    if len(observations) > max_scan:
        raise ValidationError(
            "observation scan cost limit exceeded",
            details={"requested": len(observations), "max_scan": max_scan},
        )
    return observations


def observation_matches_criteria(
    observation: BehaviorObservation,
    criteria: dict[str, object],
) -> bool:
    for key, expected in criteria.items():
        if key == "action":
            if observation.action != expected:
                return False
        elif key == "category":
            if observation.category != expected:
                return False
        elif key == "entity_type":
            if not any(ref.entity_type == expected for ref in observation.entity_refs):
                return False
        elif key == "entity_id":
            if not any(ref.entity_id == expected for ref in observation.entity_refs):
                return False
        else:
            return False
    return True
