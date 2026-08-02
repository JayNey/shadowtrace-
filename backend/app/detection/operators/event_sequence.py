"""event_sequence operator — ordered observation subsequence detection (ISSUE-123 / #628)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.errors import ValidationError
from app.detection.operators.base import (
    OperatorExecutionContext,
    OperatorMatch,
    bounded_observations,
    group_key_from_observation,
    handle_missing_group_key,
    observation_matches_criteria,
    should_process_observation,
)
from app.detection.sequences.releases import (
    GEO_SENSITIVE_SEQUENCE_V1,
    IDENTITY_EXFIL_SEQUENCE_V1,
    SequenceRelease,
)
from app.models.behavior_observation import BehaviorObservation
from app.models.detection_rule import DetectionRuleDefinition, RuleOperatorKind

_KNOWN_SEQUENCE_RELEASES: dict[str, SequenceRelease] = {
    IDENTITY_EXFIL_SEQUENCE_V1.sequence_id: IDENTITY_EXFIL_SEQUENCE_V1,
    GEO_SENSITIVE_SEQUENCE_V1.sequence_id: GEO_SENSITIVE_SEQUENCE_V1,
}


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _dedupe_observations(observations: list[BehaviorObservation]) -> list[BehaviorObservation]:
    """Keep earliest occurrence per observation_id — duplicate refs are ignored."""
    ordered = sorted(observations, key=lambda item: (item.observed_at, item.observation_id))
    seen: set[str] = set()
    deduped: list[BehaviorObservation] = []
    for observation in ordered:
        if observation.observation_id in seen:
            continue
        seen.add(observation.observation_id)
        deduped.append(observation)
    return deduped


def _resolve_sequence_release(rule: DetectionRuleDefinition) -> tuple[SequenceRelease, int]:
    criteria = rule.match_criteria
    sequence_id = criteria.get("sequence_id")
    if not isinstance(sequence_id, str) or not sequence_id:
        raise ValidationError(
            "event_sequence requires sequence_id in match_criteria",
            details={"rule_id": rule.rule_id},
        )
    release = _KNOWN_SEQUENCE_RELEASES.get(sequence_id)
    if release is None:
        raise ValidationError(
            "unsupported sequence package",
            details={"rule_id": rule.rule_id, "sequence_id": sequence_id},
        )

    sequence_hash = criteria.get("sequence_hash")
    if not isinstance(sequence_hash, str) or not sequence_hash:
        raise ValidationError(
            "event_sequence requires sequence_hash in match_criteria",
            details={"rule_id": rule.rule_id, "sequence_id": sequence_id},
        )
    if sequence_hash != release.sequence_hash:
        raise ValidationError(
            "sequence package hash mismatch",
            details={
                "rule_id": rule.rule_id,
                "sequence_id": sequence_id,
                "expected_sequence_hash": sequence_hash,
            },
        )

    max_gap_raw = criteria.get("max_step_gap_seconds")
    if not isinstance(max_gap_raw, int) or max_gap_raw <= 0:
        raise ValidationError(
            "max_step_gap_seconds must be a positive integer",
            details={"rule_id": rule.rule_id, "max_step_gap_seconds": max_gap_raw},
        )
    if max_gap_raw != release.max_step_gap_seconds:
        raise ValidationError(
            "max_step_gap_seconds must match frozen sequence release",
            details={
                "rule_id": rule.rule_id,
                "sequence_id": sequence_id,
                "expected_max_step_gap_seconds": release.max_step_gap_seconds,
            },
        )
    return release, max_gap_raw


def find_ordered_sequence_match(
    observations: list[BehaviorObservation],
    steps: list[dict[str, object]],
    *,
    max_step_gap_seconds: int | None,
) -> list[BehaviorObservation] | None:
    """Greedy earliest-match ordered subsequence within optional inter-step gap."""
    if not steps:
        return None
    deduped = _dedupe_observations(observations)
    matched: list[BehaviorObservation] = []
    search_from = 0
    for step in steps:
        found: BehaviorObservation | None = None
        for idx in range(search_from, len(deduped)):
            candidate = deduped[idx]
            if not observation_matches_criteria(candidate, step):
                continue
            if matched and max_step_gap_seconds is not None:
                gap = (
                    _ensure_utc(candidate.observed_at) - _ensure_utc(matched[-1].observed_at)
                ).total_seconds()
                if gap > max_step_gap_seconds:
                    continue
            found = candidate
            search_from = idx + 1
            break
        if found is None:
            return None
        matched.append(found)
    return matched


def _build_step_match_records(
    matched: list[BehaviorObservation],
    steps: list[dict[str, object]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, (observation, step) in enumerate(zip(matched, steps, strict=True)):
        records.append(
            {
                "step_index": index,
                "observation_id": observation.observation_id,
                "source_revision": observation.source_ref.source_revision,
                "action": observation.action,
                "category": observation.category,
                "observed_at": _ensure_utc(observation.observed_at).isoformat(),
                "step_criteria": {key: step[key] for key in sorted(step)},
            }
        )
    return records


def _build_match_explanation(sequence_id: str, matched: list[BehaviorObservation]) -> str:
    actions = "→".join(obs.action or "?" for obs in matched)
    return f"matched sequence {sequence_id}: {actions}"


class EventSequenceOperator:
    operator_kind = RuleOperatorKind.EVENT_SEQUENCE.value

    def evaluate(
        self,
        rule: DetectionRuleDefinition,
        context: OperatorExecutionContext,
    ) -> list[OperatorMatch]:
        observations = bounded_observations(
            context.observations,
            max_scan=rule.max_observation_scan,
        )
        release, max_step_gap_seconds = _resolve_sequence_release(rule)
        steps = [dict(step) for step in release.sequence_steps]

        grouped: dict[tuple[tuple[str, str], ...], list[BehaviorObservation]] = {}
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
            grouped.setdefault(key_tuple, []).append(observation)

        matches: list[OperatorMatch] = []
        for key_tuple, group_observations in grouped.items():
            matched_observations = find_ordered_sequence_match(
                group_observations,
                steps,
                max_step_gap_seconds=max_step_gap_seconds,
            )
            if matched_observations is None:
                continue
            matched_value = float(len(matched_observations))
            if matched_value < rule.threshold:
                continue
            ordered_ids = [obs.observation_id for obs in matched_observations]
            step_records = _build_step_match_records(matched_observations, steps)
            matches.append(
                OperatorMatch(
                    group_key=dict(key_tuple),
                    matched_value=matched_value,
                    observation_ids=ordered_ids,
                    snapshot_ids=[],
                    window_start=context.window_start,
                    window_end=context.window_end,
                    sequence_provenance={
                        "sequence_id": release.sequence_id,
                        "sequence_hash": release.sequence_hash,
                        "max_step_gap_seconds": release.max_step_gap_seconds,
                        "ordered_observation_ids": ordered_ids,
                        "sequence_step_matches": step_records,
                        "match_explanation": _build_match_explanation(
                            release.sequence_id,
                            matched_observations,
                        ),
                    },
                )
            )
        return matches
