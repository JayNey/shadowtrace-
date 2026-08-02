"""statistical_anomaly operator — MAD/quantile robust scorer (ISSUE-122 / #627)."""

from __future__ import annotations

from typing import Any

from app.core.errors import ValidationError
from app.detection.operators.base import (
    OperatorExecutionContext,
    OperatorMatch,
    apply_missing_data_policy,
    group_key_from_snapshot,
)
from app.detection.scoring.anomaly_scorer import score_snapshot
from app.detection.scoring.release import MOCK_ACCOUNT_MAD_RELEASE, AnomalyScorerRelease
from app.models.detection_rule import DetectionRuleDefinition, MissingDataPolicy, RuleOperatorKind
from app.models.feature_snapshot import DetectionFeatureBaseline


def _snapshot_matches_criteria(snapshot: Any, criteria: dict[str, Any]) -> bool:
    for key in ("entity_type", "entity_id"):
        expected = criteria.get(key)
        if isinstance(expected, str) and getattr(snapshot, key, None) != expected:
            return False
    return True


def _baseline_for_entity(
    entity_type: str,
    entity_id: str,
    baselines: list[DetectionFeatureBaseline],
) -> DetectionFeatureBaseline | None:
    for baseline in baselines:
        if baseline.entity_type == entity_type and baseline.entity_id == entity_id:
            return baseline
    return None


def _resolve_release(rule: DetectionRuleDefinition) -> AnomalyScorerRelease:
    release_id = rule.match_criteria.get("model_release_id")
    if release_id is None or release_id == MOCK_ACCOUNT_MAD_RELEASE.release_id:
        return MOCK_ACCOUNT_MAD_RELEASE
    raise ValidationError(
        "unsupported anomaly scorer release",
        details={"model_release_id": release_id},
    )


class StatisticalAnomalyOperator:
    operator_kind = RuleOperatorKind.STATISTICAL_ANOMALY.value

    def evaluate(
        self,
        rule: DetectionRuleDefinition,
        context: OperatorExecutionContext,
    ) -> list[OperatorMatch]:
        release = _resolve_release(rule)
        expected_release_hash = rule.match_criteria.get("model_release_hash")
        if isinstance(expected_release_hash, str):
            release.verify_hash(expected_release_hash)

        expected_baseline_hash = rule.match_criteria.get("baseline_content_hash")
        if expected_baseline_hash is not None and not isinstance(expected_baseline_hash, str):
            expected_baseline_hash = None

        robust_z_threshold = (
            rule.threshold if rule.threshold > 0 else release.default_robust_z_threshold
        )

        matches: list[OperatorMatch] = []
        for snapshot in context.snapshots:
            if rule.match_criteria and not _snapshot_matches_criteria(
                snapshot, rule.match_criteria
            ):
                continue

            baseline = _baseline_for_entity(
                snapshot.entity_type,
                snapshot.entity_id,
                context.baselines,
            )
            if baseline is None:
                if rule.missing_data_policy is MissingDataPolicy.SKIP:
                    continue
                apply_missing_data_policy(
                    policy=rule.missing_data_policy,
                    rule_id=rule.rule_id,
                    reason="missing detection feature baseline for snapshot entity",
                )
                continue

            scored = score_snapshot(
                snapshot=snapshot,
                baseline=baseline,
                release=release,
                robust_z_threshold=robust_z_threshold,
                expected_release_hash=(
                    expected_release_hash if isinstance(expected_release_hash, str) else None
                ),
                expected_baseline_content_hash=expected_baseline_hash,
            )

            if not scored.is_anomaly:
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

            scorer_provenance = _scorer_provenance(
                snapshot=snapshot,
                baseline=baseline,
                scored=scored,
                release=release,
            )
            matches.append(
                OperatorMatch(
                    group_key=group_key,
                    matched_value=scored.detection_score,
                    observation_ids=[],
                    snapshot_ids=[snapshot.snapshot_id],
                    window_start=snapshot.window_start,
                    window_end=snapshot.window_end,
                    scorer_provenance=scorer_provenance,
                )
            )
        return matches


def _scorer_provenance(
    *,
    snapshot: Any,
    baseline: DetectionFeatureBaseline,
    scored: Any,
    release: AnomalyScorerRelease,
) -> dict[str, Any]:
    return {
        "model_release_id": release.release_id,
        "model_release_hash": release.release_hash,
        "calibration_version": release.calibration_version,
        "threshold_version": release.threshold_version,
        "detection_score": scored.detection_score,
        "feature_contract_version": snapshot.feature_contract_version,
        "snapshot_content_hash": snapshot.content_hash,
        "baseline_id": baseline.baseline_id,
        "baseline_content_hash": baseline.content_hash,
        "snapshot_revision": snapshot.revision,
        "contributing_features": [item.as_dict() for item in scored.contributing_features],
    }
