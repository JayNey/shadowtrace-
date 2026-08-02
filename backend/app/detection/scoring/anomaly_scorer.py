"""Robust statistical anomaly scorer over FeatureSnapshot + baseline (#625 / ISSUE-122)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.core.errors import ValidationError
from app.detection.scoring.release import AnomalyScorerRelease
from app.detection.scoring.robust_stats import robust_z_score
from app.models.feature_snapshot import (
    DetectionBaselineStatus,
    DetectionFeatureBaseline,
    FeatureSnapshot,
    FeatureSnapshotStatus,
)

MAX_FEATURE_VALUE = 1_000_000.0
MAX_CONTRIBUTING_FEATURES = 8


class ScorerErrorCategory(StrEnum):
    INSUFFICIENT_HISTORY = "insufficient_history"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"
    ARTIFACT_HASH_MISMATCH = "artifact_hash_mismatch"
    POISONED_INPUT = "poisoned_input"
    BASELINE_HASH_MISMATCH = "baseline_hash_mismatch"


@dataclass(frozen=True)
class ContributingFeature:
    feature_name: str
    value: float
    baseline_median: float
    baseline_mad: float
    robust_z: float
    weight: float

    def as_dict(self) -> dict[str, float | str]:
        return {
            "feature_name": self.feature_name,
            "value": round(self.value, 4),
            "baseline_median": round(self.baseline_median, 4),
            "baseline_mad": round(self.baseline_mad, 4),
            "robust_z": round(self.robust_z, 4),
            "weight": round(self.weight, 4),
        }


@dataclass(frozen=True)
class AnomalyScoreResult:
    detection_score: float
    max_robust_z: float
    is_anomaly: bool
    contributing_features: tuple[ContributingFeature, ...]
    release: AnomalyScorerRelease


def _coerce_feature_value(raw: Any, *, feature_name: str) -> float:
    if raw is None:
        raise ValidationError(
            f"missing feature value: {feature_name}",
            details={"feature_name": feature_name},
        )
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            f"non-numeric feature value: {feature_name}",
            details={"feature_name": feature_name},
        ) from exc
    if not math_isfinite(value):
        raise ValidationError(
            "poisoned feature value",
            details={"feature_name": feature_name, "category": ScorerErrorCategory.POISONED_INPUT},
        )
    if abs(value) > MAX_FEATURE_VALUE:
        raise ValidationError(
            "feature value exceeds resource limit",
            details={"feature_name": feature_name, "category": ScorerErrorCategory.POISONED_INPUT},
        )
    return value


def math_isfinite(value: float) -> bool:
    return value == value and value not in (float("inf"), float("-inf"))


def _robust_stats_for_feature(
    baseline: DetectionFeatureBaseline,
    feature_name: str,
) -> dict[str, float] | None:
    robust_root = baseline.stats.get("robust")
    if isinstance(robust_root, dict):
        feature_stats = robust_root.get(feature_name)
        if isinstance(feature_stats, dict):
            return {key: float(value) for key, value in feature_stats.items()}
    legacy_median = baseline.stats.get(f"median_{feature_name}")
    legacy_mad = baseline.stats.get(f"mad_{feature_name}")
    if isinstance(legacy_median, (int, float)) and isinstance(legacy_mad, (int, float)):
        return {"median": float(legacy_median), "mad": float(legacy_mad)}
    return None


def calibrate_detection_score(max_robust_z: float, *, threshold: float) -> float:
    """Map robust z to 0–100 detection score — not severity/risk."""
    if threshold <= 0:
        return 0.0
    normalized = max(0.0, min(1.0, max_robust_z / threshold))
    return round(normalized * 100.0, 2)


def score_snapshot(
    *,
    snapshot: FeatureSnapshot,
    baseline: DetectionFeatureBaseline,
    release: AnomalyScorerRelease,
    robust_z_threshold: float,
    expected_release_hash: str | None = None,
    expected_baseline_content_hash: str | None = None,
) -> AnomalyScoreResult:
    """Score one entity snapshot against a #625 baseline — deterministic, fail-closed."""
    release.verify_hash(expected_release_hash)

    if snapshot.feature_contract_version != release.feature_contract_version:
        raise ValidationError(
            "feature contract version mismatch",
            details={
                "snapshot_version": snapshot.feature_contract_version,
                "release_version": release.feature_contract_version,
            },
        )

    if expected_baseline_content_hash is not None and (
        expected_baseline_content_hash != baseline.content_hash
    ):
        raise ValidationError(
            "baseline content hash mismatch",
            details={
                "expected_baseline_content_hash": expected_baseline_content_hash,
                "actual_baseline_content_hash": baseline.content_hash,
                "category": ScorerErrorCategory.BASELINE_HASH_MISMATCH,
            },
        )

    if snapshot.status is FeatureSnapshotStatus.INSUFFICIENT_HISTORY:
        raise ValidationError(
            "snapshot insufficient history — cannot score",
            details={"category": ScorerErrorCategory.INSUFFICIENT_HISTORY},
        )
    if snapshot.status is FeatureSnapshotStatus.INSUFFICIENT_COVERAGE:
        raise ValidationError(
            "snapshot insufficient coverage — cannot score",
            details={"category": ScorerErrorCategory.INSUFFICIENT_COVERAGE},
        )
    if snapshot.status is not FeatureSnapshotStatus.READY:
        raise ValidationError(
            "snapshot not ready — cannot score",
            details={"status": snapshot.status.value},
        )

    if baseline.status is DetectionBaselineStatus.INSUFFICIENT_HISTORY:
        raise ValidationError(
            "baseline insufficient history — cannot score",
            details={"category": ScorerErrorCategory.INSUFFICIENT_HISTORY},
        )
    if baseline.status is DetectionBaselineStatus.INSUFFICIENT_COVERAGE:
        raise ValidationError(
            "baseline insufficient coverage — cannot score",
            details={"category": ScorerErrorCategory.INSUFFICIENT_COVERAGE},
        )
    if baseline.status is not DetectionBaselineStatus.READY:
        raise ValidationError(
            "baseline not ready — cannot score",
            details={"status": baseline.status.value},
        )

    if (
        snapshot.source_tenant_id != baseline.source_tenant_id
        or snapshot.detection_scope_id != baseline.detection_scope_id
        or snapshot.entity_type != baseline.entity_type
        or snapshot.entity_id != baseline.entity_id
    ):
        raise ValidationError(
            "snapshot/baseline tenant or entity binding mismatch",
            details={
                "snapshot_id": snapshot.snapshot_id,
                "baseline_id": baseline.baseline_id,
            },
        )

    contributing: list[ContributingFeature] = []
    max_z = 0.0
    for feature_name in release.scored_features:
        stats = _robust_stats_for_feature(baseline, feature_name)
        if stats is None:
            continue
        center = stats.get("median")
        scale = stats.get("mad")
        if center is None or scale is None:
            continue
        raw_value = snapshot.features.get(feature_name)
        value = _coerce_feature_value(raw_value, feature_name=feature_name)
        z = abs(robust_z_score(value=value, center=center, scale=scale))
        weight = 1.0 / len(release.scored_features)
        contributing.append(
            ContributingFeature(
                feature_name=feature_name,
                value=value,
                baseline_median=center,
                baseline_mad=scale,
                robust_z=z,
                weight=weight,
            )
        )
        max_z = max(max_z, z)

    if not contributing:
        raise ValidationError(
            "baseline missing robust stats for scorer release",
            details={"category": ScorerErrorCategory.INSUFFICIENT_COVERAGE},
        )

    contributing_sorted = tuple(
        sorted(contributing, key=lambda item: item.robust_z, reverse=True)[
            :MAX_CONTRIBUTING_FEATURES
        ]
    )
    detection_score = calibrate_detection_score(max_z, threshold=robust_z_threshold)
    return AnomalyScoreResult(
        detection_score=detection_score,
        max_robust_z=max_z,
        is_anomaly=max_z >= robust_z_threshold,
        contributing_features=contributing_sorted,
        release=release,
    )
