"""Frozen anomaly scorer release artifacts (ISSUE-122 Phase A / #627)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import orjson

from app.models.feature_snapshot import FEATURE_CONTRACT_VERSION

SCORED_ACCOUNT_FEATURES = (
    "observation_count",
    "avg_detection_score",
    "unique_action_count",
)

MOCK_ACCOUNT_MAD_RELEASE_ID = "mock-account-mad-v1"
MOCK_ACCOUNT_CALIBRATION_VERSION = "mad_robust_z_v1"
MOCK_ACCOUNT_THRESHOLD_VERSION = "robust_z_3.5"
# Frozen for release hash audit. Phase A scoring uses MAD + quantile fallback;
# contamination is recorded in the artifact but not applied until Phase B ensemble.
MOCK_ACCOUNT_CONTAMINATION = 0.05
DEFAULT_ROBUST_Z_THRESHOLD = 3.5


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


@dataclass(frozen=True)
class AnomalyScorerRelease:
    """Immutable scorer release — hash must match for shadow execution."""

    release_id: str
    release_hash: str
    calibration_version: str
    threshold_version: str
    contamination: float
    feature_contract_version: str
    scored_features: tuple[str, ...]
    default_robust_z_threshold: float = DEFAULT_ROBUST_Z_THRESHOLD

    def verify_hash(self, expected_hash: str | None) -> None:
        if expected_hash is None:
            return
        if expected_hash != self.release_hash:
            from app.core.errors import ValidationError

            raise ValidationError(
                "anomaly scorer release hash mismatch",
                details={
                    "expected_release_hash": expected_hash,
                    "actual_release_hash": self.release_hash,
                    "release_id": self.release_id,
                    "category": "artifact_hash_mismatch",
                },
            )


def _build_release_hash(material: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(material)).hexdigest()


def build_mock_account_mad_release() -> AnomalyScorerRelease:
    material = {
        "release_id": MOCK_ACCOUNT_MAD_RELEASE_ID,
        "calibration_version": MOCK_ACCOUNT_CALIBRATION_VERSION,
        "threshold_version": MOCK_ACCOUNT_THRESHOLD_VERSION,
        "contamination": MOCK_ACCOUNT_CONTAMINATION,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "scored_features": list(SCORED_ACCOUNT_FEATURES),
        "default_robust_z_threshold": DEFAULT_ROBUST_Z_THRESHOLD,
        "algorithm": "mad_robust_z",
    }
    return AnomalyScorerRelease(
        release_id=MOCK_ACCOUNT_MAD_RELEASE_ID,
        release_hash=_build_release_hash(material),
        calibration_version=MOCK_ACCOUNT_CALIBRATION_VERSION,
        threshold_version=MOCK_ACCOUNT_THRESHOLD_VERSION,
        contamination=MOCK_ACCOUNT_CONTAMINATION,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        scored_features=SCORED_ACCOUNT_FEATURES,
    )


MOCK_ACCOUNT_MAD_RELEASE = build_mock_account_mad_release()
