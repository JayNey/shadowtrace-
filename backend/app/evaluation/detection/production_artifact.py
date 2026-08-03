"""Post-promotion comparison artifact hashing (ISSUE-126 / #631 Phase B)."""

from __future__ import annotations

import hashlib
from typing import Any

import orjson

from app.models.detection_production_comparison import DetectionProductionComparisonArtifact

_HASH_EXCLUDE = frozenset(
    {
        "comparison_id",
        "started_at",
        "completed_at",
        "artifact_hash",
    }
)


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def compute_production_comparison_artifact_hash(
    artifact: DetectionProductionComparisonArtifact,
) -> str:
    payload = artifact.model_dump(mode="json")
    canonical = {k: v for k, v in payload.items() if k not in _HASH_EXCLUDE}
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def finalize_production_comparison_artifact(
    artifact: DetectionProductionComparisonArtifact,
) -> DetectionProductionComparisonArtifact:
    digest = compute_production_comparison_artifact_hash(artifact)
    return artifact.model_copy(update={"artifact_hash": digest})


__all__ = [
    "compute_production_comparison_artifact_hash",
    "finalize_production_comparison_artifact",
]
