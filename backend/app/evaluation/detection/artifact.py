"""Detection evaluation artifact hashing (ISSUE-126 / #631 Phase A)."""

from __future__ import annotations

import hashlib
from typing import Any

import orjson

from app.models.detection_evaluation import DetectionEvaluationArtifact

_HASH_EXCLUDE = frozenset(
    {
        "evaluation_id",
        "started_at",
        "completed_at",
        "artifact_hash",
    }
)


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def _canonical_payload(artifact: DetectionEvaluationArtifact) -> dict[str, Any]:
    payload = artifact.model_dump(mode="json")
    canonical = {k: v for k, v in payload.items() if k not in _HASH_EXCLUDE}
    gate = canonical.get("gate")
    if isinstance(gate, dict):
        canonical["gate"] = {key: value for key, value in gate.items() if key != "manifest_path"}
    return canonical


def compute_detection_artifact_hash(artifact: DetectionEvaluationArtifact) -> str:
    """Hash reproducible detection artifact fields (excludes evaluation id and timestamps)."""
    return hashlib.sha256(_canonical_bytes(_canonical_payload(artifact))).hexdigest()


def finalize_detection_artifact(artifact: DetectionEvaluationArtifact) -> DetectionEvaluationArtifact:
    """Attach ``artifact_hash`` derived from reproducible fields."""
    digest = compute_detection_artifact_hash(artifact)
    return artifact.model_copy(update={"artifact_hash": digest})


__all__ = ["compute_detection_artifact_hash", "finalize_detection_artifact"]
