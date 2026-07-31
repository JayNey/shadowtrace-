"""Evaluation artifact hashing helpers (ISSUE-105 / #608)."""

from __future__ import annotations

import hashlib
from typing import Any

import orjson

from app.models.evaluation_run import EvaluationRunArtifact

_HASH_EXCLUDE = frozenset(
    {
        "run_id",
        "started_at",
        "completed_at",
        "artifact_hash",
    }
)


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def compute_artifact_hash(artifact: EvaluationRunArtifact) -> str:
    """Hash reproducible artifact fields (excludes run id and timestamps)."""
    payload = artifact.model_dump(mode="json")
    canonical = {k: v for k, v in payload.items() if k not in _HASH_EXCLUDE}
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def finalize_artifact(artifact: EvaluationRunArtifact) -> EvaluationRunArtifact:
    """Attach ``artifact_hash`` derived from reproducible fields."""
    digest = compute_artifact_hash(artifact)
    return artifact.model_copy(update={"artifact_hash": digest})


__all__ = ["compute_artifact_hash", "finalize_artifact"]
