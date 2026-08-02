"""Versioned identity/exfiltration sequence rule material (ISSUE-123 Phase A / #628)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, cast

import orjson

IDENTITY_EXFIL_SEQUENCE_ID = "identity-exfil-v1"
GEO_SENSITIVE_SEQUENCE_ID = "geo-sensitive-v1"

# Upper bound for inter-step gap; runtime window_kind still caps observable span.
DEFAULT_MAX_STEP_GAP_SECONDS = 86_400


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


@dataclass(frozen=True)
class SequenceRelease:
    """Immutable ordered-step package — hash must match for shadow execution."""

    sequence_id: str
    sequence_hash: str
    sequence_steps: tuple[dict[str, object], ...]
    max_step_gap_seconds: int
    description: str

    def as_match_criteria(self) -> dict[str, Any]:
        return {
            "sequence_id": self.sequence_id,
            "sequence_hash": self.sequence_hash,
            "sequence_steps": [dict(step) for step in self.sequence_steps],
            "max_step_gap_seconds": self.max_step_gap_seconds,
        }


def sequence_match_threshold(release: SequenceRelease) -> float:
    """All-or-nothing matcher requires threshold == frozen step count."""
    return float(len(release.sequence_steps))


def _build_sequence_hash(material: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(material)).hexdigest()


def build_identity_exfil_sequence_v1() -> SequenceRelease:
    steps: tuple[dict[str, object], ...] = (
        {"action": "login", "category": "identity"},
        {"action": "privilege_change", "category": "identity"},
        {"action": "bulk_read", "category": "data_access"},
        {"action": "egress", "category": "data_exfiltration"},
    )
    description = "abnormal login → privilege change → bulk read → egress"
    material: dict[str, Any] = {
        "sequence_id": IDENTITY_EXFIL_SEQUENCE_ID,
        "sequence_steps": list(steps),
        "max_step_gap_seconds": DEFAULT_MAX_STEP_GAP_SECONDS,
        "description": description,
    }
    return SequenceRelease(
        sequence_id=IDENTITY_EXFIL_SEQUENCE_ID,
        sequence_hash=_build_sequence_hash(material),
        sequence_steps=steps,
        max_step_gap_seconds=DEFAULT_MAX_STEP_GAP_SECONDS,
        description=description,
    )


def build_geo_sensitive_sequence_v1() -> SequenceRelease:
    steps = cast(
        tuple[dict[str, object], ...],
        (
            {"action": "anomalous_login", "category": "identity"},
            {"action": "sensitive_access", "category": "data_access"},
        ),
    )
    description = "new device/geo anomaly → sensitive access"
    material: dict[str, Any] = {
        "sequence_id": GEO_SENSITIVE_SEQUENCE_ID,
        "sequence_steps": list(steps),
        "max_step_gap_seconds": DEFAULT_MAX_STEP_GAP_SECONDS,
        "description": description,
    }
    return SequenceRelease(
        sequence_id=GEO_SENSITIVE_SEQUENCE_ID,
        sequence_hash=_build_sequence_hash(material),
        sequence_steps=steps,
        max_step_gap_seconds=DEFAULT_MAX_STEP_GAP_SECONDS,
        description=description,
    )


IDENTITY_EXFIL_SEQUENCE_V1 = build_identity_exfil_sequence_v1()
GEO_SENSITIVE_SEQUENCE_V1 = build_geo_sensitive_sequence_v1()
