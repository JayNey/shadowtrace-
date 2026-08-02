"""Robust statistical helpers for shadow anomaly scoring (ISSUE-122 / #627)."""

from __future__ import annotations

import math


def median(values: list[float]) -> float:
    if not values:
        raise ValueError("median requires at least one value")
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def mad(values: list[float], *, center: float | None = None) -> float:
    """Median absolute deviation."""
    if not values:
        raise ValueError("mad requires at least one value")
    med = center if center is not None else median(values)
    deviations = [abs(value - med) for value in values]
    return median(deviations)


def quantile(values: list[float], q: float) -> float:
    if not values:
        raise ValueError("quantile requires at least one value")
    if q <= 0:
        return min(values)
    if q >= 1:
        return max(values)
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lower = math.floor(pos)
    upper = math.ceil(pos)
    if lower == upper:
        return ordered[int(pos)]
    weight = pos - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def robust_z_score(*, value: float, center: float, scale: float) -> float:
    """Modified z-score using MAD; 0.6745 scales MAD to std-equivalent units."""
    if scale <= 0:
        return 0.0
    return 0.6745 * (value - center) / scale


def robust_feature_stats(values: list[float]) -> dict[str, float]:
    med = median(values)
    deviation = mad(values, center=med)
    return {
        "median": round(med, 4),
        "mad": round(deviation, 4),
        "p25": round(quantile(values, 0.25), 4),
        "p75": round(quantile(values, 0.75), 4),
        "p95": round(quantile(values, 0.95), 4),
    }
