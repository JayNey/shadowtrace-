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


_MAD_SCALE_FACTOR = 0.6745
_MIN_QUANTILE_SCALE = 1e-6


def robust_z_score(*, value: float, center: float, scale: float) -> float:
    """Modified z-score using MAD; 0.6745 scales MAD to std-equivalent units."""
    if scale <= 0:
        return 0.0
    return _MAD_SCALE_FACTOR * (value - center) / scale


def feature_anomaly_z(*, value: float, stats: dict[str, float]) -> tuple[float, str]:
    """Score one feature: MAD robust-z, quantile IQR fallback when MAD is degenerate."""
    center = stats["median"]
    scale = stats.get("mad", 0.0)
    if scale > 0:
        return abs(robust_z_score(value=value, center=center, scale=scale)), "mad"
    if value == center:
        return 0.0, "mad_degenerate"
    p25 = stats.get("p25")
    p75 = stats.get("p75")
    p95 = stats.get("p95")
    if p25 is not None and p75 is not None:
        half_iqr = (p75 - p25) / 2.0
        if half_iqr > _MIN_QUANTILE_SCALE:
            if value > p75:
                z = _MAD_SCALE_FACTOR * (value - p75) / half_iqr + _MAD_SCALE_FACTOR
            elif value < p25:
                z = _MAD_SCALE_FACTOR * (p25 - value) / half_iqr + _MAD_SCALE_FACTOR
            else:
                z = _MAD_SCALE_FACTOR * abs(value - center) / half_iqr
            return z, "quantile_iqr"
    if p95 is not None and value > p95:
        tail_scale = max(p95 - center, _MIN_QUANTILE_SCALE)
        return abs(_MAD_SCALE_FACTOR * (value - center) / tail_scale), "quantile_p95"
    if p25 is not None and value < p25:
        tail_scale = max(center - p25, _MIN_QUANTILE_SCALE)
        return abs(_MAD_SCALE_FACTOR * (center - value) / tail_scale), "quantile_p25"
    return abs(_MAD_SCALE_FACTOR * (value - center) / _MIN_QUANTILE_SCALE), "quantile_epsilon"


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
