"""Unit tests for robust statistics (ISSUE-122 / #627)."""

from __future__ import annotations

import pytest

from app.detection.scoring.robust_stats import (
    feature_anomaly_z,
    mad,
    median,
    quantile,
    robust_feature_stats,
    robust_z_score,
)


def test_median_odd_and_even() -> None:
    assert median([1.0, 3.0, 9.0]) == 3.0
    assert median([1.0, 2.0, 3.0, 4.0]) == 2.5


def test_mad_is_robust_to_outlier() -> None:
    values = [1.0, 1.0, 1.0, 1.0, 100.0]
    assert mad(values) == 0.0


def test_quantile_endpoints() -> None:
    values = [1.0, 2.0, 3.0, 4.0]
    assert quantile(values, 0.0) == 1.0
    assert quantile(values, 1.0) == 4.0
    assert quantile(values, 0.5) == 2.5


def test_robust_z_score_uses_mad_scale() -> None:
    z = robust_z_score(value=10.0, center=0.0, scale=1.0)
    assert z == pytest.approx(6.745)


def test_feature_anomaly_z_mad_degenerate_uses_quantile_fallback() -> None:
    stats = {"median": 2.0, "mad": 0.0, "p25": 2.0, "p75": 4.0, "p95": 5.0}
    z, method = feature_anomaly_z(value=8.0, stats=stats)
    assert z > 0.0
    assert method == "quantile_iqr"


def test_feature_anomaly_z_mad_degenerate_equal_value_is_zero() -> None:
    stats = {"median": 2.0, "mad": 0.0, "p25": 2.0, "p75": 2.0, "p95": 2.0}
    z, method = feature_anomaly_z(value=2.0, stats=stats)
    assert z == 0.0
    assert method == "mad_degenerate"


def test_robust_feature_stats_keys() -> None:
    stats = robust_feature_stats([1.0, 2.0, 3.0, 4.0, 100.0])
    assert set(stats) == {"median", "mad", "p25", "p75", "p95"}
