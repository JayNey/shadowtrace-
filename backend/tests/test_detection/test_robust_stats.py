"""Unit tests for robust statistics (ISSUE-122 / #627)."""

from __future__ import annotations

import pytest

from app.detection.scoring.robust_stats import (
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


def test_robust_feature_stats_keys() -> None:
    stats = robust_feature_stats([1.0, 2.0, 3.0, 4.0, 100.0])
    assert set(stats) == {"median", "mad", "p25", "p75", "p95"}
