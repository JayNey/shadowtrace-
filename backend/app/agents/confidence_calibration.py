"""Confidence calibration helper (ISSUE-035)."""

from __future__ import annotations

DEFAULT_TEMPERATURE = 1.2


def calibrate_confidence(
    raw_confidence: float,
    *,
    temperature: float = DEFAULT_TEMPERATURE,
) -> float:
    """Calibrate model/rule confidence: ``min(1.0, raw / temperature)``.

    When ``temperature > 1``, calibrated confidence is strictly below the raw
    value (acceptance criterion for ISSUE-035).
    """
    if temperature <= 0:
        raise ValueError("temperature must be > 0")
    raw = max(0.0, min(1.0, float(raw_confidence)))
    return min(1.0, raw / float(temperature))
