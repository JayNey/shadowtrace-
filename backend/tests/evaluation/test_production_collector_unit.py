"""Unit tests for production_collector helpers (ISSUE-164 / #683)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.evaluation.detection.production_collector import _should_prefer_promotion_record
from app.models.detection_promotion import (
    DetectionPromotionRecord,
    DetectionPromotionStatus,
)

_BASE = dict(
    promotion_id="promo-1",
    tenant_id="tenant-a",
    promotion_key="key-1",
    status=DetectionPromotionStatus.COMPLETED,
    decision_id="dec-1",
    candidate_detection_id="cand-1",
    candidate_content_hash="a" * 64,
    package_id="pkg-1",
    package_version=1,
    package_content_hash="c" * 64,
    detection_scope_id="scope-1",
    scope_revision_id="rev-1",
    derived_connector_id="conn-1",
    source_record_id="src-1",
    event_id="evt-1",
    link_revision=1,
    reason_codes=[],
    reason_message="",
)


def _record(*, updated_at: datetime | None) -> DetectionPromotionRecord:
    return DetectionPromotionRecord(**_BASE, updated_at=updated_at)


def test_should_prefer_promotion_record_when_no_existing() -> None:
    assert _should_prefer_promotion_record(None, _record(updated_at=datetime.now(UTC)))


def test_should_prefer_promotion_record_both_updated_at_none_keeps_existing() -> None:
    existing = _record(updated_at=None)
    candidate = _record(updated_at=None)
    assert not _should_prefer_promotion_record(existing, candidate)


def test_should_prefer_promotion_record_candidate_none_updated_at() -> None:
    existing = _record(updated_at=datetime.now(UTC))
    candidate = _record(updated_at=None)
    assert not _should_prefer_promotion_record(existing, candidate)


def test_should_prefer_promotion_record_existing_none_updated_at() -> None:
    existing = _record(updated_at=None)
    candidate = _record(updated_at=datetime(2026, 1, 2, tzinfo=UTC))
    assert _should_prefer_promotion_record(existing, candidate)


def test_should_prefer_promotion_record_newer_candidate() -> None:
    existing = _record(updated_at=datetime(2026, 1, 1, tzinfo=UTC))
    candidate = _record(updated_at=datetime(2026, 1, 2, tzinfo=UTC))
    assert _should_prefer_promotion_record(existing, candidate)


def test_should_prefer_promotion_record_older_candidate() -> None:
    existing = _record(updated_at=datetime(2026, 1, 2, tzinfo=UTC))
    candidate = _record(updated_at=datetime(2026, 1, 1, tzinfo=UTC))
    assert not _should_prefer_promotion_record(existing, candidate)
