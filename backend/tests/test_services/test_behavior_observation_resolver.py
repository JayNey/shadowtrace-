"""Unit tests for BehaviorObservation resolver (ISSUE-119 / #624)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.enums import SourceObjectKind
from app.services.behavior_observation_resolver import (
    build_behavior_observation,
    build_observation_id,
    build_observation_idempotency_key,
    compute_observation_content_hash,
)


def _source_row(**overrides: object) -> orm.SourceObject:
    base = {
        "source_record_id": "src-test123456",
        "source_product": "mock_xdr",
        "source_tenant_id": "tenant-a",
        "connector_id": "conn-log",
        "source_kind": SourceObjectKind.LOG.value,
        "source_object_id": "log-001",
        "source_object_type": "edr",
        "source_status_raw": "indexed",
        "source_disposition": "unknown",
        "schema_version": "1",
        "ingested_at": datetime(2026, 8, 1, tzinfo=UTC),
        "raw_payload_hash": "abc123",
        "normalized": {
            "channel": "endpoint",
            "category": "process_create",
            "action": "create_process",
            "src_ip": "10.0.0.5",
            "detection_score": 72,
            "risk_score": 99,
            "logged_at": "2026-08-01T00:00:00+00:00",
        },
        "raw_payload": {"secret": "must-not-copy"},
        "current_source_status_raw": "indexed",
        "current_source_disposition": "unknown",
        "current_state_version": 1,
        "source_updated_at": datetime(2026, 8, 1, tzinfo=UTC),
    }
    base.update(overrides)
    return orm.SourceObject(**base)


def test_observation_id_is_deterministic() -> None:
    key = build_observation_idempotency_key(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-abc",
        source_kind="log",
        source_object_id="log-001",
        source_revision=1,
    )
    first = build_observation_id(idempotency_key=key)
    second = build_observation_id(idempotency_key=key)
    assert first == second
    assert first.startswith("bobs-")


def test_build_behavior_observation_ignores_risk_score() -> None:
    observation = build_behavior_observation(
        row=_source_row(),
        detection_scope_id="dscope-test",
    )
    assert observation.detection_score == 72.0
    assert "risk_score" not in observation.normalized_attributes
    assert "secret" not in observation.normalized_attributes
    assert any(ref.entity_id == "10.0.0.5" for ref in observation.entity_refs)
    assert observation.provenance.source_record_id == "src-test123456"
    assert observation.provenance.raw_payload_hash == "abc123"


def test_content_hash_stable_for_same_inputs() -> None:
    first = build_behavior_observation(row=_source_row(), detection_scope_id="dscope-test")
    second = build_behavior_observation(row=_source_row(), detection_scope_id="dscope-test")
    assert first.content_hash == second.content_hash
    assert first.observation_id == second.observation_id


def test_content_hash_changes_with_source_revision() -> None:
    first = build_behavior_observation(row=_source_row(), detection_scope_id="dscope-test")
    second = build_behavior_observation(
        row=_source_row(current_state_version=2),
        detection_scope_id="dscope-test",
    )
    assert first.content_hash != second.content_hash
    assert first.observation_id != second.observation_id


def test_connector_kind_rejected() -> None:
    with pytest.raises(ValidationError, match="connector source objects"):
        build_behavior_observation(
            row=_source_row(source_kind=SourceObjectKind.CONNECTOR.value),
            detection_scope_id="dscope-test",
        )


def test_compute_observation_content_hash_ignores_runtime_metadata() -> None:
    observation = build_behavior_observation(row=_source_row(), detection_scope_id="dscope-test")
    payload = {
        "observation_id": observation.observation_id,
        "source_tenant_id": observation.source_tenant_id,
        "detection_scope_id": observation.detection_scope_id,
        "source_ref": observation.source_ref.model_dump(mode="json"),
        "observed_at": observation.observed_at.isoformat(),
        "ingested_at": observation.ingested_at.isoformat(),
        "entity_refs": [item.model_dump(mode="json") for item in observation.entity_refs],
        "action": observation.action,
        "category": observation.category,
        "normalized_attributes": observation.normalized_attributes,
        "detection_score": observation.detection_score,
        "schema_version": observation.schema_version,
        "projection_schema_version": observation.projection_schema_version,
        "provenance": observation.provenance.model_dump(mode="json"),
        "supersedes_observation_id": observation.supersedes_observation_id,
        "created_at": "2026-08-01T01:00:00+00:00",
        "observation_hash": "different",
    }
    assert compute_observation_content_hash(payload) == observation.content_hash
