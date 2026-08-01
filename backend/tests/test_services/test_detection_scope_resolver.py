"""Unit tests for canonical Detection Scope resolver (ISSUE-120 Phase 0)."""

from __future__ import annotations

import pytest

from app.core.errors import ValidationError
from app.models.detection_scope import (
    ConnectorScopeRole,
    DerivedDetectionConnectorBinding,
    DetectionScopeIdentity,
    UpstreamConnectorMember,
)
from app.services.detection_scope_resolver import (
    DetectionScopeResolver,
    build_detection_scope_id,
    build_detection_scope_revision,
    compute_connector_set_hash,
    compute_scope_content_hash,
    normalize_upstream_connector_set,
)


def _identity(
    *,
    tenant: str = "tenant-a",
    product: str = "mock_xdr",
    instance: str = "inst-primary",
    environment: str | None = "prod",
    region: str | None = "cn-east",
) -> DetectionScopeIdentity:
    return DetectionScopeIdentity(
        source_tenant_id=tenant,
        source_product=product,
        integration_instance_id=instance,
        environment=environment,
        region=region,
    )


def _upstream(connector_id: str, *, product: str = "mock_xdr") -> UpstreamConnectorMember:
    return UpstreamConnectorMember(connector_id=connector_id, source_product=product)


def test_detection_scope_id_is_deterministic_for_same_inputs() -> None:
    identity = _identity()
    first = build_detection_scope_id(identity, connector_set_version=1)
    second = build_detection_scope_id(identity, connector_set_version=1)
    assert first == second
    assert first.startswith("dscope-")


def test_detection_scope_id_changes_with_connector_set_version() -> None:
    identity = _identity()
    v1 = build_detection_scope_id(identity, connector_set_version=1)
    v2 = build_detection_scope_id(identity, connector_set_version=2)
    assert v1 != v2


def test_detection_scope_id_isolated_across_tenants() -> None:
    left = build_detection_scope_id(_identity(tenant="tenant-a"), connector_set_version=1)
    right = build_detection_scope_id(_identity(tenant="tenant-b"), connector_set_version=1)
    assert left != right


def test_upstream_connector_set_is_canonical_sorted() -> None:
    normalized = normalize_upstream_connector_set(
        connector_set_version=1,
        upstream_connectors=[
            _upstream("conn-b"),
            _upstream("conn-a"),
        ],
    )
    assert [item.connector_id for item in normalized.upstream_connectors] == ["conn-a", "conn-b"]


def test_upstream_connector_set_rejects_duplicates() -> None:
    with pytest.raises(ValidationError, match="duplicate upstream connector"):
        normalize_upstream_connector_set(
            connector_set_version=1,
            upstream_connectors=[
                _upstream("conn-a"),
                _upstream("conn-b"),
                _upstream("conn-b"),
            ],
        )


def test_derived_connector_rejected_from_upstream_set() -> None:
    from pydantic import ValidationError as PydanticValidationError

    with pytest.raises(PydanticValidationError, match="upstream connector set members must have role=upstream_source"):
        UpstreamConnectorMember(
            connector_id="derived-1",
            source_product="mock_xdr",
            role=ConnectorScopeRole.DERIVED_DETECTION,
        )


def test_derived_binding_does_not_change_scope_identity() -> None:
    identity = _identity()
    revision = build_detection_scope_revision(
        identity=identity,
        connector_set=normalize_upstream_connector_set(
            connector_set_version=1,
            upstream_connectors=[_upstream("conn-log")],
        ),
    )
    binding = DerivedDetectionConnectorBinding(
        connector_id="derived-det-1",
        detection_scope_id=revision.detection_scope_id,
    )
    DetectionScopeResolver.assert_derived_connector_excluded_from_set(
        binding.connector_id,
        revision.connector_set,
    )
    with pytest.raises(ValidationError, match="derived detection connector cannot appear"):
        DetectionScopeResolver.assert_derived_connector_excluded_from_set(
            "conn-log",
            revision.connector_set,
        )


def test_content_hash_stable_for_same_cutoff_inputs() -> None:
    identity = _identity()
    connector_set = normalize_upstream_connector_set(
        connector_set_version=1,
        upstream_connectors=[_upstream("conn-log"), _upstream("conn-edr")],
    )
    first = build_detection_scope_revision(identity=identity, connector_set=connector_set)
    second = build_detection_scope_revision(identity=identity, connector_set=connector_set)
    assert first.content_hash == second.content_hash
    assert first.detection_scope_id == second.detection_scope_id
    assert compute_connector_set_hash(first.connector_set) == compute_connector_set_hash(
        second.connector_set
    )


def test_content_hash_changes_when_connector_membership_changes() -> None:
    identity = _identity()
    first = build_detection_scope_revision(
        identity=identity,
        connector_set=normalize_upstream_connector_set(
            connector_set_version=1,
            upstream_connectors=[_upstream("conn-log")],
        ),
    )
    second = build_detection_scope_revision(
        identity=identity,
        connector_set=normalize_upstream_connector_set(
            connector_set_version=2,
            upstream_connectors=[_upstream("conn-log"), _upstream("conn-edr")],
        ),
        revision=2,
    )
    assert first.content_hash != second.content_hash
    assert first.detection_scope_id != second.detection_scope_id


def test_scope_content_hash_ignores_runtime_metadata() -> None:
    identity = _identity()
    connector_set = normalize_upstream_connector_set(
        connector_set_version=1,
        upstream_connectors=[_upstream("conn-log")],
    )
    base = build_detection_scope_revision(identity=identity, connector_set=connector_set)
    payload = {
        "detection_scope_id": base.detection_scope_id,
        "identity": identity.model_dump(mode="json"),
        "connector_set": connector_set.model_dump(mode="json"),
        "lifecycle_state": base.lifecycle_state.value,
        "revision": base.revision,
        "schema_version": base.schema_version,
        "scope_revision_id": "different-runtime-id",
        "created_at": "2026-08-01T00:00:00+00:00",
    }
    assert compute_scope_content_hash(payload) == base.content_hash
