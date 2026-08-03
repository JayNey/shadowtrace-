"""Project approved shadow candidates into typed SourceAlert ingest envelopes (#629)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from app.models.detection_promotion import DerivedDetectionConnectorRecord
from app.models.detection_rule import CandidateDetection
from app.models.enums import SourceDisposition, SourceObjectKind
from app.models.source import SourceAlert, SourceReference


def build_promoted_source_object_id(candidate: CandidateDetection) -> str:
    material = (
        f"{candidate.candidate_detection_id}|{candidate.content_hash}|"
        f"{candidate.package_id}|v{candidate.package_version}"
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"pdet-{digest}"


def candidate_to_source_alert(
    candidate: CandidateDetection,
    *,
    derived_connector: DerivedDetectionConnectorRecord,
    promotion_id: str,
) -> SourceAlert:
    """Build a provisional SourceAlert for canonical ingest — never bypass EventService."""
    occurred_at = candidate.cutoff_at.astimezone(UTC)
    source_object_id = build_promoted_source_object_id(candidate)
    entity_type = candidate.group_key.get("entity_type")
    entity_id = candidate.group_key.get("entity_id")
    normalized = {
        "title": f"Detection promotion: {candidate.rule_id}",
        "description": (
            f"Promoted candidate {candidate.candidate_detection_id} "
            f"from package {candidate.package_id}@{candidate.package_version}"
        ),
        "alert_type": "detection_promotion",
        "severity": candidate.severity,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "detection_scope_id": candidate.detection_scope_id,
        "package_id": candidate.package_id,
        "package_version": candidate.package_version,
        "rule_id": candidate.rule_id,
        "candidate_detection_id": candidate.candidate_detection_id,
        "candidate_content_hash": candidate.content_hash,
        "promotion_id": promotion_id,
        "provisional": True,
        "shadow_origin": True,
        "matched_value": candidate.matched_value,
        "operator": candidate.operator.value,
    }
    raw_payload = {
        "promotion_id": promotion_id,
        "candidate_detection_id": candidate.candidate_detection_id,
        "candidate_content_hash": candidate.content_hash,
        "package_content_hash": candidate.provenance.model_dump(mode="json"),
        "group_key": candidate.group_key,
        "provenance": candidate.provenance.model_dump(mode="json"),
    }
    reference = SourceReference(
        source_kind=SourceObjectKind.ALERT,
        source_product=str(derived_connector.metadata.get("source_product", "mock_xdr")),
        source_tenant_id=candidate.source_tenant_id,
        connector_id=derived_connector.connector_id,
        source_object_type="detection_promotion",
        source_object_id=source_object_id,
        source_disposition=SourceDisposition.PENDING,
        source_updated_at=occurred_at,
        ingested_at=datetime.now(UTC),
        raw_payload_hash=hashlib.sha256(
            f"{source_object_id}|{candidate.content_hash}".encode()
        ).hexdigest(),
    )
    return SourceAlert(
        reference=reference,
        normalized=normalized,
        raw_payload=raw_payload,
    )
