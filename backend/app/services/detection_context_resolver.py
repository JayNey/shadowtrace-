"""Pure detection context snapshot assembly (ISSUE-127 / #633)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

import orjson

from app.models.detection_context_snapshot import (
    DETECTION_CONTEXT_SNAPSHOT_SCHEMA_VERSION,
    DetectionContextAttackRef,
    DetectionContextCoverageSummary,
    DetectionContextEvaluationRefs,
    DetectionContextEvidenceRef,
    DetectionContextEvidenceRefKind,
    DetectionContextGovernanceRefs,
    DetectionContextReleaseRefs,
    DetectionContextScoreSummary,
    DetectionContextSnapshot,
    DetectionContextSnapshotRef,
)
from app.models.detection_governance import DetectionGovernanceDecision
from app.models.detection_promotion import DetectionPromotionRecord
from app.models.detection_rule import CandidateDetection, DetectionRuleDefinition
from app.models.feature_snapshot import FeatureSnapshot, FeatureSnapshotStatus

_HASH_EXCLUDE = frozenset(
    {
        "snapshot_id",
        "content_hash",
        "idempotency_key",
        "created_at",
        "supersedes_snapshot_id",
    }
)

_TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def build_snapshot_id(*, tenant_id: str, event_id: str, revision: int, content_hash: str) -> str:
    material = f"{tenant_id}|{event_id}|{revision}|{content_hash}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    return f"dctx-{digest}"


def build_idempotency_key(
    *,
    tenant_id: str,
    event_id: str,
    promotion_id: str,
    promotion_link_revision: int,
    source_revision_material: str,
) -> str:
    return (
        f"{tenant_id}|{event_id}|{promotion_id}|{promotion_link_revision}|"
        f"{source_revision_material}"
    )


def compute_snapshot_content_hash(payload: dict[str, Any]) -> str:
    canonical = {k: v for k, v in payload.items() if k not in _HASH_EXCLUDE}
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def extract_attack_refs_from_rule(
    rule: DetectionRuleDefinition | None,
) -> list[DetectionContextAttackRef]:
    if rule is None:
        return []
    criteria = rule.match_criteria or {}
    refs: list[DetectionContextAttackRef] = []
    for key in ("attack_technique_ids", "mitre_technique_ids", "expected_attack_techniques"):
        raw = criteria.get(key)
        if raw is None:
            continue
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            if isinstance(item, str) and _TECHNIQUE_ID_PATTERN.match(item.strip()):
                refs.append(
                    DetectionContextAttackRef(
                        technique_id=item.strip().upper(),
                        source="rule",
                    )
                )
            elif isinstance(item, dict):
                technique_id = str(item.get("technique_id") or item.get("id") or "").strip()
                if technique_id and _TECHNIQUE_ID_PATTERN.match(technique_id):
                    name = item.get("technique_name") or item.get("name")
                    refs.append(
                        DetectionContextAttackRef(
                            technique_id=technique_id.upper(),
                            technique_name=str(name)[:128] if name else None,
                            source="rule",
                        )
                    )
    deduped: dict[str, DetectionContextAttackRef] = {}
    for ref in refs:
        deduped[ref.technique_id] = ref
    return list(deduped.values())


def build_ordered_evidence_refs(
    *,
    promotion: DetectionPromotionRecord,
    candidate: CandidateDetection,
) -> list[DetectionContextEvidenceRef]:
    refs: list[DetectionContextEvidenceRef] = []
    ordinal = 0
    refs.append(
        DetectionContextEvidenceRef(
            ref_kind=DetectionContextEvidenceRefKind.PROMOTION,
            ref_id=promotion.promotion_id,
            ordinal=ordinal,
        )
    )
    ordinal += 1
    if promotion.source_record_id:
        refs.append(
            DetectionContextEvidenceRef(
                ref_kind=DetectionContextEvidenceRefKind.SOURCE_RECORD,
                ref_id=promotion.source_record_id,
                ordinal=ordinal,
            )
        )
        ordinal += 1
    observation_ids = list(candidate.provenance.ordered_observation_ids or [])
    if not observation_ids:
        observation_ids = list(candidate.provenance.observation_ids or [])
    for observation_id in observation_ids:
        refs.append(
            DetectionContextEvidenceRef(
                ref_kind=DetectionContextEvidenceRefKind.BEHAVIOR_OBSERVATION,
                ref_id=observation_id,
                ordinal=ordinal,
            )
        )
        ordinal += 1
    for snapshot_id in candidate.provenance.snapshot_ids or []:
        refs.append(
            DetectionContextEvidenceRef(
                ref_kind=DetectionContextEvidenceRefKind.FEATURE_SNAPSHOT,
                ref_id=snapshot_id,
                ordinal=ordinal,
            )
        )
        ordinal += 1
    return refs


def summarize_feature_coverage(
    snapshots: list[FeatureSnapshot],
) -> DetectionContextCoverageSummary:
    ready = 0
    insufficient_history = 0
    insufficient_coverage = 0
    for snapshot in snapshots:
        if snapshot.status is FeatureSnapshotStatus.READY:
            ready += 1
        elif snapshot.status is FeatureSnapshotStatus.INSUFFICIENT_HISTORY:
            insufficient_history += 1
        elif snapshot.status is FeatureSnapshotStatus.INSUFFICIENT_COVERAGE:
            insufficient_coverage += 1
    return DetectionContextCoverageSummary(
        feature_snapshot_count=len(snapshots),
        ready_snapshot_count=ready,
        insufficient_history_count=insufficient_history,
        insufficient_coverage_count=insufficient_coverage,
    )


def build_detection_context_snapshot(
    *,
    promotion: DetectionPromotionRecord,
    candidate: CandidateDetection,
    decision: DetectionGovernanceDecision,
    event_revision: int,
    rule: DetectionRuleDefinition | None,
    feature_snapshots: list[FeatureSnapshot],
    revision: int = 1,
    supersedes_snapshot_id: str | None = None,
    projection_errors: list[str] | None = None,
) -> DetectionContextSnapshot:
    bound = decision.candidate_binding
    refs = bound.candidate_refs
    release_refs = DetectionContextReleaseRefs(
        candidate_detection_id=candidate.candidate_detection_id,
        candidate_content_hash=candidate.content_hash,
        package_id=candidate.package_id,
        package_version=candidate.package_version,
        package_content_hash=refs.package_content_hash,
        rule_id=candidate.rule_id,
        rule_version=candidate.rule_version,
        feature_contract_version=refs.feature_contract_version,
        detection_scope_id=candidate.detection_scope_id,
        scope_revision_id=bound.scope_revision_id,
        model_release_id=refs.model_release_id,
        model_release_hash=refs.model_release_hash,
    )
    governance_refs = DetectionContextGovernanceRefs(
        decision_id=decision.decision_id,
        binding_hash=decision.binding_hash,
        decision_hash=decision.decision_hash,
        candidate_set_hash=bound.candidate_set_hash,
    )
    evaluation = decision.evaluation_binding
    evaluation_refs = DetectionContextEvaluationRefs(
        evaluation_id=evaluation.evaluation_id,
        artifact_hash=evaluation.artifact_hash,
        dataset_id=evaluation.dataset_id,
        dataset_version=evaluation.dataset_version,
        dataset_content_hash=evaluation.dataset_content_hash,
        code_sha=evaluation.code_sha,
    )
    source_revision_material = hashlib.sha256(
        _canonical_bytes(
            {
                "candidate_content_hash": candidate.content_hash,
                "decision_hash": decision.decision_hash,
                "event_revision": event_revision,
                "promotion_link_revision": promotion.link_revision,
                "package_content_hash": refs.package_content_hash,
            }
        )
    ).hexdigest()
    idempotency_key = build_idempotency_key(
        tenant_id=promotion.tenant_id,
        event_id=promotion.event_id or "",
        promotion_id=promotion.promotion_id,
        promotion_link_revision=promotion.link_revision,
        source_revision_material=source_revision_material,
    )
    body = DetectionContextSnapshot.model_construct(
        snapshot_id="pending",
        tenant_id=promotion.tenant_id,
        event_id=promotion.event_id or "",
        event_revision=event_revision,
        promotion_id=promotion.promotion_id,
        promotion_link_revision=promotion.link_revision,
        promotion_key=promotion.promotion_key,
        release_refs=release_refs,
        governance_refs=governance_refs,
        evaluation_refs=evaluation_refs,
        evidence_refs=build_ordered_evidence_refs(promotion=promotion, candidate=candidate),
        attack_refs=extract_attack_refs_from_rule(rule),
        scores=DetectionContextScoreSummary(
            matched_value=candidate.matched_value,
            detection_score=candidate.provenance.detection_score,
            severity=candidate.severity,
            operator=candidate.operator.value,
        ),
        coverage=summarize_feature_coverage(feature_snapshots),
        projection_errors=list(projection_errors or []),
        revision=revision,
        supersedes_snapshot_id=supersedes_snapshot_id,
        content_hash="0" * 64,
        idempotency_key=idempotency_key,
        schema_version=DETECTION_CONTEXT_SNAPSHOT_SCHEMA_VERSION,
    )
    payload = body.model_dump(mode="json")
    content_hash = compute_snapshot_content_hash(payload)
    snapshot_id = build_snapshot_id(
        tenant_id=promotion.tenant_id,
        event_id=promotion.event_id or "",
        revision=revision,
        content_hash=content_hash,
    )
    return DetectionContextSnapshot.model_validate(
        {
            **payload,
            "snapshot_id": snapshot_id,
            "content_hash": content_hash,
        }
    )


def snapshot_to_context_ref(snapshot: DetectionContextSnapshot) -> DetectionContextSnapshotRef:
    return DetectionContextSnapshotRef(
        snapshot_id=snapshot.snapshot_id,
        revision=snapshot.revision,
        content_hash=snapshot.content_hash,
        promotion_id=snapshot.promotion_id,
        promotion_link_revision=snapshot.promotion_link_revision,
        event_revision=snapshot.event_revision,
        created_at=snapshot.created_at,
    )


class DetectionContextResolver:
    """Server-owned entry point — consumers must not assemble snapshots locally."""

    build_detection_context_snapshot = staticmethod(build_detection_context_snapshot)
    build_snapshot_id = staticmethod(build_snapshot_id)
    compute_snapshot_content_hash = staticmethod(compute_snapshot_content_hash)
    snapshot_to_context_ref = staticmethod(snapshot_to_context_ref)
