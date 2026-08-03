"""Hash binding and replay validation for detection governance (ISSUE-125 / #630)."""

from __future__ import annotations

import hashlib
from typing import Any

import orjson

from app.core.errors import ValidationError
from app.evaluation.detection.artifact import compute_detection_artifact_hash
from app.models.detection_evaluation import DetectionEvaluationArtifact
from app.models.detection_governance import (
    DetectionGovernanceCandidateBinding,
    DetectionGovernanceDecision,
    DetectionGovernanceDecisionKind,
    DetectionGovernanceEvaluationBinding,
    DetectionGovernanceReasonCode,
    DetectionGovernanceThresholdBinding,
)
from app.services.detection_governance_policy import DETECTION_GOVERNANCE_POLICY_VERSION

_HASH_EXCLUDE = frozenset({"decision_id", "decided_at", "decision_hash", "expires_at"})


def build_candidate_binding(
    artifact: DetectionEvaluationArtifact,
) -> DetectionGovernanceCandidateBinding:
    refs = artifact.config.candidate_refs
    return DetectionGovernanceCandidateBinding(
        candidate_set_hash=artifact.config.candidate_set_hash,
        candidate_refs=refs,
        feature_contract_version=refs.feature_contract_version,
        detection_scope_id=refs.detection_scope_id,
        scope_revision_id=refs.scope_revision_id,
        model_release_id=refs.model_release_id,
        model_release_hash=refs.model_release_hash,
    )


def build_evaluation_binding(
    artifact: DetectionEvaluationArtifact,
) -> DetectionGovernanceEvaluationBinding:
    if not artifact.artifact_hash:
        raise ValidationError(
            "evaluation artifact missing artifact_hash",
            details={"evaluation_id": artifact.evaluation_id},
        )
    return DetectionGovernanceEvaluationBinding(
        evaluation_id=artifact.evaluation_id,
        dataset_id=artifact.dataset_id,
        dataset_version=artifact.dataset_version,
        dataset_content_hash=artifact.dataset_content_hash,
        artifact_hash=artifact.artifact_hash,
        code_sha=artifact.code_sha,
    )


def build_threshold_binding(
    artifact: DetectionEvaluationArtifact,
    *,
    manifest_path: str | None = None,
) -> DetectionGovernanceThresholdBinding:
    gate = artifact.gate
    manifest_version = gate.manifest_version if gate is not None else ""
    if not manifest_version:
        raise ValidationError(
            "evaluation artifact missing gate manifest_version",
            details={"evaluation_id": artifact.evaluation_id},
        )
    return DetectionGovernanceThresholdBinding(
        manifest_version=manifest_version,
        manifest_path=manifest_path or (gate.manifest_path if gate is not None else None),
    )


def compute_binding_hash(
    *,
    tenant_id: str,
    candidate_binding: DetectionGovernanceCandidateBinding,
    evaluation_binding: DetectionGovernanceEvaluationBinding,
    threshold_binding: DetectionGovernanceThresholdBinding,
    policy_version: str,
) -> str:
    payload = {
        "tenant_id": tenant_id,
        "candidate_set_hash": candidate_binding.candidate_set_hash,
        "package_content_hash": candidate_binding.candidate_refs.package_content_hash,
        "package_id": candidate_binding.candidate_refs.package_id,
        "package_version": candidate_binding.candidate_refs.package_version,
        "feature_contract_version": candidate_binding.feature_contract_version,
        "detection_scope_id": candidate_binding.detection_scope_id,
        "scope_revision_id": candidate_binding.scope_revision_id,
        "model_release_id": candidate_binding.model_release_id,
        "model_release_hash": candidate_binding.model_release_hash,
        "evaluation_artifact_hash": evaluation_binding.artifact_hash,
        "dataset_content_hash": evaluation_binding.dataset_content_hash,
        "threshold_manifest_version": threshold_binding.manifest_version,
        "policy_version": policy_version,
    }
    return hashlib.sha256(orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)).hexdigest()


def compute_decision_hash(decision: DetectionGovernanceDecision) -> str:
    payload = decision.model_dump(mode="json")
    canonical = {k: v for k, v in payload.items() if k not in _HASH_EXCLUDE}
    return hashlib.sha256(orjson.dumps(canonical, option=orjson.OPT_SORT_KEYS)).hexdigest()


def finalize_decision(decision: DetectionGovernanceDecision) -> DetectionGovernanceDecision:
    digest = compute_decision_hash(decision)
    return decision.model_copy(update={"decision_hash": digest})


def validate_decision_artifact_binding(
    decision: DetectionGovernanceDecision,
    artifact: DetectionEvaluationArtifact,
) -> None:
    """Fail closed when artifact drifted after governance decision was recorded."""
    computed_hash = compute_detection_artifact_hash(artifact)
    if computed_hash != decision.evaluation_binding.artifact_hash:
        raise ValidationError(
            "governance binding stale: evaluation artifact hash changed",
            details={
                "decision_id": decision.decision_id,
                "reason": DetectionGovernanceReasonCode.ARTIFACT_HASH_MISMATCH.value,
            },
        )
    if artifact.artifact_hash != decision.evaluation_binding.artifact_hash:
        raise ValidationError(
            "governance binding stale: artifact_hash field mismatch",
            details={
                "decision_id": decision.decision_id,
                "reason": DetectionGovernanceReasonCode.ARTIFACT_HASH_MISMATCH.value,
            },
        )

    candidate = build_candidate_binding(artifact)
    bound = decision.candidate_binding
    if candidate.candidate_set_hash != bound.candidate_set_hash:
        raise ValidationError(
            "governance binding stale: candidate_set_hash changed",
            details={
                "decision_id": decision.decision_id,
                "reason": DetectionGovernanceReasonCode.CANDIDATE_BINDING_MISMATCH.value,
            },
        )
    bound_refs = bound.candidate_refs.model_dump(mode="json")
    candidate_refs = candidate.candidate_refs.model_dump(mode="json")
    if candidate_refs != bound_refs:
        raise ValidationError(
            "governance binding stale: candidate refs changed",
            details={
                "decision_id": decision.decision_id,
                "reason": DetectionGovernanceReasonCode.CANDIDATE_BINDING_MISMATCH.value,
            },
        )

    if decision.policy_version != DETECTION_GOVERNANCE_POLICY_VERSION:
        raise ValidationError(
            "governance binding stale: policy version changed",
            details={
                "decision_id": decision.decision_id,
                "reason": DetectionGovernanceReasonCode.POLICY_VERSION_MISMATCH.value,
            },
        )


def decision_is_active(
    decision: DetectionGovernanceDecision,
    *,
    now: Any,
    superseding_kinds: set[DetectionGovernanceDecisionKind] | None = None,
) -> bool:
    if decision.decision != DetectionGovernanceDecisionKind.APPROVE:
        return False
    if decision.expires_at is not None and decision.expires_at <= now:
        return False
    if superseding_kinds:
        if DetectionGovernanceDecisionKind.REVOKE in superseding_kinds:
            return False
        if DetectionGovernanceDecisionKind.EXPIRE in superseding_kinds:
            return False
    return True


__all__ = [
    "build_candidate_binding",
    "build_evaluation_binding",
    "build_threshold_binding",
    "compute_binding_hash",
    "compute_decision_hash",
    "decision_is_active",
    "finalize_decision",
    "validate_decision_artifact_binding",
]
