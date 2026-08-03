"""Detection governance contract schema export tests (ISSUE-125 / #630 Phase A)."""

from __future__ import annotations

import json

from app.models import MODEL_REGISTRY
from app.models.detection_governance import (
    DetectionGovernanceCandidateBinding,
    DetectionGovernanceDecision,
    DetectionGovernanceDecisionKind,
    DetectionGovernanceEligibilityAssessment,
    DetectionGovernanceEvaluationBinding,
    DetectionGovernancePromotionGateResult,
    DetectionGovernanceThresholdBinding,
)


def test_detection_governance_models_are_registered() -> None:
    expected = {
        "DetectionGovernanceCandidateBinding",
        "DetectionGovernanceDecision",
        "DetectionGovernanceDecisionRequest",
        "DetectionGovernanceEligibilityAssessment",
        "DetectionGovernanceEvaluationBinding",
        "DetectionGovernancePromotionGateResult",
        "DetectionGovernanceRevokeRequest",
        "DetectionGovernanceThresholdBinding",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


def test_detection_governance_decision_schema_exports_core_fields() -> None:
    schema = DetectionGovernanceDecision.model_json_schema(mode="serialization")
    props = schema.get("properties", {})
    for field in (
        "decision_id",
        "tenant_id",
        "decision",
        "candidate_binding",
        "evaluation_binding",
        "threshold_binding",
        "binding_hash",
        "policy_version",
        "reviewer_subject",
        "reason_codes",
        "decided_at",
    ):
        assert field in props


def test_detection_governance_eligibility_schema_exports_validated_flag() -> None:
    schema = DetectionGovernanceEligibilityAssessment.model_json_schema(mode="serialization")
    props = schema.get("properties", {})
    assert "threshold_manifest_validated" in props


def test_detection_governance_golden_json_roundtrip() -> None:
    from datetime import UTC, datetime

    from app.models.detection_evaluation import DetectionCandidateRefs

    refs = DetectionCandidateRefs(
        package_id="drpkg-test",
        package_version=1,
        package_content_hash="a" * 64,
        feature_contract_version="1.0",
        detection_scope_id="dscope-test",
    )
    decision = DetectionGovernanceDecision(
        decision_id="dgov-golden",
        tenant_id="tenant-a",
        decision=DetectionGovernanceDecisionKind.APPROVE,
        candidate_binding=DetectionGovernanceCandidateBinding(
            candidate_set_hash="c" * 64,
            candidate_refs=refs,
            feature_contract_version="1.0",
            detection_scope_id="dscope-test",
        ),
        evaluation_binding=DetectionGovernanceEvaluationBinding(
            evaluation_id="deval-golden",
            dataset_id="detection_shadow_v1",
            dataset_version="2026.08.02",
            dataset_content_hash="b" * 64,
            artifact_hash="d" * 64,
            code_sha="abc1234",
        ),
        threshold_binding=DetectionGovernanceThresholdBinding(manifest_version="2026.08.02"),
        binding_hash="e" * 64,
        policy_version="issue125_v1",
        reviewer_subject="approver-1",
        reviewer_roles=["approver"],
        decided_at=datetime.now(UTC),
    )
    golden = json.dumps(decision.model_dump(mode="json"), sort_keys=True)
    restored = DetectionGovernanceDecision.model_validate_json(golden)
    assert restored.decision == DetectionGovernanceDecisionKind.APPROVE
    assert restored.evaluation_binding.artifact_hash == "d" * 64


def test_promotion_gate_result_extra_forbid() -> None:
    schema = DetectionGovernancePromotionGateResult.model_json_schema(mode="serialization")
    assert schema.get("additionalProperties") is False
