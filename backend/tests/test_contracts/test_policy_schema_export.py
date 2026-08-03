"""Policy contract schema export tests (ISSUE-129 / #635)."""

from __future__ import annotations

import json

from app.models import MODEL_REGISTRY
from app.models.policy_citation import ApplicabilityStatus, PolicyCitation
from app.models.policy_release import PolicyControlRef


def test_policy_contract_models_are_registered() -> None:
    expected = {
        "AttackControlMapping",
        "OrganizationPolicyProfile",
        "PolicyApplicabilityHints",
        "PolicyCitation",
        "PolicyControl",
        "PolicyControlRef",
        "PolicyQueryPlan",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


def test_policy_citation_schema_exports_applicability_fields() -> None:
    schema = PolicyCitation.model_json_schema(mode="serialization")
    props = schema.get("properties", {})
    assert "applicability_status" in props
    assert "text_locator" in props
    assert "mapping_provenance" in props


def test_policy_control_ref_golden_json_roundtrip() -> None:
    ref = PolicyControlRef(
        control_id="ctrl-a1b2c3d4",
        framework_id="nist_csf",
        release_id="krel-test",
        release_version="v1",
        content_hash="a" * 64,
        bundle_content_hash="b" * 64,
        text_locator="NIST-CSF:PR.AC-1",
    )
    golden = json.dumps(ref.model_dump(mode="json"), sort_keys=True)
    restored = PolicyControlRef.model_validate_json(golden)
    assert restored == ref


def test_policy_citation_not_evaluated_roundtrip() -> None:
    citation = PolicyCitation(
        framework_id="nist_csf",
        release_id="krel-test",
        control_id="ctrl-a1b2c3d4",
        text_locator="NIST-CSF:PR.AC-1",
        applicability_status=ApplicabilityStatus.NOT_EVALUATED,
    )
    payload = citation.model_dump(mode="json")
    restored = PolicyCitation.model_validate(payload)
    assert restored.applicability_status is ApplicabilityStatus.NOT_EVALUATED
