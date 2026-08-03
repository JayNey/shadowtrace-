"""Policy applicability and citation tests (ISSUE-129 / #635)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.errors import ValidationError
from app.models.attack_control_mapping import AttackControlMapping, MappingApprovalState
from app.models.knowledge_release import KnowledgeQueryPlan
from app.models.organization_policy_profile import OrganizationPolicyProfile
from app.models.policy_citation import (
    ApplicabilityReasonCode,
    ApplicabilityStatus,
    PolicyApplicabilityHints,
)
from app.models.policy_query_plan import PolicyQueryPlan
from app.models.policy_release import PolicyControl
from app.services.policy_applicability_service import (
    assert_plan_profile_consistency,
    build_mapping_citation,
    build_technique_policy_citations,
    evaluate_control_applicability,
)


def _profile(*, frameworks: tuple[str, ...] = ("nist_csf",)) -> OrganizationPolicyProfile:
    now = datetime.now(tz=UTC)
    return OrganizationPolicyProfile(
        profile_id="opp-a1b2c3d4",
        tenant_id="tenant-a",
        revision=1,
        owner_principal="principal-a",
        framework_allowlist=frameworks,
        jurisdiction_codes=("US",),
        industry_codes=("finance",),
        effective_at=now,
        created_at=now,
        updated_at=now,
    )


def _control(**overrides: object) -> PolicyControl:
    base = {
        "control_id": "ctrl-a1b2c3d4",
        "framework_id": "nist_csf",
        "control_family": "PR.AC",
        "title": "Access Control",
        "requirement_text": "Manage identities.",
        "text_locator": "NIST-CSF:PR.AC-1",
        "jurisdiction_codes": ("US",),
        "industry_codes": ("finance", "healthcare"),
    }
    base.update(overrides)
    return PolicyControl.model_validate(base)


def test_missing_profile_fail_closed_not_evaluated() -> None:
    citation = evaluate_control_applicability(
        profile=None,
        control=_control(),
        release_id="krel-test",
        hints=PolicyApplicabilityHints(framework_ids=["iso27001"]),
    )
    assert citation.applicability_status is ApplicabilityStatus.NOT_EVALUATED
    assert citation.applicability_reason is ApplicabilityReasonCode.PROFILE_MISSING


def test_framework_not_in_allowlist_not_applicable() -> None:
    citation = evaluate_control_applicability(
        profile=_profile(frameworks=("iso27001",)),
        control=_control(),
        release_id="krel-test",
    )
    assert citation.applicability_status is ApplicabilityStatus.NOT_APPLICABLE
    assert citation.applicability_reason is ApplicabilityReasonCode.FRAMEWORK_NOT_ALLOWED


def test_unapproved_mapping_excluded_from_production_citation() -> None:
    mapping = AttackControlMapping(
        mapping_id="map-candidate",
        release_id="krel-test",
        technique_id="T1059",
        control_id="ctrl-a1b2c3d4",
        framework_id="nist_csf",
        approval_state=MappingApprovalState.CANDIDATE,
        mapping_version="1.0",
        provenance="model_suggestion",
    )
    assert (
        build_mapping_citation(
            mapping=mapping,
            control=_control(),
            profile=_profile(),
        )
        is None
    )


def test_approved_mapping_produces_citation_with_provenance() -> None:
    mapping = AttackControlMapping(
        mapping_id="map-approved",
        release_id="krel-test",
        technique_id="T1059",
        control_id="ctrl-a1b2c3d4",
        framework_id="nist_csf",
        approval_state=MappingApprovalState.APPROVED,
        mapping_version="1.0",
        provenance="curated_baseline_v1",
    )
    citation = build_mapping_citation(
        mapping=mapping,
        control=_control(),
        profile=_profile(),
    )
    assert citation is not None
    assert citation.applicability_status is ApplicabilityStatus.APPLICABLE
    assert citation.mapping_provenance == "curated_baseline_v1"
    assert citation.technique_id == "T1059"


def test_technique_citations_exclude_candidate_mappings() -> None:
    control = _control()
    mappings = [
        AttackControlMapping(
            mapping_id="map-approved",
            release_id="krel-test",
            technique_id="T1059",
            control_id="ctrl-a1b2c3d4",
            framework_id="nist_csf",
            approval_state=MappingApprovalState.APPROVED,
            mapping_version="1.0",
            provenance="curated_baseline_v1",
        ),
        AttackControlMapping(
            mapping_id="map-candidate",
            release_id="krel-test",
            technique_id="T1059",
            control_id="ctrl-b2c3d4e5",
            framework_id="nist_csf",
            approval_state=MappingApprovalState.CANDIDATE,
            mapping_version="1.0",
            provenance="model_suggestion",
        ),
    ]
    citations = build_technique_policy_citations(
        technique_id="T1059",
        release_id="krel-test",
        mappings=mappings,
        controls_by_id={control.control_id: control},
        profile=_profile(),
    )
    assert len(citations) == 1
    assert citations[0].mapping_provenance == "curated_baseline_v1"


def test_empty_framework_allowlist_fail_closed_not_evaluated() -> None:
    citation = evaluate_control_applicability(
        profile=_profile(frameworks=()),
        control=_control(),
        release_id="krel-test",
    )
    assert citation.applicability_status is ApplicabilityStatus.NOT_EVALUATED
    assert citation.applicability_reason is ApplicabilityReasonCode.PROFILE_INCOMPLETE


def test_jurisdiction_mismatch_not_applicable() -> None:
    citation = evaluate_control_applicability(
        profile=_profile(frameworks=("nist_csf",)).model_copy(
            update={"jurisdiction_codes": ("EU",)}
        ),
        control=_control(),
        release_id="krel-test",
    )
    assert citation.applicability_status is ApplicabilityStatus.NOT_APPLICABLE
    assert citation.applicability_reason is ApplicabilityReasonCode.JURISDICTION_MISMATCH


def test_technique_citations_control_not_in_release_returns_typed_citation() -> None:
    mapping = AttackControlMapping(
        mapping_id="map-approved-missing-control",
        release_id="krel-test",
        technique_id="T1059",
        control_id="ctrl-deadbeef",
        framework_id="nist_csf",
        approval_state=MappingApprovalState.APPROVED,
        mapping_version="1.0",
        provenance="curated_baseline_v1",
    )
    citations = build_technique_policy_citations(
        technique_id="T1059",
        release_id="krel-test",
        mappings=[mapping],
        controls_by_id={},
        profile=_profile(),
    )
    assert len(citations) == 1
    assert citations[0].applicability_reason is ApplicabilityReasonCode.CONTROL_NOT_IN_RELEASE
    assert citations[0].text_locator == "unknown:control_not_in_release"


def test_assert_plan_profile_consistency_rejects_stale_revision() -> None:
    profile = _profile()
    stale_profile = profile.model_copy(update={"revision": 2})
    now = datetime.now(tz=UTC)
    plan = PolicyQueryPlan(
        tenant_id="tenant-a",
        principal="principal-a",
        knowledge_plan=KnowledgeQueryPlan(
            corpus_id="policy_control",
            active_release_id="krel-test",
            embedding_release_id="emb-test",
            trace_id="trace-1",
            kb_name="policy_kb",
            plan_hash="a" * 64,
            pinned_at=now,
        ),
        profile_id=profile.profile_id,
        profile_revision=1,
        plan_hash="b" * 64,
        pinned_at=now,
    )
    with pytest.raises(ValidationError, match="profile revision mismatch"):
        assert_plan_profile_consistency(plan, stale_profile)
