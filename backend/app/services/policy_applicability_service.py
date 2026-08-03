"""Policy applicability evaluation and citation builder (ISSUE-129 / #635 Phase A)."""

from __future__ import annotations

import hashlib
import json

from app.core.errors import ValidationError
from app.models.attack_control_mapping import AttackControlMapping, MappingApprovalState
from app.models.organization_policy_profile import OrganizationPolicyProfile
from app.models.policy_citation import (
    ApplicabilityReasonCode,
    ApplicabilityStatus,
    PolicyApplicabilityHints,
    PolicyCitation,
)
from app.models.policy_query_plan import PolicyQueryPlan
from app.models.policy_release import PolicyControl

_MISSING_CONTROL_LOCATOR = "unknown:control_not_in_release"
_PROFILE_MISSING_FRAMEWORK = "unknown"
_PROFILE_MISSING_CONTROL_ID = "unknown:profile_missing"
_PROFILE_MISSING_LOCATOR = "unknown:profile_missing"


def compute_policy_query_plan_hash(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _framework_allowed(profile: OrganizationPolicyProfile, framework_id: str) -> bool:
    return framework_id in profile.framework_allowlist


def _jurisdiction_compatible(profile: OrganizationPolicyProfile, control: PolicyControl) -> bool:
    """Empty control jurisdiction_codes means universal scope within allowed framework."""
    if not profile.jurisdiction_codes:
        return True
    if not control.jurisdiction_codes:
        return True
    return bool(set(profile.jurisdiction_codes) & set(control.jurisdiction_codes))


def _industry_compatible(profile: OrganizationPolicyProfile, control: PolicyControl) -> bool:
    """Empty control industry_codes means universal scope within allowed framework."""
    if not profile.industry_codes:
        return True
    if not control.industry_codes:
        return True
    return bool(set(profile.industry_codes) & set(control.industry_codes))


def evaluate_control_applicability(
    *,
    profile: OrganizationPolicyProfile | None,
    control: PolicyControl,
    release_id: str,
    hints: PolicyApplicabilityHints | None = None,
) -> PolicyCitation:
    """Server-owned applicability — agent hints are ignored for allow decisions."""
    _ = hints  # untrusted; retained for future audit logging only
    if profile is None:
        return PolicyCitation(
            framework_id=control.framework_id,
            release_id=release_id,
            control_id=control.control_id,
            text_locator=control.text_locator,
            applicability_status=ApplicabilityStatus.NOT_EVALUATED,
            applicability_reason=ApplicabilityReasonCode.PROFILE_MISSING,
        )
    if not profile.framework_allowlist:
        return PolicyCitation(
            framework_id=control.framework_id,
            release_id=release_id,
            control_id=control.control_id,
            text_locator=control.text_locator,
            applicability_status=ApplicabilityStatus.NOT_EVALUATED,
            applicability_reason=ApplicabilityReasonCode.PROFILE_INCOMPLETE,
            profile_id=profile.profile_id,
            profile_revision=profile.revision,
        )
    if not _framework_allowed(profile, control.framework_id):
        return PolicyCitation(
            framework_id=control.framework_id,
            release_id=release_id,
            control_id=control.control_id,
            text_locator=control.text_locator,
            applicability_status=ApplicabilityStatus.NOT_APPLICABLE,
            applicability_reason=ApplicabilityReasonCode.FRAMEWORK_NOT_ALLOWED,
            profile_id=profile.profile_id,
            profile_revision=profile.revision,
        )
    if not _jurisdiction_compatible(profile, control):
        return PolicyCitation(
            framework_id=control.framework_id,
            release_id=release_id,
            control_id=control.control_id,
            text_locator=control.text_locator,
            applicability_status=ApplicabilityStatus.NOT_APPLICABLE,
            applicability_reason=ApplicabilityReasonCode.JURISDICTION_MISMATCH,
            profile_id=profile.profile_id,
            profile_revision=profile.revision,
        )
    if not _industry_compatible(profile, control):
        return PolicyCitation(
            framework_id=control.framework_id,
            release_id=release_id,
            control_id=control.control_id,
            text_locator=control.text_locator,
            applicability_status=ApplicabilityStatus.NOT_APPLICABLE,
            applicability_reason=ApplicabilityReasonCode.INDUSTRY_MISMATCH,
            profile_id=profile.profile_id,
            profile_revision=profile.revision,
        )
    return PolicyCitation(
        framework_id=control.framework_id,
        release_id=release_id,
        control_id=control.control_id,
        text_locator=control.text_locator,
        applicability_status=ApplicabilityStatus.APPLICABLE,
        profile_id=profile.profile_id,
        profile_revision=profile.revision,
    )


def build_mapping_citation(
    *,
    mapping: AttackControlMapping,
    control: PolicyControl,
    profile: OrganizationPolicyProfile | None,
    hints: PolicyApplicabilityHints | None = None,
) -> PolicyCitation | None:
    """Return production citation for an approved mapping only."""
    if mapping.approval_state is not MappingApprovalState.APPROVED:
        return None
    base = evaluate_control_applicability(
        profile=profile,
        control=control,
        release_id=mapping.release_id,
        hints=hints,
    )
    if base.applicability_status is ApplicabilityStatus.NOT_EVALUATED:
        return base
    return PolicyCitation(
        framework_id=base.framework_id,
        release_id=base.release_id,
        control_id=base.control_id,
        text_locator=base.text_locator,
        applicability_status=base.applicability_status,
        applicability_reason=base.applicability_reason,
        mapping_provenance=mapping.provenance,
        mapping_version=mapping.mapping_version,
        technique_id=mapping.technique_id,
        profile_id=base.profile_id,
        profile_revision=base.profile_revision,
    )


def build_technique_policy_citations(
    *,
    technique_id: str,
    release_id: str,
    mappings: list[AttackControlMapping],
    controls_by_id: dict[str, PolicyControl],
    profile: OrganizationPolicyProfile | None,
    hints: PolicyApplicabilityHints | None = None,
) -> list[PolicyCitation]:
    """Build production citations for one technique; excludes unapproved mappings."""
    if profile is None:
        return [
            PolicyCitation(
                framework_id=_PROFILE_MISSING_FRAMEWORK,
                release_id=release_id,
                control_id=_PROFILE_MISSING_CONTROL_ID,
                text_locator=_PROFILE_MISSING_LOCATOR,
                applicability_status=ApplicabilityStatus.NOT_EVALUATED,
                applicability_reason=ApplicabilityReasonCode.PROFILE_MISSING,
                technique_id=technique_id,
            )
        ]

    citations: list[PolicyCitation] = []
    for mapping in mappings:
        if mapping.technique_id != technique_id:
            continue
        if mapping.approval_state is not MappingApprovalState.APPROVED:
            continue
        control = controls_by_id.get(mapping.control_id)
        if control is None:
            citations.append(
                PolicyCitation(
                    framework_id=mapping.framework_id,
                    release_id=release_id,
                    control_id=mapping.control_id,
                    text_locator=_MISSING_CONTROL_LOCATOR,
                    applicability_status=ApplicabilityStatus.NOT_EVALUATED,
                    applicability_reason=ApplicabilityReasonCode.CONTROL_NOT_IN_RELEASE,
                    technique_id=technique_id,
                    profile_id=profile.profile_id,
                    profile_revision=profile.revision,
                )
            )
            continue
        citation = build_mapping_citation(
            mapping=mapping,
            control=control,
            profile=profile,
            hints=hints,
        )
        if citation is not None:
            citations.append(citation)
    return citations


def assert_plan_profile_consistency(
    plan: PolicyQueryPlan,
    profile: OrganizationPolicyProfile | None,
) -> None:
    """Fail closed when a pinned plan references a missing or stale profile revision."""
    if plan.profile_id is None:
        return
    if profile is None:
        raise ValidationError(
            "pinned policy query plan references missing profile",
            details={
                "profile_id": plan.profile_id,
                "profile_revision": plan.profile_revision,
                "reason": ApplicabilityReasonCode.PROFILE_REVISION_STALE.value,
            },
        )
    if plan.profile_revision != profile.revision or plan.profile_id != profile.profile_id:
        raise ValidationError(
            "policy query plan profile revision mismatch",
            details={
                "profile_id": plan.profile_id,
                "expected_revision": plan.profile_revision,
                "actual_revision": profile.revision,
                "reason": ApplicabilityReasonCode.PROFILE_REVISION_STALE.value,
            },
        )


__all__ = [
    "assert_plan_profile_consistency",
    "build_mapping_citation",
    "build_technique_policy_citations",
    "compute_policy_query_plan_hash",
    "evaluate_control_applicability",
]
