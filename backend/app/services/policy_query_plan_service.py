"""Resolve request-scoped policy query plan (ISSUE-129 / #635)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from app.core.config import Settings
from app.core.embedding.release import build_embedding_release
from app.core.errors import ValidationError
from app.models.knowledge_release import KnowledgeQueryPlan
from app.models.organization_policy_profile import OrganizationPolicyProfile
from app.models.policy_query_plan import POLICY_QUERY_PLAN_SCHEMA_VERSION, PolicyQueryPlan
from app.models.policy_release import POLICY_CORPUS_ID, POLICY_KB_NAME
from app.services.knowledge_query_plan_service import resolve_knowledge_query_plan
from app.services.organization_policy_profile_service import OrganizationPolicyProfileService
from app.services.policy_applicability_service import (
    assert_plan_profile_consistency,
    compute_policy_query_plan_hash,
)
from app.services.policy_release_service import PolicyReleaseService

logger = logging.getLogger(__name__)


async def validate_pinned_policy_query_plan(
    plan: PolicyQueryPlan,
    profile_service: OrganizationPolicyProfileService,
    *,
    tenant_id: str,
    principal: str,
    authorized_tenant_id: str | None = None,
) -> OrganizationPolicyProfile | None:
    """Load the profile revision pinned on the plan (not the current effective revision)."""
    normalized_tenant = tenant_id.strip()
    normalized_principal = principal.strip()
    if plan.tenant_id.strip() != normalized_tenant:
        raise ValidationError(
            "policy query plan tenant mismatch",
            details={"expected_tenant_id": normalized_tenant, "plan_tenant_id": plan.tenant_id},
        )
    if plan.principal.strip() != normalized_principal:
        raise ValidationError(
            "policy query plan principal mismatch",
            details={
                "expected_principal": normalized_principal,
                "plan_principal": plan.principal,
            },
        )
    if plan.profile_id is None or plan.profile_revision is None:
        return None
    authorized = (
        authorized_tenant_id.strip() if authorized_tenant_id is not None else normalized_tenant
    )
    return await profile_service.validate_profile_revision(
        tenant_id=normalized_tenant,
        profile_id=plan.profile_id,
        profile_revision=plan.profile_revision,
        authorized_tenant_id=authorized,
    )


async def resolve_active_policy_query_plan(
    release_service: PolicyReleaseService,
    profile_service: OrganizationPolicyProfileService,
    settings: Settings,
    *,
    tenant_id: str,
    principal: str,
    trace_id: str,
) -> PolicyQueryPlan | None:
    """Pin active policy release and effective organization profile for one request."""
    active = await release_service.get_active_release()
    if active is None:
        logger.debug("no active policy release for corpus=%s", POLICY_CORPUS_ID)
        return None

    normalized_tenant = tenant_id.strip()
    profile = await profile_service.get_effective_profile(
        tenant_id=normalized_tenant,
        principal=principal,
        authorized_tenant_id=normalized_tenant,
    )
    embedding_release_id = active.embedding_release_id
    if not embedding_release_id:
        embedding_release_id = build_embedding_release(settings).release_id

    knowledge_plan = resolve_knowledge_query_plan(
        corpus_id=POLICY_CORPUS_ID,
        active_release_id=active.release_id,
        embedding_release_id=embedding_release_id,
        trace_id=trace_id,
        kb_name=POLICY_KB_NAME,
        tenant_id=tenant_id.strip(),
        principal=principal.strip(),
    )
    plan = build_policy_query_plan(
        tenant_id=normalized_tenant,
        principal=principal,
        knowledge_plan=knowledge_plan,
        profile=profile,
    )
    assert_plan_profile_consistency(plan, profile)
    return plan


def build_policy_query_plan(
    *,
    tenant_id: str,
    principal: str,
    knowledge_plan: KnowledgeQueryPlan,
    profile: OrganizationPolicyProfile | None,
) -> PolicyQueryPlan:
    pinned_at = datetime.now(UTC)
    draft = PolicyQueryPlan(
        schema_version=POLICY_QUERY_PLAN_SCHEMA_VERSION,
        tenant_id=tenant_id.strip(),
        principal=principal.strip(),
        knowledge_plan=knowledge_plan,
        profile_id=profile.profile_id if profile is not None else None,
        profile_revision=profile.revision if profile is not None else None,
        plan_hash="",
        pinned_at=pinned_at,
    )
    hash_payload = draft.model_dump(mode="json", exclude={"plan_hash"})
    plan_hash = compute_policy_query_plan_hash(hash_payload)
    return draft.model_copy(update={"plan_hash": plan_hash})


__all__ = [
    "build_policy_query_plan",
    "resolve_active_policy_query_plan",
    "validate_pinned_policy_query_plan",
]
