"""Detection governance decision API (ISSUE-125 / #630 Phase A)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.v1 import schemas as s
from app.api.v1.deps import DetectionGovernanceDep
from app.core.auth import ROLE_ANALYST, ROLE_APPROVER, Principal, require_roles
from app.models.detection_evaluation import DetectionEvaluationArtifact
from app.models.detection_governance import (
    DetectionGovernanceDecisionKind,
    DetectionGovernanceDecisionRequest,
    DetectionGovernanceRevokeRequest,
)

router = APIRouter(tags=["detection-governance"])


@router.post(
    "/detection/governance/eligibility",
    response_model=s.DetectionGovernanceEligibilityResponse,
)
async def assess_detection_governance_eligibility(
    body: s.DetectionGovernanceEligibilityRequest,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
) -> s.DetectionGovernanceEligibilityResponse:
    artifact = DetectionEvaluationArtifact.model_validate(body.artifact)
    assessment = await governance.assess_eligibility(
        artifact,
        threshold_manifest_path=Path(body.threshold_manifest_path)
        if body.threshold_manifest_path
        else None,
    )
    return s.DetectionGovernanceEligibilityResponse.model_validate(assessment.model_dump())


@router.post(
    "/detection/governance/decisions",
    response_model=s.DetectionGovernanceDecisionResponse,
)
async def record_detection_governance_decision(
    body: s.DetectionGovernanceDecisionCreateRequest,
    principal: Annotated[Principal, require_roles(ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
) -> s.DetectionGovernanceDecisionResponse:
    artifact = DetectionEvaluationArtifact.model_validate(body.artifact)
    request = DetectionGovernanceDecisionRequest(
        decision=DetectionGovernanceDecisionKind(body.decision),
        reason_note=body.reason_note,
        expires_at=body.expires_at,
    )
    decision = await governance.record_decision(
        principal,
        artifact,
        request,
        threshold_manifest_path=Path(body.threshold_manifest_path)
        if body.threshold_manifest_path
        else None,
    )
    return s.DetectionGovernanceDecisionResponse.model_validate(decision.model_dump())


@router.get(
    "/detection/governance/decisions/{decision_id}",
    response_model=s.DetectionGovernanceDecisionResponse,
)
async def get_detection_governance_decision(
    decision_id: str,
    tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
) -> s.DetectionGovernanceDecisionResponse:
    decision = await governance.get_decision(decision_id, tenant_id=tenant_id)
    return s.DetectionGovernanceDecisionResponse.model_validate(decision.model_dump())


@router.get(
    "/detection/governance/decisions",
    response_model=s.DetectionGovernanceDecisionListResponse,
)
async def list_detection_governance_decisions(
    tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
    binding_hash: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
) -> s.DetectionGovernanceDecisionListResponse:
    offset = (page - 1) * page_size
    items, total = await governance.list_decisions(
        tenant_id=tenant_id,
        binding_hash=binding_hash,
        limit=page_size,
        offset=offset,
    )
    return s.DetectionGovernanceDecisionListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[
            s.DetectionGovernanceDecisionResponse.model_validate(item.model_dump())
            for item in items
        ],
    )


@router.post(
    "/detection/governance/decisions/{decision_id}/revoke",
    response_model=s.DetectionGovernanceDecisionResponse,
)
async def revoke_detection_governance_decision(
    decision_id: str,
    tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    body: DetectionGovernanceRevokeRequest,
    principal: Annotated[Principal, require_roles(ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
) -> s.DetectionGovernanceDecisionResponse:
    decision = await governance.revoke_decision(
        principal,
        decision_id,
        reason_note=body.reason_note,
        tenant_id=tenant_id,
    )
    return s.DetectionGovernanceDecisionResponse.model_validate(decision.model_dump())


@router.post(
    "/detection/governance/promotion-gate",
    response_model=s.DetectionGovernancePromotionGateResponse,
)
async def evaluate_detection_promotion_gate(
    body: s.DetectionGovernancePromotionGateRequest,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
) -> s.DetectionGovernancePromotionGateResponse:
    artifact = DetectionEvaluationArtifact.model_validate(body.artifact)
    result = await governance.evaluate_promotion_gate(
        artifact,
        binding_hash=body.binding_hash,
    )
    return s.DetectionGovernancePromotionGateResponse.model_validate(result.model_dump())
