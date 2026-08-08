"""Knowledge listing and governed memory review endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter

from app.api.v1 import schemas as s
from app.api.v1.deps import MemoryGovernanceDep
from app.core.auth import ROLE_ANALYST, ROLE_APPROVER, Principal, ReadPrincipal, require_roles

router = APIRouter(tags=["knowledge"])


@router.get("/knowledge", response_model=s.KnowledgeResponse)
async def list_knowledge(
    principal: ReadPrincipal, page: int = 1, page_size: int = 20
) -> s.KnowledgeResponse:
    return s.KnowledgeResponse(total=0, page=page, page_size=page_size, items=[])


@router.get("/knowledge/reviews", response_model=s.MemoryReviewListResponse)
async def list_memory_reviews(
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    governance: MemoryGovernanceDep,
    kb_name: str | None = None,
) -> s.MemoryReviewListResponse:
    reviews = await governance.list_pending(kb_name)
    items = [s.MemoryReviewItem.model_validate(review.model_dump()) for review in reviews]
    return s.MemoryReviewListResponse(total=len(items), items=items)


@router.post(
    "/knowledge/reviews/{review_id}/promote",
    response_model=s.MemoryReviewOperationResponse,
)
async def promote_memory_review(
    review_id: str,
    principal: Annotated[Principal, require_roles(ROLE_APPROVER)],
    governance: MemoryGovernanceDep,
) -> s.MemoryReviewOperationResponse:
    await governance.promote(review_id, principal.subject)
    return s.MemoryReviewOperationResponse(
        review_id=review_id,
        status="promoted",
        message="memory candidate promoted",
    )


@router.post(
    "/knowledge/reviews/{review_id}/reject",
    response_model=s.MemoryReviewOperationResponse,
)
async def reject_memory_review(
    review_id: str,
    body: s.MemoryReviewRejectRequest,
    principal: Annotated[Principal, require_roles(ROLE_APPROVER)],
    governance: MemoryGovernanceDep,
) -> s.MemoryReviewOperationResponse:
    await governance.demote(review_id, principal.subject, body.reason)
    return s.MemoryReviewOperationResponse(
        review_id=review_id,
        status="demoted",
        message="memory candidate rejected",
    )
