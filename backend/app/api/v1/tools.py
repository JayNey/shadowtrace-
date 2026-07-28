"""Tool catalog + platform-wide tool-call listing endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import schemas as s
from app.core.auth import CurrentPrincipal

router = APIRouter(tags=["tools"])


@router.get("/tools", response_model=s.ToolsResponse)
async def list_tools(principal: CurrentPrincipal) -> s.ToolsResponse:
    return s.ToolsResponse(
        items=[
            s.ToolMetaItem(
                tool_name="block_ip",
                tool_category="response",
                side_effect_level="high",
                idempotency=True,
                async_mode=True,
                rollback_supported=True,
            ),
            s.ToolMetaItem(
                tool_name="query_asset_info",
                tool_category="query",
                side_effect_level="none",
                idempotency=True,
                async_mode=False,
                rollback_supported=False,
            ),
        ]
    )
