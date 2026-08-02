"""Production wiring for ToolCallGrant, compatibility path, and ReAct executors (ISSUE-134)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from app.core.config import Settings
from app.core.errors import ToolCallGrantUnavailableError
from app.models.enums import ToolCategory
from app.models.tool_meta import RoutingKind
from app.models.tool_call_grant import ToolCallGrantScope
from app.orchestration.react_engine import DEFAULT_TOOL_CALL_BUDGET, ReadOnlyReActExecutor
from app.services.safe_tool_projection import SafeToolProjectionService
from app.services.tool_call_grant_resolver import resolve_effective_query_tools
from app.services.tool_call_grant_service import (
    ToolCallGrantService,
    build_react_grant_request,
)
from app.services.tenant_resolution import resolve_tenant_id
from app.tools.bound_tool_executor import BoundToolExecutor
from app.tools.compatibility_query_path import CompatibilityQueryToolPath
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


def build_evidence_query_executor(
    inner: ToolExecutor,
    *,
    settings: Settings,
) -> CompatibilityQueryToolPath:
    """Wrap the shared ToolExecutor with the named Evidence compatibility path."""

    return CompatibilityQueryToolPath(
        inner=inner,
        registry=inner.registry,
        settings=settings,
    )


def list_dynamic_query_tools(registry: ToolRegistry) -> list[str]:
    """Query tools eligible for dynamic ReAct grants (registry ∩ non-disposition)."""

    return sorted(
        meta.tool_name
        for meta in registry.list_tools(category=ToolCategory.QUERY)
        if meta.routing_kind is not RoutingKind.DISPOSITION_ONLY
    )


@dataclass
class ReactToolExecutorFactory:
    """Mint grant-bound executors per investigation event for ReAct dynamic calls."""

    inner_executor: ToolExecutor
    grant_service: ToolCallGrantService
    settings: Settings
    projection_service: SafeToolProjectionService

    @property
    def registry(self) -> ToolRegistry:
        return self.inner_executor.registry

    async def for_event(
        self,
        event_id: str,
        *,
        tenant_id: str | None = None,
        source_snapshot: dict[str, Any] | None = None,
    ) -> ReadOnlyReActExecutor:
        resolved_tenant = (tenant_id or resolve_tenant_id(source_snapshot) or "").strip()
        if not resolved_tenant:
            resolved_tenant = self.settings.retrieval_default_tenant_id.strip()

        if not self.settings.tool_call_grant_required:
            return ReadOnlyReActExecutor(self.inner_executor, event_id=event_id)

        if not self.grant_service.available:
            raise ToolCallGrantUnavailableError(
                "tool call grant service unavailable for dynamic ReAct",
                details={"event_id": event_id},
            )

        allowed_tools = list_dynamic_query_tools(self.registry)
        scope_tools = sorted(
            resolve_effective_query_tools(
                ToolCallGrantScope(allowed_tools=allowed_tools),
                self.registry,
            )
        )
        issued = await self.grant_service.issue_grant(
            build_react_grant_request(
                event_id=event_id,
                tenant_id=resolved_tenant,
                allowed_tools=scope_tools,
                max_calls=max(1, DEFAULT_TOOL_CALL_BUDGET),
                policy_version=self.settings.tool_call_grant_policy_version,
            )
        )
        if issued.grant_token:
            grant = issued.grant
            grant_token = issued.grant_token
        else:
            grant = await self.grant_service.load_grant_trusted(issued.grant.grant_id)
            grant_token = ""
            logger.info(
                "react grant idempotent replay grant_id=%s event_id=%s",
                grant.grant_id,
                event_id,
            )

        bound = BoundToolExecutor(
            inner=self.inner_executor,
            grant=grant,
            grant_service=self.grant_service,
            registry=self.registry,
            projection_service=self.projection_service,
            grant_token=grant_token,
        )
        return ReadOnlyReActExecutor(bound, event_id=event_id)


__all__ = [
    "ReactToolExecutorFactory",
    "build_evidence_query_executor",
    "list_dynamic_query_tools",
]
