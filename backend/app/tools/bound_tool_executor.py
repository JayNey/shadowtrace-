"""BoundToolExecutor — grant-mediated dynamic tool dispatch (ISSUE-134)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.core.errors import ToolCallGrantDeniedError
from app.models.enums import ToolCategory
from app.models.tool_call_grant import (
    SafeToolProjection,
    ToolCallAttemptStatus,
    ToolCallGrant,
    ToolCallMode,
)
from app.models.tool_meta import ToolResult, ToolResultStatus
from app.services.safe_tool_projection import SafeToolProjectionService
from app.services.tool_call_grant_resolver import (
    is_non_query_dynamic_tool,
    is_tool_allowed_by_grant,
    validate_scope_params,
)
from app.services.tool_call_grant_service import ToolCallGrantService
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry, ToolValidationError

logger = logging.getLogger(__name__)


@dataclass
class BoundToolCallResult:
    """Grant-bound tool result with safe projection (raw data not for LLM)."""

    result: ToolResult
    projection: SafeToolProjection
    attempt_id: str


@dataclass
class BoundToolExecutor:
    """Trusted executor that enforces grant scope before dispatch."""

    inner: ToolExecutor
    grant: ToolCallGrant
    grant_service: ToolCallGrantService
    registry: ToolRegistry
    projection_service: SafeToolProjectionService = field(repr=False)
    grant_token: str = field(repr=False, default="")

    @property
    def event_id(self) -> str:
        return self.grant.event_id

    @property
    def trusted_agent_name(self) -> str:
        return self.grant.execution_principal.agent_name

    async def call(
        self,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        *,
        agent_name: str | None = None,
        **kwargs: Any,
    ) -> BoundToolCallResult:
        del agent_name  # never trust caller-supplied identity
        params = dict(params)
        attempt = await self.grant_service.reserve_attempt(
            self.grant,
            tool_name=tool_name,
            params=params,
            event_id=event_id,
        )

        denial_reason = self._precheck(tool_name, params, event_id=event_id)
        if denial_reason is not None:
            await self.grant_service.finalize_attempt(
                attempt.attempt_id,
                status=ToolCallAttemptStatus.DENIED,
                denial_reason=denial_reason,
            )
            raise ToolCallGrantDeniedError(
                denial_reason,
                details={
                    "grant_id": self.grant.grant_id,
                    "tool_name": tool_name,
                    "attempt_id": attempt.attempt_id,
                },
            )

        try:
            self.registry.validate_input(tool_name, params)
        except ToolValidationError as exc:
            await self.grant_service.finalize_attempt(
                attempt.attempt_id,
                status=ToolCallAttemptStatus.DENIED,
                denial_reason=str(exc),
            )
            raise ToolCallGrantDeniedError(
                "tool input validation failed",
                details={"grant_id": self.grant.grant_id, "tool_name": tool_name},
            ) from exc

        result = await self.inner.call(
            tool_name,
            params,
            event_id,
            agent_name=self.trusted_agent_name,
            **kwargs,
        )
        projection = self.projection_service.project(
            tool_name,
            result,
            grant_id=self.grant.grant_id,
            attempt_id=attempt.attempt_id,
        )

        attempt_status = _attempt_status_for_result(result)
        await self.grant_service.finalize_attempt(
            attempt.attempt_id,
            status=attempt_status,
            result_status=result.status.value,
            projection_hash=projection.projection_hash,
        )

        sanitized = ToolResult(
            call_id=result.call_id,
            tool_name=result.tool_name,
            provider_name=result.provider_name,
            status=result.status,
            data=projection.data,
            error_detail=result.error_detail,
            execution_time_ms=result.execution_time_ms,
        )
        return BoundToolCallResult(
            result=sanitized,
            projection=projection,
            attempt_id=attempt.attempt_id,
        )

    def _precheck(
        self,
        tool_name: str,
        params: dict[str, Any],
        *,
        event_id: str,
    ) -> str | None:
        if self.grant.event_id != event_id:
            return "cross-event grant reuse denied"
        if self.grant.tenant_id and params.get("tenant_id"):
            if str(params["tenant_id"]) != self.grant.tenant_id:
                return "tenant mismatch"
        if is_non_query_dynamic_tool(self.registry, tool_name):
            return "dynamic non-query tools are forbidden"
        if not is_tool_allowed_by_grant(
            tool_name,
            scope=self.grant.scope,
            registry=self.registry,
        ):
            return "tool not in grant allow-list"
        registered = self.registry.get_tool(tool_name)
        if registered.tool_meta.tool_category is not ToolCategory.QUERY:
            return "only query tools allowed in dynamic path"
        return validate_scope_params(params, scope=self.grant.scope)

    def with_forged_agent_name(self, forged_name: str) -> BoundToolExecutor:
        """Return self — caller cannot replace trusted principal via params."""

        del forged_name
        return self


def _attempt_status_for_result(result: ToolResult) -> ToolCallAttemptStatus:
    if result.status is ToolResultStatus.TIMEOUT:
        return ToolCallAttemptStatus.TIMEOUT
    if result.status in {
        ToolResultStatus.SUCCESS,
        ToolResultStatus.PARTIAL_SUCCESS,
        ToolResultStatus.ACCEPTED,
    }:
        return ToolCallAttemptStatus.SUCCESS
    return ToolCallAttemptStatus.FAILED


__all__ = ["BoundToolCallResult", "BoundToolExecutor"]
