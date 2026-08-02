"""Named compatibility path for fixed Evidence queries (ISSUE-134)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from app.core.config import Settings, get_settings
from app.core.errors import ToolCallGrantUnavailableError
from app.models.enums import ToolCategory
from app.models.tool_call_grant import (
    EVIDENCE_COMPATIBILITY_POLICY_VERSION,
    EVIDENCE_COMPATIBILITY_QUERY_TOOLS,
)
from app.models.tool_meta import RoutingKind, ToolResult
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

COMPATIBILITY_PATH_NAME = "evidence_fixed_query_compat"


@dataclass
class CompatibilityQueryToolPath:
    """Explicit, observable baseline path for fixed Evidence query tools."""

    inner: ToolExecutor
    registry: ToolRegistry
    settings: Settings | None = None

    @property
    def policy_version(self) -> str:
        return EVIDENCE_COMPATIBILITY_POLICY_VERSION

    @property
    def path_name(self) -> str:
        return COMPATIBILITY_PATH_NAME

    def _settings(self) -> Settings:
        return self.settings or get_settings()

    async def call(
        self,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        *,
        agent_name: str = "evidence_agent",
        **kwargs: Any,
    ) -> ToolResult:
        settings = self._settings()
        if not settings.tool_call_compatibility_path_enabled:
            raise ToolCallGrantUnavailableError(
                "compatibility path disabled",
                details={"path": self.path_name},
            )

        if tool_name not in EVIDENCE_COMPATIBILITY_QUERY_TOOLS:
            raise ToolCallGrantUnavailableError(
                "tool not allowed on compatibility path",
                details={"tool_name": tool_name, "path": self.path_name},
            )

        registered = self.registry.get_tool(tool_name)
        meta = registered.tool_meta
        if meta.tool_category is not ToolCategory.QUERY:
            raise ToolCallGrantUnavailableError(
                "compatibility path allows query tools only",
                details={"tool_name": tool_name},
            )
        if meta.routing_kind is RoutingKind.DISPOSITION_ONLY:
            raise ToolCallGrantUnavailableError(
                "disposition-only tools forbidden on compatibility path",
                details={"tool_name": tool_name},
            )

        logger.info(
            "compatibility tool path=%s policy=%s tool=%s event_id=%s",
            self.path_name,
            self.policy_version,
            tool_name,
            event_id,
        )
        return await self.inner.call(
            tool_name,
            dict(params),
            event_id,
            agent_name=agent_name,
            **kwargs,
        )


__all__ = ["COMPATIBILITY_PATH_NAME", "CompatibilityQueryToolPath"]
