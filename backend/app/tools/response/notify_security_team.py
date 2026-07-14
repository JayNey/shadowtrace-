from typing import Any

from app.tools.response._common import execute_response_tool, response_tool_meta

TOOL_META = response_tool_meta("notify_security_team")


async def execute(params: dict[str, Any]) -> dict[str, Any]:
    return await execute_response_tool(TOOL_META.tool_name, params)
