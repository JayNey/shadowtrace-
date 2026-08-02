"""Safe tool output projection — schema validate, truncate, redact (ISSUE-134)."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import orjson
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from app.core.sanitization import sanitize_data
from app.models.tool_call_grant import SafeToolProjection
from app.models.tool_meta import ToolMeta, ToolResult, ToolResultStatus
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

DEFAULT_MAX_FIELD_CHARS = 8_192
DEFAULT_MAX_RECORDS = 200
DEFAULT_MAX_TOTAL_BYTES = 256_000


class SafeToolProjectionService:
    """Validate and sanitize tool output before LLM/agent consumption."""

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        max_field_chars: int = DEFAULT_MAX_FIELD_CHARS,
        max_records: int = DEFAULT_MAX_RECORDS,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    ) -> None:
        self._registry = registry
        self._max_field_chars = max_field_chars
        self._max_records = max_records
        self._max_total_bytes = max_total_bytes

    def project(
        self,
        tool_name: str,
        result: ToolResult,
        *,
        grant_id: str,
        attempt_id: str,
    ) -> SafeToolProjection:
        meta = self._registry.get_tool(tool_name).tool_meta
        raw_data = dict(result.data or {})
        sanitized = sanitize_data(raw_data)
        bounded = self._bound_payload(sanitized)
        schema_errors = self._schema_errors(meta, bounded)
        taint_flags: list[str] = []
        trust_level = "verified"
        if schema_errors:
            trust_level = "untrusted"
            taint_flags.append("schema_validation_failed")
            bounded = {}
        if result.status not in {
            ToolResultStatus.SUCCESS,
            ToolResultStatus.PARTIAL_SUCCESS,
            ToolResultStatus.ACCEPTED,
        }:
            trust_level = "untrusted"
            taint_flags.append(f"tool_status:{result.status.value}")

        projection_hash = hashlib.sha256(
            orjson.dumps(
                {
                    "tool_name": tool_name,
                    "status": result.status.value,
                    "data": bounded,
                    "grant_id": grant_id,
                    "attempt_id": attempt_id,
                },
                option=orjson.OPT_SORT_KEYS,
            )
        ).hexdigest()

        return SafeToolProjection(
            tool_name=tool_name,
            status=result.status.value,
            data=bounded,
            provenance={
                "grant_id": grant_id,
                "attempt_id": attempt_id,
                "provider_name": result.provider_name,
                "call_id": result.call_id,
            },
            trust_level=trust_level,
            taint_flags=taint_flags,
            projection_hash=projection_hash,
        )

    def _schema_errors(self, meta: ToolMeta, data: dict[str, Any]) -> list[str]:
        schema = meta.output_schema
        if not schema:
            return []
        try:
            Draft202012Validator(schema).validate(data)
        except JsonSchemaValidationError as exc:
            return [str(exc.message)]
        return []

    def _bound_payload(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {"value": self._truncate_scalar(value)}

        records = value.get("records")
        if isinstance(records, list):
            value = dict(value)
            value["records"] = records[: self._max_records]
            for index, record in enumerate(value["records"]):
                if isinstance(record, dict):
                    value["records"][index] = self._truncate_mapping(record)

        bounded = self._truncate_mapping(value)
        encoded = orjson.dumps(bounded)
        if len(encoded) <= self._max_total_bytes:
            return bounded

        return {
            "truncated": True,
            "summary_keys": sorted(bounded.keys())[:32],
            "record_count": len(bounded.get("records") or []),
        }

    def _truncate_mapping(self, mapping: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, raw in mapping.items():
            if isinstance(raw, str):
                out[str(key)] = raw[: self._max_field_chars]
            elif isinstance(raw, list):
                out[str(key)] = raw[: self._max_records]
            elif isinstance(raw, dict):
                out[str(key)] = self._truncate_mapping(raw)
            else:
                out[str(key)] = self._truncate_scalar(raw)
        return out

    def _truncate_scalar(self, value: Any) -> Any:
        if isinstance(value, str):
            return value[: self._max_field_chars]
        return value


__all__ = ["SafeToolProjectionService"]
