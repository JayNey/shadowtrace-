"""Bounded content projection builder (ISSUE-133 / #639 Phase A)."""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

import orjson

from app.core.errors import ValidationError
from app.core.sanitization import sanitize_data
from app.models.agent_task import (
    ALLOWLISTED_EVENT_CONTEXT_FIELDS,
    MAX_PROJECTION_BYTES,
    AgentTaskContextRef,
    ContentProjection,
)

logger = logging.getLogger(__name__)

_INJECTION_HINT_RE = re.compile(
    r"(?i)(ignore\s+(all\s+)?(previous|prior)\s+instructions|"
    r"ignore\s+all\s+rules|"
    r"disregard\s+(all\s+)?(previous|prior)\s+instructions|"
    r"system\s*:\s*)"
)

_FORBIDDEN_KEYS = frozenset(
    {
        "thought",
        "chain_of_thought",
        "raw_prompt",
        "raw_response",
        "decision_trace",
        "cot",
    }
)


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def projection_hash(fields: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(fields)).hexdigest()


def _contains_injection_hint(value: str) -> bool:
    return bool(_INJECTION_HINT_RE.search(value))


def _scan_injection(value: Any) -> bool:
    if isinstance(value, str):
        return _contains_injection_hint(value)
    if isinstance(value, dict):
        return any(_scan_injection(item) for item in value.values())
    if isinstance(value, list):
        return any(_scan_injection(item) for item in value)
    return False


def _strip_forbidden_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_forbidden_keys(item)
            for key, item in value.items()
            if str(key).lower() not in _FORBIDDEN_KEYS
        }
    if isinstance(value, list):
        return [_strip_forbidden_keys(item) for item in value[:200]]
    if isinstance(value, str):
        return value[:8192]
    return value


class ContentProjectionService:
    """Build schema-validated bounded projections from allowlisted context slices."""

    def __init__(self, *, max_bytes: int = MAX_PROJECTION_BYTES) -> None:
        self._max_bytes = max_bytes

    def build(
        self,
        *,
        projection_kind: str,
        raw_fields: dict[str, Any],
        source_refs: list[AgentTaskContextRef],
    ) -> ContentProjection:
        for ref in source_refs:
            if ref.ref_kind == "event_context_field" and ref.ref_id not in ALLOWLISTED_EVENT_CONTEXT_FIELDS:
                raise ValidationError(
                    f"projection source ref not allowlisted: {ref.ref_id}",
                    error_code="validation_error",
                )

        sanitized = sanitize_data(_strip_forbidden_keys(dict(raw_fields)))
        bounded = self._bound_payload(sanitized)
        byte_size = len(_canonical_bytes(bounded))
        if byte_size > self._max_bytes:
            raise ValidationError(
                "content projection exceeds size limit",
                error_code="validation_error",
                details={"byte_size": byte_size, "max_bytes": self._max_bytes},
            )
        if _scan_injection(bounded):
            raise ValidationError(
                "content projection rejected: prompt injection suspect",
                error_code="validation_error",
            )

        return ContentProjection(
            projection_kind=projection_kind,
            fields=bounded,
            source_refs=source_refs,
            byte_size=byte_size,
        )

    def _bound_payload(self, value: dict[str, Any]) -> dict[str, Any]:
        bounded: dict[str, Any] = {}
        for key, item in list(value.items())[:64]:
            token = str(key)[:128]
            if token.lower() in _FORBIDDEN_KEYS:
                continue
            if isinstance(item, str):
                bounded[token] = item[:8192]
            elif isinstance(item, (int, float, bool)) or item is None:
                bounded[token] = item
            elif isinstance(item, dict):
                bounded[token] = self._bound_payload(item)
            elif isinstance(item, list):
                bounded[token] = item[:200]
            else:
                bounded[token] = str(item)[:512]
        return bounded


__all__ = ["ContentProjectionService", "projection_hash"]
