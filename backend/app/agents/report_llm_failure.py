"""Structured LLM failure metadata for ReportAgent template fallback (ISSUE-104)."""

from __future__ import annotations

import asyncio
from typing import Any

from app.core.errors import ShadowTraceError
from app.core.sanitization import redact_sensitive_text, sanitize_data

_MAX_SAFE_MESSAGE_CHARS = 500
_FORBIDDEN_DETAIL_KEYS = frozenset(
    {
        "prompt",
        "prompt_text",
        "messages",
        "response_body",
        "raw_response",
        "response_content",
        "api_key",
    }
)

# Stable codes for non-ShadowTraceError failures (aligned with verify_agent taxonomy).
_EXC_ERROR_CODES: dict[type[BaseException], str] = {
    TimeoutError: "llm_timeout",
    asyncio.TimeoutError: "llm_timeout",
    ConnectionError: "llm_connection_error",
    OSError: "llm_connection_error",
    RuntimeError: "internal_error",
    ValueError: "validation_error",
    TypeError: "validation_error",
    KeyError: "validation_error",
}


def error_code_for_exception(exc: BaseException) -> str:
    """Return a stable error_code for *exc*."""
    if isinstance(exc, ShadowTraceError):
        return exc.error_code
    for exc_type, code in _EXC_ERROR_CODES.items():
        if isinstance(exc, exc_type):
            return code
    return "internal_error"


def _truncate_safe_text(value: str, *, max_chars: int = _MAX_SAFE_MESSAGE_CHARS) -> str:
    cleaned = redact_sensitive_text(value.strip())
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[: max_chars - 3] + "..."


def _safe_details(details: dict[str, Any] | None) -> dict[str, Any]:
    if not details:
        return {}
    filtered = {
        key: value
        for key, value in details.items()
        if key not in _FORBIDDEN_DETAIL_KEYS and not str(key).lower().endswith("_key")
    }
    sanitized = sanitize_data(filtered)
    if not isinstance(sanitized, dict):
        return {}
    return sanitized


def llm_failure_metadata(exc: BaseException) -> dict[str, Any]:
    """Build sanitized observability payload for template fallback."""
    error_code = error_code_for_exception(exc)
    raw_message = str(exc).strip()
    if not raw_message:
        raw_message = error_code.replace("_", " ")
    error_message = _truncate_safe_text(raw_message)

    http_status: int | None = None
    safe_details: dict[str, Any] = {}
    if isinstance(exc, ShadowTraceError):
        http_status = exc.details.get("http_status") if exc.details else None
        if http_status is None and exc.status_code not in {500}:
            http_status = exc.status_code
        safe_details = _safe_details(exc.details)

    return {
        "error_code": error_code,
        "error_message": error_message,
        "http_status": http_status,
        "details": safe_details,
    }


__all__ = ["error_code_for_exception", "llm_failure_metadata"]
