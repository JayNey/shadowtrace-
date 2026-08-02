"""LLM URL helpers (ISSUE-106)."""

from __future__ import annotations

from urllib.parse import urlparse


def normalize_llm_base_url(raw: str) -> str:
    """Normalize OpenAI-compatible base URL to the chat-completions prefix."""
    trimmed = raw.strip().rstrip("/")
    if trimmed.endswith("/chat/completions"):
        return trimmed[: -len("/chat/completions")].rstrip("/")
    return trimmed


def redact_base_url(raw: str) -> str:
    """Return a host-only URL safe for health/smoke output."""
    if not raw.strip():
        return ""
    parsed = urlparse(normalize_llm_base_url(raw))
    if not parsed.scheme or not parsed.netloc:
        return "[invalid-url]"
    return f"{parsed.scheme}://{parsed.netloc}"


__all__ = ["normalize_llm_base_url", "redact_base_url"]
