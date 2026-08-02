#!/usr/bin/env python3
"""LLM provider smoke test (ISSUE-106 / #609).

Usage:
  cd backend && uv run python ../scripts/llm_smoke_test.py

Never prints API keys or provider response bodies.
"""

from __future__ import annotations

import asyncio
import json
import sys


async def _run() -> int:
    from app.core.config import get_settings
    from app.core.llm.base import InMemoryLLMCallAuditRecorder, LLMMessage
    from app.core.llm.diagnostics import (
        classify_llm_error,
        probe_llm_provider,
        redact_base_url,
        reset_llm_probe_cache,
    )
    from app.core.llm.factory import get_llm_client
    from app.models.llm_provider import LLMProviderMode

    settings = get_settings()
    reset_llm_probe_cache()
    probe = await probe_llm_provider(settings, force=True)
    payload: dict[str, object] = {
        "mode": settings.llm_mode.strip().lower(),
        "base_url_redacted": redact_base_url(settings.llm_api_base_url),
        "primary_model": settings.llm_primary_model,
        "probe": probe.model_dump(mode="json"),
    }

    mode = settings.llm_mode.strip().lower()
    synthetic_status = "skipped"
    if mode == LLMProviderMode.MOCK.value:
        audit = InMemoryLLMCallAuditRecorder()
        client = get_llm_client(settings=settings, audit_recorder=audit)
        await client.chat(
            [LLMMessage(role="user", content="ping")],
            event_id="evt-llm-smoke",
            agent_name="LLMSmoke",
            prompt_key="llm_smoke",
        )
        synthetic_status = audit.entries[-1].status if audit.entries else "unknown"
    elif mode == LLMProviderMode.OPENAI_COMPATIBLE.value:
        audit = InMemoryLLMCallAuditRecorder()
        client = get_llm_client(settings=settings, audit_recorder=audit)
        try:
            await client.chat(
                [LLMMessage(role="user", content="ping")],
                event_id="evt-llm-smoke",
                agent_name="LLMSmoke",
                prompt_key="llm_smoke",
                max_tokens=8,
            )
            synthetic_status = audit.entries[-1].status if audit.entries else "unknown"
        except Exception as exc:  # noqa: BLE001 — smoke reports classification
            error_class, error_code = classify_llm_error(exc=exc)
            payload["synthetic_chat_error"] = {
                "error_class": error_class,
                "error_code": error_code,
            }
            synthetic_status = "error"
        finally:
            closer = getattr(client, "aclose", None)
            if closer is not None:
                await closer()

    payload["synthetic_chat_status"] = synthetic_status
    print(json.dumps(payload, ensure_ascii=False, indent=2))

    if mode == LLMProviderMode.MOCK.value:
        return 0 if synthetic_status == "success" else 1
    if probe.status == "error":
        return 1
    if synthetic_status not in {"success", "skipped"}:
        return 1
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(_run()))


if __name__ == "__main__":
    main()
