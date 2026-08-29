"""Report generation prompt builders (ISSUE-036)."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.agents.report_section_builder import SECTION_KEYS
from app.core.llm.base import LLMMessage


class ReportGenerateLLMResponse(BaseModel):
    """Wire model so report_generate repair embeds a real schema."""

    model_config = ConfigDict(extra="ignore")

    title: str = ""
    summary: str = ""
    sections: dict[str, str] = Field(default_factory=dict)

    @field_validator("title", "summary", mode="before")
    @classmethod
    def _coerce_text(cls, value: Any) -> str:
        return "" if value is None else str(value)

    @field_validator("sections", mode="before")
    @classmethod
    def _coerce_sections(cls, value: Any) -> dict[str, str]:
        if not isinstance(value, dict):
            return {}
        out: dict[str, str] = {}
        for key, item in value.items():
            text = str(item).strip() if item is not None else ""
            if text:
                out[str(key)] = text
        return out


def build_report_messages(
    *,
    event_id: str,
    context_summary: dict[str, Any],
    draft_sections: dict[str, str],
) -> list[LLMMessage]:
    """Ask the LLM to refine a 15-section investigation report (JSON only)."""
    system = (
        "You are ShadowTrace ReportAgent, a senior SOC investigator. "
        "Produce a structured investigation report. Reply with JSON only. "
        "Do not invent entities, IPs, hosts, scores, or citation ids (cit-…) that "
        "are absent from the provided facts. Do not mint new cit- tokens. "
        "recommendations must contain 3 to 5 concrete next steps. "
        "Keep each section concise and evidence-grounded."
    )
    payload = {
        "event_id": event_id,
        "facts": context_summary,
        "draft_sections": draft_sections,
        "required_section_keys": list(SECTION_KEYS),
        "response_schema": {
            "title": "string",
            "summary": "string",
            "sections": {key: "markdown string" for key in SECTION_KEYS},
        },
    }
    user = (
        "Refine the investigation report. Return JSON shaped like:\n"
        '{"title":"...","summary":"...","sections":{'
        + ",".join(f'"{k}":"..."' for k in SECTION_KEYS)
        + "}}\n"
        "Use every required_section_keys entry. Prefer the draft text when facts "
        "are already complete; improve narrative quality for overview, "
        "attack_storyline, and recommendations.\n"
        f"Context:\n{json.dumps(payload, ensure_ascii=False)}"
    )
    return [
        LLMMessage(role="system", content=system),
        LLMMessage(role="user", content=user),
    ]
