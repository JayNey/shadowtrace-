"""Extract JSON objects from glm-style messy completions."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, Field

from app.core.llm.json_extract import (
    JsonExtractError,
    coerce_payload_for_model,
    extract_json_object,
)


class _Draft(BaseModel):
    rule_summary: str
    alert_signature: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class _Report(BaseModel):
    title: str = ""
    summary: str = ""
    sections: dict[str, str] = Field(default_factory=dict)


def test_extract_plain_object() -> None:
    assert extract_json_object('{"ok": true, "n": 1}') == {"ok": True, "n": 1}


def test_extract_markdown_fence() -> None:
    raw = '```json\n{"event_type":"host_compromise","confidence":0.87}\n```'
    assert extract_json_object(raw) == {
        "event_type": "host_compromise",
        "confidence": 0.87,
    }


def test_extract_think_tags_then_object() -> None:
    raw = '<think>planning</think>\n{"ok": true}'
    assert extract_json_object(raw) == {"ok": True}


def test_extract_extra_data_after_object() -> None:
    raw = '{"event_type":"other","confidence":0.4} thanks'
    assert extract_json_object(raw) == {"event_type": "other", "confidence": 0.4}


def test_extract_prefixed_commentary() -> None:
    raw = 'Here is the JSON:\n```json\n{"answer":"confirmed_threat","references":[]}\n```\n'
    assert extract_json_object(raw)["answer"] == "confirmed_threat"


def test_extract_single_element_array() -> None:
    assert extract_json_object('[{"ok": true}]') == {"ok": True}


def test_extract_empty_and_think_only_are_empty_content() -> None:
    with pytest.raises(JsonExtractError) as empty:
        extract_json_object("   ")
    assert empty.value.error_class == "empty_content"
    with pytest.raises(JsonExtractError) as think_only:
        extract_json_object("<think>no answer</think>")
    assert think_only.value.error_class == "empty_content"


def test_extract_non_object_is_invalid() -> None:
    with pytest.raises(JsonExtractError) as exc:
        extract_json_object("not-json{{{")
    assert exc.value.error_class == "invalid_json"


def test_coerce_unwraps_data_envelope() -> None:
    payload = {
        "data": {
            "rule_summary": "change window",
            "alert_signature": "ops-change-bot",
            "confidence": 0.9,
        }
    }
    assert coerce_payload_for_model(payload, _Draft)["rule_summary"] == "change window"


def test_coerce_unwraps_report_envelope() -> None:
    payload = {"result": {"title": "t", "summary": "s", "sections": {"overview": "o"}}}
    coerced = coerce_payload_for_model(payload, _Report)
    assert coerced["title"] == "t"
    assert coerced["sections"]["overview"] == "o"
