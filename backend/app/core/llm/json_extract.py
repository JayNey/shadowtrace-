"""Recover a JSON object from messy chat-completions content.

Live glm-5.2 / Ark coding responses often wrap the object in markdown fences,
``<think>`` blocks, trailing commentary, or a single-key envelope. ``json.loads``
on the raw string then fails with ``Expecting value`` / ``Extra data`` and the
agent falls back to templates even though the object is present.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel

_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*\n?(.*?)```", re.DOTALL)
_THINK_RE = re.compile(
    r"<(?:think|thinking|reason|reasoning)>.*?</(?:think|thinking|reason|reasoning)>",
    re.DOTALL | re.IGNORECASE,
)
_WRAPPER_KEYS = ("data", "result", "output", "response", "json", "payload", "content")


class JsonExtractError(ValueError):
    """Structured extract failure so callers can map empty vs illegal JSON."""

    def __init__(self, message: str, *, error_class: str) -> None:
        super().__init__(message)
        self.error_class = error_class


def extract_json_object(text: str) -> dict[str, Any]:
    """Return the first JSON object embedded in ``text``.

    Raises ``JsonExtractError`` with ``error_class`` ``empty_content`` or
    ``invalid_json``.
    """

    if text is None:
        raise JsonExtractError("empty completion content", error_class="empty_content")
    stripped = _strip_noise(text)
    if not stripped:
        raise JsonExtractError("empty completion content", error_class="empty_content")

    candidates = _candidate_bodies(stripped)
    last_error: Exception | None = None
    for candidate in candidates:
        try:
            return _decode_object(candidate)
        except (json.JSONDecodeError, ValueError) as exc:
            last_error = exc
    detail = str(last_error) if last_error is not None else "no JSON object found"
    raise JsonExtractError(detail, error_class="invalid_json") from last_error


def coerce_payload_for_model(
    payload: dict[str, Any],
    response_model: type[BaseModel] | None,
) -> dict[str, Any]:
    """Unwrap a single envelope when the wire model’s keys are nested."""

    if response_model is None:
        return payload
    model_fields = set(response_model.model_fields)
    required = {name for name, field in response_model.model_fields.items() if field.is_required()}
    if required and required.issubset(payload.keys()):
        return payload
    if not required and (model_fields & payload.keys()):
        return payload
    for key in _WRAPPER_KEYS:
        inner = payload.get(key)
        if not isinstance(inner, dict):
            continue
        if required and required.issubset(inner.keys()):
            return inner
        if not required and (model_fields & inner.keys()):
            return inner
    nested = [value for value in payload.values() if isinstance(value, dict)]
    if len(nested) == 1:
        inner = nested[0]
        if required and required.issubset(inner.keys()):
            return inner
        if not required and (model_fields & inner.keys()) and not (model_fields & payload.keys()):
            return inner
    return payload


def _strip_noise(text: str) -> str:
    cleaned = text.lstrip("\ufeff")
    cleaned = _THINK_RE.sub("", cleaned)
    return cleaned.strip()


def _candidate_bodies(text: str) -> list[str]:
    bodies: list[str] = []
    for match in _FENCE_RE.finditer(text):
        inner = match.group(1).strip()
        if inner:
            bodies.append(inner)
    bodies.append(text)
    # Preserve order, drop duplicates.
    seen: set[str] = set()
    unique: list[str] = []
    for body in bodies:
        if body not in seen:
            seen.add(body)
            unique.append(body)
    return unique


def _decode_object(candidate: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError:
        start_obj = candidate.find("{")
        start_arr = candidate.find("[")
        starts = [index for index in (start_obj, start_arr) if index >= 0]
        if not starts:
            raise
        payload, _end = decoder.raw_decode(candidate[min(starts) :])
    if isinstance(payload, list):
        dicts = [item for item in payload if isinstance(item, dict)]
        if len(dicts) == 1 and len(payload) == 1:
            payload = dicts[0]
        else:
            raise ValueError("top-level JSON must be an object")
    if not isinstance(payload, dict):
        raise ValueError("top-level JSON must be an object")
    return payload


__all__ = [
    "JsonExtractError",
    "coerce_payload_for_model",
    "extract_json_object",
]
