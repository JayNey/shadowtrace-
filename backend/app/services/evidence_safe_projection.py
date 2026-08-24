"""Evidence raw_data sanitization and API-safe projection (ISSUE-269 / ID-SEC-003).

Ingest path: recursive allowlist + secret redaction before persistence.
Read path: API responses never serialize domain ``raw_data``; historical rows are
projected through ``EvidenceSafeProjection`` even when legacy blobs remain in DB.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any

import orjson

from app.core.sanitization import REDACTED, is_sensitive_key, redact_sensitive_text
from app.models.enums import EvidenceSource
from app.models.evidence import Evidence, EvidenceSafeProjection

logger = logging.getLogger(__name__)

_OBSERVATION_FIELD_ORDER = (
    "record_id",
    "action",
    "event_type",
    "result",
    "hostname",
    "account",
    "process",
    "cmdline",
    "file_name",
    "src_ip",
    "dst_ip",
    "dst_port",
    "domain",
    "query",
    "answer",
    "protocol",
    "indicator",
    "agent_status",
)
_MAX_OBSERVATION_FIELDS = 8
_MAX_OBSERVATION_VALUE_CHARS = 80

EVIDENCE_SAFE_PROJECTION_VERSION = "1.0"

MAX_SANITIZER_DEPTH = 16
MAX_SANITIZER_NODES = 256
MAX_SANITIZER_PAYLOAD_BYTES = 32_768

# Operational fields retained for downstream scoring / FP / conflict heuristics.
_EVIDENCE_RAW_ALLOWLIST = frozenset(
    {
        "record_id",
        "channel",
        "logged_at",
        "timestamp",
        "is_key_event",
        "is_conflict_seed",
        "account",
        "src_ip",
        "dst_ip",
        "dst_port",
        "hostname",
        "domain",
        "process",
        "file_name",
        "cmdline",
        "action",
        "event_type",
        "result",
        "confidence",
        "note",
        "variant",
        "provider_error_code",
        "change_window",
        "query",
        "answer",
        "qtype",
        "ip",
        "owner",
        "agent_status",
        "asset_group",
        "group",
        "asset_value",
        "business_criticality",
        "criticality",
        "indicator",
        "indicator_type",
        "malicious",
        "ti_malicious",
        "verdict",
        "severity",
        "risk_label",
        "dlp_blocked",
        "protocol",
    }
)

# Vendor / transport metadata never persisted or returned.
_VENDOR_METADATA_DENYLIST = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api_key",
        "apikey",
        "request_headers",
        "response_headers",
        "headers",
        "http_headers",
        "raw_result",
        "raw_payload",
        "raw_response",
        "provider_payload",
        "vendor_metadata",
        "session_token",
        "access_token",
        "refresh_token",
        "bearer",
        "credentials",
        "private_key",
        "secret",
        "password",
        "token",
    }
)

_PII_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
)
_PII_PHONE_RE = re.compile(
    r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}\b",
)
_PII_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


class EvidenceSanitizerError(ValueError):
    """Raised when evidence raw_data cannot be sanitized within policy limits."""


class _SanitizerBudget:
    __slots__ = ("node_count", "payload_bytes")

    def __init__(self) -> None:
        self.node_count = 0
        self.payload_bytes = 0

    def consume_node(self) -> None:
        self.node_count += 1
        if self.node_count > MAX_SANITIZER_NODES:
            raise EvidenceSanitizerError("evidence raw_data node budget exceeded")

    def consume_bytes(self, value: Any) -> None:
        if isinstance(value, str | bytes):
            self.payload_bytes += len(value)
        elif isinstance(value, Mapping | list | tuple | set | frozenset):
            try:
                self.payload_bytes += len(orjson.dumps(value))
            except Exception:
                self.payload_bytes += 1
        if self.payload_bytes > MAX_SANITIZER_PAYLOAD_BYTES:
            raise EvidenceSanitizerError("evidence raw_data payload budget exceeded")


def _normalize_key(key: object) -> str:
    return str(key).strip().lower()


def _is_denied_metadata_key(key: str) -> bool:
    lowered = _normalize_key(key)
    if lowered in _VENDOR_METADATA_DENYLIST:
        return True
    return is_sensitive_key(key)


def _is_allowed_field(key: str) -> bool:
    return _normalize_key(key) in _EVIDENCE_RAW_ALLOWLIST


def _redact_pii_text(value: str) -> str:
    cleaned = redact_sensitive_text(value)
    cleaned = _PII_EMAIL_RE.sub(REDACTED, cleaned)
    cleaned = _PII_SSN_RE.sub(REDACTED, cleaned)
    cleaned = _PII_PHONE_RE.sub(REDACTED, cleaned)
    return cleaned


def _sanitize_scalar(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return _redact_pii_text(value)
    if isinstance(value, bytes):
        return _redact_pii_text(value.decode("utf-8", errors="replace"))
    return _redact_pii_text(str(value))


def _sanitize_tree(
    value: Any,
    *,
    depth: int,
    budget: _SanitizerBudget,
    enforce_allowlist: bool,
) -> Any:
    if depth > MAX_SANITIZER_DEPTH:
        raise EvidenceSanitizerError("evidence raw_data depth budget exceeded")

    budget.consume_node()

    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            if enforce_allowlist and not _is_allowed_field(key):
                continue
            if _is_denied_metadata_key(key):
                cleaned[key] = REDACTED
                continue
            if is_sensitive_key(key):
                cleaned[key] = REDACTED
                continue
            # Nested mappings stay under the same allowlist (ISSUE-269): parents
            # like ``result`` must not re-open an unconstrained key space.
            cleaned[key] = _sanitize_tree(
                item,
                depth=depth + 1,
                budget=budget,
                enforce_allowlist=True,
            )
        budget.consume_bytes(cleaned)
        return cleaned

    if isinstance(value, list | tuple):
        cleaned_list = [
            _sanitize_tree(item, depth=depth + 1, budget=budget, enforce_allowlist=True)
            for item in value
        ]
        budget.consume_bytes(cleaned_list)
        return cleaned_list

    if isinstance(value, set | frozenset):
        cleaned_set = [
            _sanitize_tree(item, depth=depth + 1, budget=budget, enforce_allowlist=True)
            for item in value
        ]
        budget.consume_bytes(cleaned_set)
        return cleaned_set

    scalar = _sanitize_scalar(value)
    budget.consume_bytes(scalar)
    return scalar


def sanitize_evidence_raw_data(
    tool_name: str,
    record: Mapping[str, Any],
    *,
    enforce_allowlist: bool = True,
) -> dict[str, Any]:
    """Sanitize one provider record before persistence. Fail-closed on budget exceed."""
    del tool_name  # reserved for per-tool extensions; global allowlist covers mock tools.
    if not isinstance(record, Mapping):
        raise EvidenceSanitizerError("evidence record must be a mapping")
    budget = _SanitizerBudget()
    sanitized = _sanitize_tree(
        dict(record),
        depth=0,
        budget=budget,
        enforce_allowlist=enforce_allowlist,
    )
    if not isinstance(sanitized, dict):
        raise EvidenceSanitizerError("sanitized evidence record is not an object")
    return sanitized


def sanitize_evidence_raw_data_legacy(record: Mapping[str, Any]) -> dict[str, Any]:
    """Best-effort sanitizer for historical rows (allowlist + redact, no raise on empty)."""
    try:
        return sanitize_evidence_raw_data("legacy", record, enforce_allowlist=True)
    except EvidenceSanitizerError:
        logger.warning("legacy evidence raw_data exceeded budget; returning minimal redacted stub")
        return {"_sanitization_failed": True}


def _observation_value(value: Any) -> str | None:
    if value is None or isinstance(value, bool | dict | list | tuple | set | frozenset):
        return None
    text = _redact_pii_text(str(value)).strip()
    if not text:
        return None
    if len(text) > _MAX_OBSERVATION_VALUE_CHARS:
        return text[: _MAX_OBSERVATION_VALUE_CHARS - 1] + "…"
    return text


def project_observation_fields(raw_data: Mapping[str, Any] | None) -> dict[str, str]:
    """Compact sanitized source-record fields for UI; never includes raw_data."""
    if not isinstance(raw_data, Mapping) or not raw_data:
        return {}
    try:
        sanitized = sanitize_evidence_raw_data("observe", raw_data, enforce_allowlist=True)
    except EvidenceSanitizerError:
        sanitized = sanitize_evidence_raw_data_legacy(raw_data)
    fields: dict[str, str] = {}
    for key in _OBSERVATION_FIELD_ORDER:
        if key not in sanitized:
            continue
        rendered = _observation_value(sanitized[key])
        if rendered is None:
            continue
        fields[key] = rendered
        if len(fields) >= _MAX_OBSERVATION_FIELDS:
            break
    return fields


def project_evidence_for_api(item: Evidence) -> EvidenceSafeProjection:
    """Project one Evidence domain row to API-safe shape (no raw_data)."""
    return EvidenceSafeProjection(
        schema_version=EVIDENCE_SAFE_PROJECTION_VERSION,
        evidence_id=item.evidence_id,
        event_id=item.event_id,
        source=item.source
        if isinstance(item.source, EvidenceSource)
        else EvidenceSource(item.source),
        evidence_type=item.evidence_type,
        description=_redact_pii_text(item.description),
        confidence=item.confidence,
        timestamp=item.timestamp,
        related_entities=[_redact_pii_text(str(v)) for v in item.related_entities],
        source_ref=item.source_ref,
        mitre_technique=item.mitre_technique,
        is_conflicting=item.is_conflicting,
        observation_fields=project_observation_fields(
            item.raw_data if isinstance(item.raw_data, dict) else {}
        ),
    )


def project_evidence_list_for_api(evidence_list: list[Evidence]) -> list[EvidenceSafeProjection]:
    return [project_evidence_for_api(item) for item in evidence_list]


def sanitize_evidence_for_persist(item: Evidence) -> Evidence:
    """Defense-in-depth: re-sanitize raw_data and human-facing fields before DB upsert."""
    raw = item.raw_data if isinstance(item.raw_data, dict) else {}
    sanitized_raw = sanitize_evidence_raw_data("persist", raw, enforce_allowlist=True)
    description = _redact_pii_text(item.description)
    related = [_redact_pii_text(str(v)) for v in item.related_entities]
    if (
        sanitized_raw == raw
        and description == item.description
        and related == list(item.related_entities)
    ):
        return item
    return item.model_copy(
        update={
            "raw_data": sanitized_raw,
            "description": description,
            "related_entities": related,
        }
    )


__all__ = [
    "EVIDENCE_SAFE_PROJECTION_VERSION",
    "EvidenceSanitizerError",
    "project_evidence_for_api",
    "project_evidence_list_for_api",
    "project_observation_fields",
    "sanitize_evidence_for_persist",
    "sanitize_evidence_raw_data",
    "sanitize_evidence_raw_data_legacy",
]
