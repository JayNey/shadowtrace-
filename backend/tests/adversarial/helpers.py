"""Shared helpers for adversarial audit tests."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from app.ingestion.source_ingester import SourceIngester
from app.models.enums import EventStatus, SourceObjectKind
from app.services.event_service import EventService
from tests.adversarial.scenario_credential_db_staging_exfil import GROUND_TRUTH, INCIDENT_ID

ALL_SOURCE_KINDS = [
    SourceObjectKind.INCIDENT,
    SourceObjectKind.ALERT,
    SourceObjectKind.ASSET,
    SourceObjectKind.LOG,
]

_ENTITY_VALUE_FIELDS = (
    "username",
    "hostname",
    "address",
    "fqdn",
    "name",
    "path",
    "ip",
)

_NARRATIVE_KEYS = (
    "decision_summary",
    "reasoning",
    "summary",
    "executive_summary",
    "narrative",
    "analysis",
    "conclusion",
)

_SOURCE_NORMALIZED_FIELDS = frozenset({"src_ip", "source_ip", "internal_ip", "src"})


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def strict_disposition_targets_enabled() -> bool:
    """Gate ISSUE-328 DB isolation targets until real containment lands (ISSUE-334)."""
    return _truthy_env("ADVERSARIAL_STRICT_DISPOSITION_TARGETS")


def _source_object_id(ref) -> str:
    if ref is None:
        return ""
    if hasattr(ref, "source_object_id"):
        return str(ref.source_object_id or "")
    if hasattr(ref, "model_dump"):
        return str(ref.model_dump(mode="json").get("source_object_id") or "")
    if isinstance(ref, dict):
        return str(ref.get("source_object_id") or "")
    return ""


async def ingest_true_positive_event(
    source_adapter,
    source_ingester: SourceIngester,
    event_service: EventService,
    *,
    batch_size: int = 50,
) -> str:
    """Poll the noisy adversarial scenario and return the true-positive event_id."""
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=batch_size)
    if summary.rejected:
        raise AssertionError(f"adversarial ingest rejected rows: {summary.errors}")

    listed = await event_service.list_events(status=EventStatus.NEW)
    if listed.total < 1:
        raise AssertionError("expected at least one NEW event from adversarial poll")

    true_incident_id = str(GROUND_TRUTH.get("true_positive_incident_id") or INCIDENT_ID)
    for item in listed.items:
        if _source_object_id(item.creation_source_ref) == true_incident_id:
            return item.event_id

    required = [item for item in listed.items if item.disposition_policy.value == "required"]
    pool = required or list(listed.items)
    event = max(pool, key=lambda row: (row.severity.value, row.risk_score or 0))
    return event.event_id


def response_plan_targets(
    actions: list[dict[str, object]] | tuple[dict[str, object], ...],
) -> set[str]:
    """Normalize response-plan action targets (legacy target-only view)."""
    targets: set[str] = set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        target = action.get("target")
        if isinstance(target, str) and target.strip():
            targets.add(target.strip().lower())
    return targets


def response_plan_tool_targets(
    actions: list[dict[str, object]] | tuple[dict[str, object], ...],
) -> set[tuple[str, str]]:
    """Normalize ``(tool_name, target)`` pairs for containment alignment checks."""
    pairs: set[tuple[str, str]] = set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        tool = str(action.get("tool_name") or "").strip().lower()
        target = str(action.get("target") or "").strip().lower()
        if tool and target:
            pairs.add((tool, target))
    return pairs


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)


def containment_tool_for_target(target: str, ground_truth: dict[str, object]) -> str:
    """Map a GROUND_TRUTH target to its required containment tool (tool×target contract)."""
    target_key = target.strip().lower()
    mapped = ground_truth.get("response_containment_tools")
    if isinstance(mapped, dict):
        for raw_key, raw_tool in mapped.items():
            tool = str(raw_tool or "").strip().lower()
            if tool and str(raw_key).strip().lower() == target_key:
                return tool
    entities = [
        str(item).strip()
        for item in (ground_truth.get("must_identify_entities") or [])
        if str(item).strip()
    ]
    indicators = [
        str(item).strip()
        for item in (ground_truth.get("must_identify_indicators") or [])
        if str(item).strip()
    ]
    if entities and target_key == entities[0].lower():
        return "disable_account"
    if target_key in {item.lower() for item in entities[1:]}:
        return "isolate_host"
    if target_key in {item.lower() for item in indicators}:
        indicator = next(item for item in indicators if item.lower() == target_key)
        return "block_ip" if _looks_like_ip(indicator) else "block_domain"
    return "isolate_host"


def format_disposition_gap(tool: str, target: str) -> str:
    """Stable ``tool×target`` label for artifacts and human side-notes."""
    return f"{tool.strip().lower()}×{target.strip()}"


def disposition_gap_target_label(gap: str) -> str:
    """Extract the target token from a ``tool×target`` gap label."""
    if "×" in gap:
        return gap.split("×", 1)[1]
    return gap


def _gated_response_targets(ground_truth: dict[str, object]) -> set[str]:
    gated = {
        str(item).strip().lower()
        for item in (ground_truth.get("must_response_targets_gated") or [])
        if str(item).strip()
    }
    return gated


def enforced_must_response_targets(ground_truth: dict[str, object]) -> list[str]:
    """Targets that hard-fail today; gated entries wait for ISSUE-328 unless strict env is on."""
    required = [
        str(item).strip()
        for item in (ground_truth.get("must_response_targets") or [])
        if str(item).strip()
    ]
    if not required:
        required = [
            str(item).strip()
            for item in (ground_truth.get("must_identify_entities") or [])
            if str(item).strip()
        ]
    if strict_disposition_targets_enabled():
        return required
    gated = _gated_response_targets(ground_truth)
    return [item for item in required if item.lower() not in gated]


def missing_response_targets(
    *,
    ground_truth: dict[str, object],
    actions: list[dict[str, object]] | tuple[dict[str, object], ...],
    enforce_gated: bool | None = None,
) -> list[str]:
    """Return required containment targets absent from the response plan."""
    if enforce_gated is None:
        required = enforced_must_response_targets(ground_truth)
    else:
        all_targets = [
            str(item).strip()
            for item in (ground_truth.get("must_response_targets") or [])
            if str(item).strip()
        ]
        if not all_targets:
            all_targets = [
                str(item).strip()
                for item in (ground_truth.get("must_identify_entities") or [])
                if str(item).strip()
            ]
        gated = _gated_response_targets(ground_truth)
        required = (
            all_targets
            if enforce_gated
            else [item for item in all_targets if item.lower() not in gated]
        )
    present = response_plan_tool_targets(actions)
    gaps: list[str] = []
    for item in required:
        tool = containment_tool_for_target(item, ground_truth)
        if (tool, item.strip().lower()) not in present:
            gaps.append(format_disposition_gap(tool, item))
    return gaps


def build_alert_corpus(*, alert_text: str = "", event_payload: dict[str, Any] | None = None) -> str:
    """Original alert narrative (title / description) before LLM or structured merge."""
    parts: list[str] = []
    seen: set[str] = set()

    def _add(raw: object) -> None:
        text = str(raw or "").strip()
        if text and text not in seen:
            seen.add(text)
            parts.append(text)

    _add(alert_text)
    if not event_payload:
        return "\n".join(parts)
    _add(event_payload.get("title"))
    _add(event_payload.get("description"))
    return "\n".join(parts)


def _entity_search_values(entity: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for field in _ENTITY_VALUE_FIELDS:
        raw = entity.get(field)
        if raw is not None and str(raw).strip():
            values.append(str(raw).strip())
    return values


def _iter_structured_entities(triage_ctx: dict[str, Any]) -> Iterable[tuple[str, bool]]:
    entities = triage_ctx.get("entities")
    if not isinstance(entities, dict):
        return
    for category in (
        "accounts",
        "hosts",
        "ips",
        "domains",
        "processes",
        "files",
    ):
        rows = entities.get(category)
        if not isinstance(rows, list):
            continue
        for entity in rows:
            if not isinstance(entity, dict):
                continue
            is_source = _entity_has_source_provenance(entity)
            for value in _entity_search_values(entity):
                yield value, is_source


def _entity_has_source_provenance(entity: dict[str, Any]) -> bool:
    attrs = entity.get("attributes")
    if not isinstance(attrs, dict):
        return False
    return str(attrs.get("provenance") or "").strip().lower() == "source"


def _is_source_projection_hit(token: str, *, triage_ctx: dict[str, Any]) -> bool:
    needle = token.lower()
    for value, is_source in _iter_structured_entities(triage_ctx):
        if is_source and value.lower() == needle:
            return True
    return False


def is_text_understanding_hit(token: str, *, alert_corpus: str) -> bool:
    """Count as text understanding only when grounded in original alert narrative."""
    needle = token.strip().lower()
    if not needle:
        return False
    return needle in alert_corpus.lower()


def _top_level_narrative_texts(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    texts: list[str] = []
    for key in _NARRATIVE_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            texts.append(value.strip())
    sections = payload.get("sections")
    if isinstance(sections, list):
        for section in sections:
            if not isinstance(section, dict):
                continue
            for key in ("content", "summary", "title"):
                value = section.get(key)
                if isinstance(value, str) and value.strip():
                    texts.append(value.strip())
    return texts


def build_narrative_corpus(
    *,
    triage_ctx: dict[str, Any],
    evidence_ctx: dict[str, Any],
    report_ctx: dict[str, Any],
    extra_sources: list[Any] | None = None,
) -> str:
    """LLM narrative fields where prompt-appendix echo may appear."""
    texts = (
        _top_level_narrative_texts(triage_ctx)
        + _top_level_narrative_texts(evidence_ctx)
        + _top_level_narrative_texts(report_ctx)
    )
    if extra_sources:
        for source in extra_sources:
            if isinstance(source, dict):
                texts.extend(_top_level_narrative_texts(source))
            elif isinstance(source, str) and source.strip():
                texts.append(source.strip())
    return "\n".join(texts).lower()


@dataclass(frozen=True, slots=True)
class SignalAuditResult:
    required: tuple[str, ...]
    text_understanding_hits: tuple[str, ...]
    source_projection_hits: tuple[str, ...]
    echo_only_hits: tuple[str, ...]
    text_understanding_missing: tuple[str, ...]


def opaque_scorecard_tokens(ground_truth: dict[str, object]) -> tuple[str, ...]:
    """Ground-truth entities/indicators that this scenario's alert title must omit."""
    tokens: list[str] = []
    for key in ("must_identify_entities", "must_identify_indicators"):
        for item in ground_truth.get(key) or []:
            text = str(item).strip()
            if text:
                tokens.append(text)
    return tuple(tokens)


def assert_opaque_alert_quality(
    *,
    alert_corpus: str,
    entity_audit: SignalAuditResult,
    indicator_audit: SignalAuditResult,
    opaque_tokens: Iterable[str],
) -> None:
    """Pin source/echo buckets so they cannot fill text-understanding credit.

    Live tests must assert tokens are absent from the original alert corpus;
    checking ``source_projection_hits - understanding`` against ``entities_found``
    is identity-true when ``entities_found`` is copied from understanding hits.
    """
    corpus_lower = alert_corpus.lower()
    audits = (entity_audit, indicator_audit)
    for token in opaque_tokens:
        needle = str(token).strip()
        if not needle:
            continue
        assert needle.lower() not in corpus_lower, (
            f"ISSUE-334: opaque alert corpus must not contain {needle!r}; "
            "ingest leaked a source field into title/description"
        )
        for audit in audits:
            if needle not in audit.required:
                continue
            assert needle not in audit.text_understanding_hits, (
                f"ISSUE-334: {needle!r} must not receive text-understanding credit"
            )
            assert needle in audit.text_understanding_missing, (
                f"ISSUE-334: {needle!r} must be listed in text_understanding_missing"
            )
    for audit in audits:
        assert set(audit.echo_only_hits).isdisjoint(set(audit.text_understanding_hits)), (
            "ISSUE-334: prompt echo must not count as text understanding"
        )
        for token in audit.source_projection_hits:
            if token in audit.text_understanding_hits:
                continue
            assert token in audit.text_understanding_missing, (
                "ISSUE-334: source projection must not fill text-understanding credit; "
                f"token={token!r} missing={audit.text_understanding_missing}"
            )


def audit_required_signals(
    *,
    required: list[str],
    alert_corpus: str,
    triage_ctx: dict[str, Any],
    narrative_corpus: str,
) -> SignalAuditResult:
    understanding: list[str] = []
    source_projection: list[str] = []
    echo_only: list[str] = []
    missing: list[str] = []

    for raw in required:
        token = str(raw).strip()
        if not token:
            continue
        in_alert = is_text_understanding_hit(token, alert_corpus=alert_corpus)
        in_source = _is_source_projection_hit(token, triage_ctx=triage_ctx)
        if in_alert:
            understanding.append(token)
        if in_source:
            source_projection.append(token)
        if not in_alert and token.lower() in narrative_corpus:
            echo_only.append(token)
        if not in_alert:
            missing.append(token)

    return SignalAuditResult(
        required=tuple(required),
        text_understanding_hits=tuple(understanding),
        source_projection_hits=tuple(source_projection),
        echo_only_hits=tuple(echo_only),
        text_understanding_missing=tuple(missing),
    )


def _block_ip_normalized_field(
    action: dict[str, object],
    *,
    triage_ctx: dict[str, Any] | None = None,
) -> str:
    """Resolve src/dst role from action dump or matching triage IP entity."""
    parameters = action.get("parameters")
    if isinstance(parameters, dict):
        raw = str(parameters.get("normalized_field") or "").strip()
        if raw:
            return raw
    attributes = action.get("attributes")
    if isinstance(attributes, dict):
        raw = str(attributes.get("normalized_field") or "").strip()
        if raw:
            return raw
    hints = action.get("source_hints")
    if isinstance(hints, dict):
        raw = str(hints.get("normalized_field") or "").strip()
        if raw:
            return raw
    target = str(action.get("target") or "").strip().lower()
    entities = triage_ctx.get("entities") if isinstance(triage_ctx, dict) else None
    if not target or not isinstance(entities, dict):
        return ""
    rows = entities.get("ips")
    if not isinstance(rows, list):
        return ""
    for ip in rows:
        if not isinstance(ip, dict):
            continue
        address = str(ip.get("address") or ip.get("ip") or "").strip().lower()
        if address != target:
            continue
        attrs = ip.get("attributes") if isinstance(ip.get("attributes"), dict) else {}
        return str(attrs.get("normalized_field") or "").strip()
    return ""


def block_ip_reason_destination_mislabels(
    actions: list[dict[str, object]] | tuple[dict[str, object], ...],
    *,
    triage_ctx: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Weak guard: only flag src_ip (etc.) labeled as destination in block_ip reason."""
    gaps: list[dict[str, str]] = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        if str(action.get("tool_name") or "") != "block_ip":
            continue
        reason = str(action.get("reason") or "")
        reason_lower = reason.lower()
        if "destination" not in reason_lower and "dest " not in reason_lower:
            continue
        normalized_field = _block_ip_normalized_field(action, triage_ctx=triage_ctx)
        if normalized_field.strip().lower() not in _SOURCE_NORMALIZED_FIELDS:
            continue
        gaps.append(
            {
                "target": str(action.get("target") or ""),
                "reason": reason[:240],
                "normalized_field": normalized_field,
            }
        )
    return gaps
