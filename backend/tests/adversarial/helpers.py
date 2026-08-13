"""Shared helpers for adversarial audit tests."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Iterable

from app.ingestion.source_ingester import SourceIngester
from app.models.enums import EventStatus, SourceObjectKind
from app.services.event_service import EventService
from tests.adversarial.audit_report import collect_entity_tokens
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
)


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
    """Normalize response-plan action targets for GROUND_TRUTH alignment checks."""
    targets: set[str] = set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        target = action.get("target")
        if isinstance(target, str) and target.strip():
            targets.add(target.strip().lower())
    return targets


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
    present = response_plan_targets(actions)
    return [item for item in required if item.lower() not in present]


def build_alert_corpus(*, alert_text: str = "", event_payload: dict[str, Any] | None = None) -> str:
    """Original alert / incident text available before LLM narrative (ISSUE-334)."""
    parts: list[str] = []
    if alert_text.strip():
        parts.append(alert_text.strip())
    if not event_payload:
        return "\n".join(parts)

    title = str(event_payload.get("title") or "").strip()
    if title:
        parts.append(title)

    normalized = event_payload.get("normalized")
    if isinstance(normalized, dict):
        for key in (
            "description",
            "account",
            "hostname",
            "secondary_host",
            "src_ip",
            "internal_ip",
            "domain",
            "file",
        ):
            value = normalized.get(key)
            if value:
                parts.append(str(value))
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
            has_source_refs = bool(entity.get("source_refs"))
            for value in _entity_search_values(entity):
                yield value, has_source_refs


def _is_source_projection_hit(token: str, *, triage_ctx: dict[str, Any]) -> bool:
    needle = token.lower()
    for value, has_source_refs in _iter_structured_entities(triage_ctx):
        if has_source_refs and value.lower() == needle:
            return True
    return False


def is_text_understanding_hit(
    token: str,
    *,
    alert_corpus: str,
    triage_ctx: dict[str, Any],
) -> bool:
    """Count entity/indicator only when grounded in alert text or source merge (ISSUE-334)."""
    needle = token.lower()
    if needle in alert_corpus.lower():
        return True
    return _is_source_projection_hit(token, triage_ctx=triage_ctx)


def build_narrative_corpus(
    *,
    triage_ctx: dict[str, Any],
    evidence_ctx: dict[str, Any],
    report_ctx: dict[str, Any],
    extra_sources: list[Any] | None = None,
) -> str:
    """LLM narrative fields where prompt-appendix echo may appear."""
    sources: list[Any] = [
        {"decision_summary": triage_ctx.get("decision_summary")},
        evidence_ctx,
        report_ctx,
    ]
    if extra_sources:
        sources.extend(extra_sources)
    return "\n".join(collect_entity_tokens(sources)).lower()


@dataclass(frozen=True, slots=True)
class SignalAuditResult:
  required: tuple[str, ...]
  text_understanding_hits: tuple[str, ...]
  source_projection_hits: tuple[str, ...]
  echo_only_hits: tuple[str, ...]
  text_understanding_missing: tuple[str, ...]

  @property
  def substring_hits(self) -> tuple[str, ...]:
    return self.text_understanding_hits + self.echo_only_hits


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
        if is_text_understanding_hit(token, alert_corpus=alert_corpus, triage_ctx=triage_ctx):
            understanding.append(token)
            if _is_source_projection_hit(token, triage_ctx=triage_ctx):
                source_projection.append(token)
            continue
        if token.lower() in narrative_corpus:
            echo_only.append(token)
        missing.append(token)

    return SignalAuditResult(
        required=tuple(required),
        text_understanding_hits=tuple(understanding),
        source_projection_hits=tuple(source_projection),
        echo_only_hits=tuple(echo_only),
        text_understanding_missing=tuple(missing),
    )


def block_ip_reason_destination_mislabels(
    actions: list[dict[str, object]] | tuple[dict[str, object], ...],
) -> list[dict[str, str]]:
    """Weak guard: block_ip reason must not label a source IP as destination (ISSUE-327/334)."""
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
        target = str(action.get("target") or "")
        parameters = action.get("parameters")
        normalized_field = ""
        if isinstance(parameters, dict):
            normalized_field = str(parameters.get("normalized_field") or "")
        gaps.append(
            {
                "target": target,
                "reason": reason[:240],
                "normalized_field": normalized_field,
            }
        )
    return gaps
