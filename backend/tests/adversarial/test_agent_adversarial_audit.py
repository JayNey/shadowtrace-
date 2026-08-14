"""Dynamic adversarial audit — ingest a fresh Mock XDR scenario and score agent output.

Run (requires Postgres + Redis, same as integration tests):

    cd backend
    uv run --frozen python -m pytest tests/adversarial/test_agent_adversarial_audit.py -v -s

For a closer-to-production evaluation, set a real LLM before running:

    LLM_MODE=live LLM_API_BASE_URL=... LLM_API_KEY=... \\
      uv run --frozen python -m pytest tests/adversarial/test_agent_adversarial_audit.py -v -s

Reports are written to ``tests/adversarial/artifacts/latest_audit.json``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.ingestion.source_ingester import SourceIngester
from app.models.enums import EventStatus
from app.services.context_service import EventContextStore
from app.services.event_service import EventService
from app.services.evidence_projection import bind_evidence_projection
from tests.adversarial.audit_report import (
    AdversarialAuditChecks,
    normalize_enum,
    resolve_observed_severity,
)
from tests.adversarial.helpers import (
    audit_required_signals,
    build_alert_corpus,
    build_narrative_corpus,
    ingest_true_positive_event,
)
from tests.adversarial.scenario_credential_db_staging_exfil import GROUND_TRUTH

pytestmark = [pytest.mark.integration, pytest.mark.adversarial_audit]

ARTIFACT_PATH = Path(__file__).resolve().parent / "artifacts" / "latest_audit.json"


async def _ingest_adversarial_incident(
    source_adapter,
    source_ingester: SourceIngester,
    event_service: EventService,
) -> str:
    return await ingest_true_positive_event(
        source_adapter,
        source_ingester,
        event_service,
    )


async def _audit_status_sequence(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> list[str]:
    from app.db import models as orm

    async with session_factory() as session:
        rows = list(
            await session.scalars(
                select(orm.EventAuditLog)
                .where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.to_status.is_not(None),
                )
                .order_by(orm.EventAuditLog.created_at.asc(), orm.EventAuditLog.id.asc())
            )
        )
    return [row.to_status for row in rows if row.to_status]


def _report_excerpt(report: Any) -> str:
    if report is None:
        return ""
    title = str(getattr(report, "title", "") or "")
    summary = str(getattr(report, "summary", "") or "")
    return (title + "\n" + summary).strip()[:1200]


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_adversarial_credential_db_staging_exfil_audit(
    adversarial_source_adapter,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    build_analysis_pipeline,
) -> None:
    """Ingest a fresh adversarial incident and produce a scored audit artifact.

    This test intentionally uses ``scenario_id=None`` so neutral Mock LLM default
    goldens are selected (ISSUE-201). Demo insider goldens are scenario-scoped under
    ``insider_data_exfiltration.json``; adversarial goldens live under
    ``adversarial_credential_db_staging_exfil.json``. Regex / evidence / default
    paths still run — set ``LLM_MODE=live`` for a stricter evaluation.
    """
    event_id = await _ingest_adversarial_incident(
        adversarial_source_adapter,
        source_ingester,
        event_service,
    )

    event_before = await event_service.get_event(event_id)
    assert event_before is not None
    new_events = await event_service.list_events(status=EventStatus.NEW)
    print(
        f"\n[adversarial-audit] ingested event_id={event_id} "
        f"title={event_before.title!r} "
        f"(NEW queue={new_events.total}, decoys={GROUND_TRUTH['noise_profile']['decoy_incidents']})"
    )

    pipeline, projection = build_analysis_pipeline(scenario_id=None)
    started = time.perf_counter()
    with bind_evidence_projection(projection):
        result = await pipeline.run(event_id)
    elapsed = time.perf_counter() - started
    print(f"[adversarial-audit] pipeline finished in {elapsed:.1f}s")

    event_after = await event_service.get_event(event_id)
    assert event_after is not None

    triage_ctx = await context_store.get(event_id, "triage_result") or {}
    evidence_ctx = await context_store.get(event_id, "evidence_output") or {}
    report_ctx = await context_store.get(event_id, "report") or {}
    risk_ctx = await context_store.get(event_id, "risk_assessment") or {}

    event_payload = event_after.model_dump(mode="json")
    alert_corpus = build_alert_corpus(
        alert_text=str(event_after.title or ""),
        event_payload=event_payload,
    )
    narrative_corpus = build_narrative_corpus(
        triage_ctx=triage_ctx if isinstance(triage_ctx, dict) else {},
        evidence_ctx=evidence_ctx if isinstance(evidence_ctx, dict) else {},
        report_ctx=report_ctx if isinstance(report_ctx, dict) else {},
    )
    entity_audit = audit_required_signals(
        required=list(GROUND_TRUTH["must_identify_entities"]),
        alert_corpus=alert_corpus,
        triage_ctx=triage_ctx if isinstance(triage_ctx, dict) else {},
        narrative_corpus=narrative_corpus,
    )
    indicator_audit = audit_required_signals(
        required=list(GROUND_TRUTH["must_identify_indicators"]),
        alert_corpus=alert_corpus,
        triage_ctx=triage_ctx if isinstance(triage_ctx, dict) else {},
        narrative_corpus=narrative_corpus,
    )
    entities_found = list(entity_audit.text_understanding_hits)
    indicators_found = list(indicator_audit.text_understanding_hits)

    outward_severity, triage_severity = resolve_observed_severity(
        risk_ctx=risk_ctx if isinstance(risk_ctx, dict) else None,
        event_severity=event_after.severity,
        triage_ctx=triage_ctx if isinstance(triage_ctx, dict) else None,
    )

    checks = AdversarialAuditChecks(
        ground_truth=GROUND_TRUTH,
        event_type=normalize_enum(triage_ctx.get("event_type") or event_after.event_type),
        severity=outward_severity,
        triage_severity=triage_severity,
        risk_score=int(event_after.risk_score or 0),
        final_verdict=normalize_enum(result.final_verdict or event_after.final_verdict),
        entities_found=entities_found,
        indicators_found=indicators_found,
        report_excerpt=_report_excerpt(result.report),
        triage_summary=str(triage_ctx.get("decision_summary") or ""),
        evidence_collection_status=str(
            evidence_ctx.get("collection_status") or evidence_ctx.get("status") or ""
        ),
        status_sequence=await _audit_status_sequence(session_factory, event_id),
    )
    report = checks.to_dict()
    report["quality_audit"] = {
        "alert_corpus_excerpt": alert_corpus[:400],
        "entities": {
            "text_understanding_hits": list(entity_audit.text_understanding_hits),
            "source_projection_hits": list(entity_audit.source_projection_hits),
            "echo_only_hits": list(entity_audit.echo_only_hits),
            "text_understanding_missing": list(entity_audit.text_understanding_missing),
        },
        "indicators": {
            "text_understanding_hits": list(indicator_audit.text_understanding_hits),
            "source_projection_hits": list(indicator_audit.source_projection_hits),
            "echo_only_hits": list(indicator_audit.echo_only_hits),
            "text_understanding_missing": list(indicator_audit.text_understanding_missing),
        },
    }
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("\n[adversarial-audit] human verdict:", report["verdict_for_human"])
    print("[adversarial-audit] checks:", json.dumps(report["checks"], ensure_ascii=False, indent=2))
    print(f"[adversarial-audit] full report → {ARTIFACT_PATH}")

    if isinstance(risk_ctx, dict) and risk_ctx.get("severity"):
        assert report["observed"]["severity"] == normalize_enum(risk_ctx.get("severity"))
    if triage_severity and report["observed"]["severity"] != triage_severity:
        assert report["observed"]["triage_severity"] == triage_severity

    source_only = [
        token
        for token in entity_audit.source_projection_hits
        if token not in entity_audit.text_understanding_hits
    ]
    assert set(entity_audit.echo_only_hits).isdisjoint(set(entity_audit.text_understanding_hits))
    for token in source_only:
        assert token not in entities_found

    # ISSUE-319: analysis-only audit must not require CLOSED / full-loop scoring.
    assert report["audit_mode"] == "analysis_only"
    assert "closed_reached" not in report["checks"]
    assert report["score"]["total_dimensions"] == 5
    assert not report["verdict_for_human"].startswith("PASS — full loop")

    # Soft assertion: pipeline must at least reach reporting for the audit to be meaningful.
    assert EventStatus.REPORTING.value in report["observed"]["status_sequence"], (
        "pipeline did not reach REPORTING — see artifact for details"
    )
