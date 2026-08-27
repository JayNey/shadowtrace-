"""ISSUE-114 post-evidence FP adjudication tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.agents.verdict_resolver import VerdictResolver
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    OrgContextMatch,
    RiskAssessment,
    ScoringMode,
    TriageResult,
)
from app.models.entities import AccountEntity, EntitySet
from app.models.enums import EventType, EvidenceSource, Severity
from app.models.evidence import Evidence, EvidenceConflict
from app.models.workflow import FP_HIGH_THRESHOLD, FP_LOW_THRESHOLD
from app.services.change_window_baseline_loader import (
    clear_change_window_baseline_cache,
    load_change_window_baseline,
    resolve_tenant_id,
)
from app.services.false_positive_matcher import _build_alert_text, _recommendation_for
from app.services.fp_adjudication_service import PostEvidenceFpAdjudicator


def _baseline_file(tmp_path: Path) -> Path:
    payload = {
        "schema_version": 1,
        "tenants": [
            {
                "tenant_id": "tenant-demo",
                "change_windows": [
                    {
                        "window_id": "cw-test",
                        "authorized_accounts": ["ops-change-bot"],
                        "authorized_actions": ["login", "bulk_login"],
                        "authorized_asset_groups": ["ops"],
                        "valid_from": "2024-06-15T08:00:00+00:00",
                        "valid_until": "2024-06-15T12:00:00+00:00",
                    }
                ],
            }
        ],
    }
    path = tmp_path / "change_windows.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _auth_evidence(*, change_window: bool = True) -> Evidence:
    return Evidence(
        evidence_id="evd-auth-001",
        event_id="evt-001",
        source=EvidenceSource.IDENTITY,
        evidence_type="login",
        description="ops login during maintenance",
        confidence=0.9,
        timestamp=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
        raw_data={
            "account": "ops-change-bot",
            "change_window": change_window,
            "action": "login",
            "result": "success",
        },
    )


def _malicious_edr_evidence() -> Evidence:
    return Evidence(
        evidence_id="evd-mal-edr-001",
        event_id="evt-001",
        source=EvidenceSource.ENDPOINT,
        evidence_type="process",
        description="malware process",
        confidence=0.95,
        timestamp=datetime(2024, 6, 15, 9, 35, tzinfo=UTC),
        raw_data={"malicious": True, "process": "evil.exe"},
        is_conflicting=True,
    )


def _malicious_dlp_evidence() -> Evidence:
    return Evidence(
        evidence_id="evd-mal-dlp-001",
        event_id="evt-001",
        source=EvidenceSource.DATA_SECURITY,
        evidence_type="file_access",
        description="sensitive file blocked by DLP",
        confidence=0.92,
        timestamp=datetime(2024, 6, 15, 9, 36, tzinfo=UTC),
        raw_data={"dlp_blocked": True, "file_name": "secret.docx"},
    )


def _malicious_ti_evidence() -> Evidence:
    return Evidence(
        evidence_id="evd-mal-ti-001",
        event_id="evt-001",
        source=EvidenceSource.THREAT_INTEL,
        evidence_type="indicator",
        description="TI malicious indicator",
        confidence=0.91,
        timestamp=datetime(2024, 6, 15, 9, 37, tzinfo=UTC),
        raw_data={"ti_malicious": True, "indicator": "evil.example"},
    )


def _asset_evidence(*, asset_group: str = "ops") -> Evidence:
    return Evidence(
        evidence_id="evd-asset-001",
        event_id="evt-001",
        source=EvidenceSource.ASSET,
        evidence_type="host",
        description="ops maintenance host",
        confidence=0.88,
        timestamp=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
        raw_data={"asset_group": asset_group, "hostname": "ops-host-01"},
    )


def _triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.ACCOUNT_ANOMALY,
        severity=Severity.MEDIUM,
        need_investigation=True,
        reasoning="bulk login observed",
        entities=EntitySet(
            accounts=[
                AccountEntity(
                    entity_id="acct-1",
                    entity_type="account",
                    username="ops-change-bot",
                )
            ]
        ),
    )


def _org_match(*, match_type: str = "account_exact", kind: str = "account_role") -> OrgContextMatch:
    return OrgContextMatch(
        kind=kind,  # type: ignore[arg-type]
        matched_value="ops-change-bot" if kind != "person_status" else "contractor-temp",
        explanation="org context hit",
        citation_id="cit-0c0000aa",
        chunk_id="chk-orgacct",
        match_type=match_type,
        match_confidence=1.0,
    )


def _adjudicate_close_kwargs(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "event_id": "evt-001",
        "evidence_output": EvidenceOutput(
            evidence_list=[_auth_evidence(), _asset_evidence()],
            conflicts=[],
            gaps=[],
            success_sources=["identity", "asset"],
            failed_sources=[],
            overall_confidence=0.8,
            collection_status=CollectionStatus.COMPLETED,
        ),
        "triage_result": _triage(),
        "source_snapshot": {"source_tenant_id": "tenant-demo"},
        "occurred_at": datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
        "org_context_matches": [_org_match()],
    }
    payload.update(overrides)
    return payload


def test_pre_evidence_recommendation_never_close_as_fp() -> None:
    assert _recommendation_for(FP_HIGH_THRESHOLD) == "investigate_with_flag"
    assert _recommendation_for(1.0) == "investigate_with_flag"
    assert _recommendation_for(FP_LOW_THRESHOLD) == "investigate_with_flag"
    assert _recommendation_for(FP_LOW_THRESHOLD - 0.01) == "no_match"


def test_vector_alert_text_excludes_scenario_and_signature() -> None:
    text = _build_alert_text(
        {
            "title": "Bulk login during change window",
            "scenario": "account_anomaly_fp",
            "signature": "ops_change_window_bulk_login",
        },
        EntitySet(),
    )
    assert "scenario=" not in text
    assert "signature=" not in text
    assert "Bulk login during change window" in text


def test_post_evidence_close_with_authorization(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(**_adjudicate_close_kwargs())
    assert result.recommendation == "close_as_fp"
    assert result.supporting_evidence_ids == ["evd-auth-001"]
    assert "baseline_window_match" in result.matched_conditions
    assert "org_context_exact_hit" in result.matched_conditions
    assert result.matched_window_id == "cw-test"
    assert result.max_score == 0.9
    assert result.qualification_level == 4
    assert result.arbitration == "no_contradiction"


def test_close_as_fp_max_score_floor_when_auth_confidence_low(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    low_conf_auth = _auth_evidence().model_copy(update={"confidence": 0.7})
    result = adjudicator.adjudicate(
        event_id="evt-001",
        evidence_output=EvidenceOutput(
            evidence_list=[low_conf_auth, _asset_evidence()],
            conflicts=[],
            gaps=[],
            success_sources=["identity", "asset"],
            failed_sources=[],
            overall_confidence=0.7,
            collection_status=CollectionStatus.COMPLETED,
        ),
        triage_result=_triage(),
        source_snapshot={"source_tenant_id": "tenant-demo"},
        occurred_at=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
        org_context_matches=[_org_match()],
    )
    assert result.recommendation == "close_as_fp"
    assert result.max_score == 0.88
    assert result.qualification_level == 4


def test_unauthorized_asset_group_does_not_close(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        **_adjudicate_close_kwargs(
            evidence_output=EvidenceOutput(
                evidence_list=[_auth_evidence(), _asset_evidence(asset_group="finance")],
                conflicts=[],
                gaps=[],
                success_sources=["identity", "asset"],
                failed_sources=[],
                overall_confidence=0.8,
                collection_status=CollectionStatus.COMPLETED,
            )
        )
    )
    assert result.recommendation != "close_as_fp"
    assert "baseline_window_match" in result.missing_conditions


def test_missing_asset_group_blocks_fp_close(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        event_id="evt-001",
        evidence_output=EvidenceOutput(
            evidence_list=[_auth_evidence()],
            conflicts=[],
            gaps=[],
            success_sources=["identity"],
            failed_sources=[],
            overall_confidence=0.8,
            collection_status=CollectionStatus.COMPLETED,
        ),
        triage_result=_triage(),
        source_snapshot={"source_tenant_id": "tenant-demo"},
        occurred_at=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
    )
    assert result.recommendation != "close_as_fp"
    assert "baseline_window_match" in result.missing_conditions


def test_same_telemetry_without_authorization_does_not_close(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        event_id="evt-001",
        evidence_output=EvidenceOutput(
            evidence_list=[_auth_evidence(change_window=False)],
            conflicts=[],
            gaps=[],
            success_sources=["identity"],
            failed_sources=[],
            overall_confidence=0.8,
            collection_status=CollectionStatus.COMPLETED,
        ),
        triage_result=_triage(),
        source_snapshot={"source_tenant_id": "tenant-demo"},
    )
    assert result.recommendation != "close_as_fp"
    assert "change_window_authorization_evidence" in result.missing_conditions


def test_malicious_conflicts_block_fp_close(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        event_id="evt-001",
        evidence_output=EvidenceOutput(
            evidence_list=[_auth_evidence(), _asset_evidence(), _malicious_edr_evidence()],
            conflicts=[
                EvidenceConflict(
                    conflict_id="cfl-1",
                    event_id="evt-001",
                    description="endpoint contradicts benign login",
                    evidence_ids=["evd-auth-001", "evd-mal-edr-001"],
                    sources=[EvidenceSource.IDENTITY, EvidenceSource.ENDPOINT],
                )
            ],
            gaps=[],
            success_sources=["identity", "endpoint"],
            failed_sources=[],
            overall_confidence=0.8,
            collection_status=CollectionStatus.COMPLETED,
        ),
        triage_result=_triage(),
        source_snapshot={"source_tenant_id": "tenant-demo"},
    )
    assert result.recommendation == "investigate"
    assert result.conflicts
    assert "no_malicious_conflicts" in result.missing_conditions
    assert result.qualification_level == 3
    assert result.matched_window_id == "cw-test"
    assert result.arbitration == "malicious_overrides_allowance"


@pytest.mark.parametrize(
    ("malicious_evidence", "description"),
    [
        (_malicious_dlp_evidence(), "dlp blocked sensitive exfiltration"),
        (_malicious_ti_evidence(), "threat intel malicious indicator"),
    ],
)
def test_malicious_source_conflicts_block_fp_close_without_conflict_record(
    tmp_path: Path,
    malicious_evidence: Evidence,
    description: str,
) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        event_id="evt-001",
        evidence_output=EvidenceOutput(
            evidence_list=[_auth_evidence(), _asset_evidence(), malicious_evidence],
            conflicts=[],
            gaps=[],
            success_sources=["identity", malicious_evidence.source.value],
            failed_sources=[],
            overall_confidence=0.8,
            collection_status=CollectionStatus.COMPLETED,
        ),
        triage_result=_triage(),
        source_snapshot={"source_tenant_id": "tenant-demo"},
    )
    assert result.recommendation == "investigate", description
    assert result.conflicts
    assert "no_malicious_conflicts" in result.missing_conditions
    assert result.qualification_level == 3
    assert result.arbitration == "malicious_overrides_allowance"


def test_absence_of_malicious_evidence_is_not_fp_proof(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        event_id="evt-001",
        evidence_output=EvidenceOutput(
            evidence_list=[],
            conflicts=[],
            gaps=[],
            success_sources=[],
            failed_sources=[],
            overall_confidence=0.0,
            collection_status=CollectionStatus.COMPLETED,
        ),
        triage_result=_triage(),
        source_snapshot={"source_tenant_id": "tenant-demo"},
    )
    assert result.recommendation == "no_fp_signal"
    assert "change_window_authorization_evidence" in result.missing_conditions


def test_verdict_resolver_ignores_pre_evidence_close_as_fp() -> None:
    resolver = VerdictResolver()
    assessment = RiskAssessment(
        risk_score=85,
        severity=Severity.HIGH,
        confidence=0.9,
        risk_factors=[],
        possible_false_positive=False,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    verdict = resolver.resolve(
        assessment,
        false_positive_match={"recommendation": "close_as_fp", "phase": "pre_evidence"},
    )
    assert verdict.value == "confirmed_threat"


def test_verdict_resolver_pre_evidence_high_score_is_advisory_only() -> None:
    resolver = VerdictResolver()
    assessment = RiskAssessment(
        risk_score=20,
        severity=Severity.LOW,
        confidence=0.9,
        risk_factors=[],
        possible_false_positive=False,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    verdict = resolver.resolve(
        assessment,
        false_positive_match={
            "recommendation": "investigate_with_flag",
            "max_score": 0.96,
            "phase": "pre_evidence",
        },
    )
    assert verdict.value == "possible_false_positive"


def test_verdict_resolver_rejects_forged_post_evidence_fp_match_without_adjudication() -> None:
    resolver = VerdictResolver()
    assessment = RiskAssessment(
        risk_score=20,
        severity=Severity.LOW,
        confidence=0.9,
        risk_factors=[],
        possible_false_positive=False,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    verdict = resolver.resolve(
        assessment,
        false_positive_match={
            "recommendation": "close_as_fp",
            "phase": "post_evidence",
            "max_score": 0.96,
        },
        fp_adjudication={
            "recommendation": "investigate",
            "missing_conditions": ["baseline_window_match"],
        },
    )
    assert verdict.value == "possible_false_positive"


def test_missing_tenant_id_does_not_use_demo_baseline(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        event_id="evt-001",
        evidence_output=EvidenceOutput(
            evidence_list=[_auth_evidence(), _asset_evidence()],
            conflicts=[],
            gaps=[],
            success_sources=["identity", "asset"],
            failed_sources=[],
            overall_confidence=0.8,
            collection_status=CollectionStatus.COMPLETED,
        ),
        triage_result=_triage(),
        source_snapshot={"title": "no tenant in snapshot"},
        occurred_at=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
    )
    assert result.recommendation == "no_fp_signal"
    assert result.missing_conditions == ["tenant_id"]


def test_action_scope_requires_authorization_evidence_not_event_type_default(
    tmp_path: Path,
) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    auth_without_action = Evidence(
        evidence_id="evd-auth-002",
        event_id="evt-001",
        source=EvidenceSource.IDENTITY,
        evidence_type="session",
        description="change window flag without action metadata",
        confidence=0.9,
        timestamp=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
        raw_data={"account": "ops-change-bot", "change_window": True, "result": "success"},
    )
    result = adjudicator.adjudicate(
        event_id="evt-001",
        evidence_output=EvidenceOutput(
            evidence_list=[auth_without_action, _asset_evidence()],
            conflicts=[],
            gaps=[],
            success_sources=["identity", "asset"],
            failed_sources=[],
            overall_confidence=0.8,
            collection_status=CollectionStatus.COMPLETED,
        ),
        triage_result=_triage(),
        source_snapshot={"source_tenant_id": "tenant-demo"},
        occurred_at=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
    )
    assert result.recommendation != "close_as_fp"
    assert "baseline_window_match" in result.missing_conditions


def test_verdict_resolver_honors_post_evidence_adjudication() -> None:
    resolver = VerdictResolver()
    assessment = RiskAssessment(
        risk_score=85,
        severity=Severity.HIGH,
        confidence=0.9,
        risk_factors=[],
        possible_false_positive=False,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    verdict = resolver.resolve(
        assessment,
        fp_adjudication={"recommendation": "close_as_fp", "matched_window_id": "cw-test"},
    )
    assert verdict.value == "false_positive"


def test_baseline_loader_indexes_tenants(tmp_path: Path) -> None:
    clear_change_window_baseline_cache()
    indexed = load_change_window_baseline(str(_baseline_file(tmp_path)))
    assert "tenant-demo" in indexed
    assert indexed["tenant-demo"].change_windows[0].window_id == "cw-test"


def test_resolve_tenant_id_from_creation_source_ref() -> None:
    from app.db import models as orm
    from app.services.event_service import _source_snapshot_from_row

    row = orm.SecurityEvent(
        event_id="evt-tenant-ref",
        event_type="account_anomaly",
        title="Bulk login",
        creation_source_ref={
            "source_product": "mock_xdr",
            "source_tenant_id": "tenant-demo",
            "connector_id": "conn-1",
            "source_kind": "incident",
            "source_object_id": "inc-1",
        },
        source_reference_snapshots=[],
    )
    snapshot = _source_snapshot_from_row(row)
    assert resolve_tenant_id(snapshot) == "tenant-demo"
    assert resolve_tenant_id({"title": "no tenant"}) is None


def test_window_match_is_independent_of_scenario_field(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    snapshot_with = {"source_tenant_id": "tenant-demo", "scenario": "account_anomaly_fp"}
    snapshot_without = {"source_tenant_id": "tenant-demo"}
    evidence = EvidenceOutput(
        evidence_list=[_auth_evidence(), _asset_evidence()],
        conflicts=[],
        gaps=[],
        success_sources=["identity", "asset"],
        failed_sources=[],
        overall_confidence=0.8,
        collection_status=CollectionStatus.COMPLETED,
    )
    with_scenario = adjudicator.adjudicate(
        event_id="evt-a",
        evidence_output=evidence,
        triage_result=_triage(),
        source_snapshot=snapshot_with,
        occurred_at=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
        org_context_matches=[_org_match()],
    )
    without_scenario = adjudicator.adjudicate(
        event_id="evt-b",
        evidence_output=evidence,
        triage_result=_triage(),
        source_snapshot=snapshot_without,
        occurred_at=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
        org_context_matches=[_org_match()],
    )
    assert with_scenario.recommendation == without_scenario.recommendation == "close_as_fp"


def test_missing_org_context_does_not_block_close_as_fp(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(**_adjudicate_close_kwargs(org_context_matches=[]))
    assert result.recommendation == "close_as_fp"
    assert "org_context_exact_hit" not in result.matched_conditions
    assert "org_context_exact_hit" not in result.missing_conditions


def test_vector_org_match_type_is_not_a_close_gate(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        **_adjudicate_close_kwargs(org_context_matches=[_org_match(match_type="vector")])
    )
    assert result.recommendation == "close_as_fp"
    assert "org_context_exact_hit" not in result.matched_conditions


def test_same_account_outside_change_window_does_not_close(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    outside = datetime(2024, 6, 15, 18, 0, tzinfo=UTC)
    outside_auth = _auth_evidence().model_copy(update={"timestamp": outside})
    result = adjudicator.adjudicate(
        **_adjudicate_close_kwargs(
            evidence_output=EvidenceOutput(
                evidence_list=[outside_auth, _asset_evidence()],
                conflicts=[],
                gaps=[],
                success_sources=["identity", "asset"],
                failed_sources=[],
                overall_confidence=0.8,
                collection_status=CollectionStatus.COMPLETED,
            ),
            occurred_at=outside,
        )
    )
    assert result.recommendation != "close_as_fp"
    assert "baseline_window_match" in result.missing_conditions
    assert "time_match" in result.missing_conditions
    assert "identity_scope_match" not in result.missing_conditions
    assert result.qualification_level == 1


def test_org_hit_alone_does_not_close(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        event_id="evt-001",
        evidence_output=EvidenceOutput(
            evidence_list=[],
            conflicts=[],
            gaps=[],
            success_sources=[],
            failed_sources=[],
            overall_confidence=0.0,
            collection_status=CollectionStatus.COMPLETED,
        ),
        triage_result=_triage(),
        source_snapshot={"source_tenant_id": "tenant-demo"},
        occurred_at=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
        org_context_matches=[_org_match()],
    )
    assert result.recommendation == "no_fp_signal"
    assert result.recommendation != "close_as_fp"
    assert result.qualification_level <= 1


def test_person_status_hit_is_not_a_close_gate(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        **_adjudicate_close_kwargs(
            org_context_matches=[_org_match(kind="person_status")],
        )
    )
    assert result.recommendation == "close_as_fp"
    assert "org_context_exact_hit" not in result.matched_conditions
    assert result.qualification_level == 4


def _endpoint_process(*, process: str, cmdline: str) -> Evidence:
    return Evidence(
        evidence_id="evd-proc-001",
        event_id="evt-001",
        source=EvidenceSource.ENDPOINT,
        evidence_type="process",
        description=cmdline,
        confidence=0.9,
        timestamp=datetime(2024, 6, 15, 9, 35, tzinfo=UTC),
        raw_data={"process": process, "cmdline": cmdline},
    )


def test_encoded_powershell_blocks_fp_close(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        **_adjudicate_close_kwargs(
            evidence_output=EvidenceOutput(
                evidence_list=[
                    _auth_evidence(),
                    _asset_evidence(),
                    _endpoint_process(
                        process="powershell.exe",
                        cmdline="powershell.exe -EncodedCommand SQBFAFgA",
                    ),
                ],
                conflicts=[],
                gaps=[],
                success_sources=["identity", "asset", "endpoint"],
                failed_sources=[],
                overall_confidence=0.8,
                collection_status=CollectionStatus.COMPLETED,
            )
        )
    )
    assert result.recommendation != "close_as_fp"
    assert result.qualification_level == 3
    assert result.arbitration == "malicious_overrides_allowance"
    assert any("encoded_powershell" in item for item in result.conflicts)


def test_bare_powershell_does_not_block_fp_close(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        **_adjudicate_close_kwargs(
            evidence_output=EvidenceOutput(
                evidence_list=[
                    _auth_evidence(),
                    _asset_evidence(),
                    _endpoint_process(
                        process="powershell.exe",
                        cmdline="powershell.exe Get-Service",
                    ),
                ],
                conflicts=[],
                gaps=[],
                success_sources=["identity", "asset", "endpoint"],
                failed_sources=[],
                overall_confidence=0.8,
                collection_status=CollectionStatus.COMPLETED,
            )
        )
    )
    assert result.recommendation == "close_as_fp"
    assert result.qualification_level == 4


def test_unauthorized_asset_reports_only_failed_scope(tmp_path: Path) -> None:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(_baseline_file(tmp_path)))
    result = adjudicator.adjudicate(
        **_adjudicate_close_kwargs(
            evidence_output=EvidenceOutput(
                evidence_list=[_auth_evidence(), _asset_evidence(asset_group="finance")],
                conflicts=[],
                gaps=[],
                success_sources=["identity", "asset"],
                failed_sources=[],
                overall_confidence=0.8,
                collection_status=CollectionStatus.COMPLETED,
            )
        )
    )
    assert result.recommendation != "close_as_fp"
    assert result.qualification_level == 2
    assert "asset_scope_match" in result.missing_conditions
    assert "time_match" not in result.missing_conditions
    assert "time_match" in result.matched_conditions
