"""Tests for triage prompt grounding appendix (ISSUE-325)."""

from __future__ import annotations

from app.agents.prompts.triage_prompt import (
    build_triage_messages,
    build_triage_validation_corpus,
    format_triage_structured_appendix,
)
from app.models.agent_io import TriageRelatedAlertHint, TriageStructuredPromptContext
from app.models.entities import AccountEntity, DomainEntity, EntitySet, HostEntity, IPEntity


def test_format_structured_appendix_includes_normalized_and_hints() -> None:
    appendix = format_triage_structured_appendix(
        hint_entities=EntitySet(
            accounts=[AccountEntity(entity_id="a1", username="svc-analytics-47")],
            hosts=[HostEntity(entity_id="h1", hostname="SRV-DB-STG-02")],
            ips=[IPEntity(entity_id="i1", address="198.51.100.44", scope="external")],
            domains=[DomainEntity(entity_id="d1", fqdn="storage-sync-cdn.example")],
        ),
        structured_context=TriageStructuredPromptContext(
            normalized_fields={
                "account": "svc-analytics-47",
                "hostname": "WKS-DATA-031",
                "secondary_host": "SRV-DB-STG-02",
                "src_ip": "198.51.100.44",
                "domain": "storage-sync-cdn.example",
            },
            related_alerts=[
                TriageRelatedAlertHint(title="VPN session velocity", tag="session_geo_delta"),
            ],
        ),
    )
    assert "Structured ticket fields" in appendix
    assert "normalized_src_ip: 198.51.100.44" in appendix
    assert "normalized_secondary_host: SRV-DB-STG-02" in appendix
    assert "hint_domains: storage-sync-cdn.example" in appendix
    assert "related_alert: title=VPN session velocity; tag=session_geo_delta" in appendix


def test_build_triage_messages_appends_structured_appendix() -> None:
    blurry_title = "Correlation: elevated session and volume signals on analytics segment"
    messages = build_triage_messages(
        blurry_title,
        structured_context=TriageStructuredPromptContext(
            normalized_fields={
                "account": "svc-analytics-47",
                "src_ip": "198.51.100.44",
                "secondary_host": "SRV-DB-STG-02",
                "domain": "storage-sync-cdn.example",
            }
        ),
    )
    user = messages[1].content
    assert blurry_title in user
    assert "normalized_src_ip: 198.51.100.44" in user
    assert "normalized_secondary_host: SRV-DB-STG-02" in user
    assert "normalized_domain: storage-sync-cdn.example" in user


def test_build_triage_messages_without_structured_context_unchanged() -> None:
    messages = build_triage_messages("Plain alert body")
    assert messages[1].content == "Parse this alert and respond with JSON only:\nPlain alert body"


def test_validation_corpus_aligns_with_prompt_appendix() -> None:
    alert = "Correlation: elevated session and volume signals"
    context = TriageStructuredPromptContext(
        normalized_fields={"hostname": "WKS-DATA-031"},
    )
    corpus = build_triage_validation_corpus(alert, structured_context=context)
    messages = build_triage_messages(alert, structured_context=context)
    assert "normalized_hostname: WKS-DATA-031" in corpus
    assert "normalized_hostname: WKS-DATA-031" in messages[1].content


def test_related_alerts_are_capped_at_five() -> None:
    alerts = [
        TriageRelatedAlertHint(title=f"alert-{index}", tag=f"tag-{index}")
        for index in range(8)
    ]
    appendix = format_triage_structured_appendix(
        structured_context=TriageStructuredPromptContext(related_alerts=alerts),
    )
    assert appendix.count("related_alert:") == 5
