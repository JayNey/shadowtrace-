"""Tests for entity semantic validation (ISSUE-100)."""

from __future__ import annotations

import pytest

from app.models.entities import EntitySet, HostEntity
from app.services.entity_validator import validate_entity_set


@pytest.mark.parametrize(
    "hostname",
    [
        "DEV-WKS-012",
        "db01",
        "ip-10-0-0-4",
        "ubuntu-prod-01",
        "WKS-HOST-007",
    ],
)
def test_structured_source_hostnames_accepted(hostname: str) -> None:
    entities = EntitySet(hosts=[HostEntity(entity_id="h1", hostname=hostname)])
    result = validate_entity_set(entities, provenance="source")
    assert len(result.entity_set.hosts) == 1
    assert result.entity_set.hosts[0].hostname == hostname


def test_ransomware_like_phrase_rejected_for_regex() -> None:
    alert = "Malicious process spawned — ransomware-like behavior"
    entities = EntitySet(hosts=[HostEntity(entity_id="h1", hostname="ransomware-like")])
    result = validate_entity_set(entities, provenance="regex", alert_text=alert)
    assert result.entity_set.hosts == []
    assert any(r.reason_code == "phrase_without_host_context" for r in result.rejections)


def test_dev_wks_accepted_for_regex_without_context() -> None:
    entities = EntitySet(hosts=[HostEntity(entity_id="h1", hostname="DEV-WKS-012")])
    result = validate_entity_set(
        entities,
        provenance="regex",
        alert_text="Malicious process spawned — ransomware-like behavior",
    )
    assert len(result.entity_set.hosts) == 1


@pytest.mark.parametrize(
    "phrase",
    [
        "behavior detected on endpoint",
        "suspicious activity observed",
        "like pattern observed",
        "stage chain attempt",
    ],
)
def test_negative_natural_language_samples_no_hostname(phrase: str) -> None:
    from app.agents.rules.entity_extraction_rules import extract_entities_regex

    extracted = extract_entities_regex(phrase)
    validated = validate_entity_set(
        EntitySet(
            hosts=[
                HostEntity(entity_id=f"h{i}", hostname=h)
                for i, h in enumerate(extracted.hostnames, 1)
            ]
        ),
        provenance="regex",
        alert_text=phrase,
    )
    assert validated.entity_set.hosts == []


def test_private_ip_not_rejected_as_invalid_syntax() -> None:
    from app.models.entities import IPEntity

    entities = EntitySet(ips=[IPEntity(entity_id="ip-1", address="10.60.1.10")])
    result = validate_entity_set(entities, provenance="regex")
    assert len(result.entity_set.ips) == 1
