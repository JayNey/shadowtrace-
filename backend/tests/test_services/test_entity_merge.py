"""Tests for source-priority entity merge (ISSUE-099)."""

from __future__ import annotations

from app.models.entities import AccountEntity, EntitySet, HostEntity, IPEntity, ProcessEntity
from app.services.entity_merge import merge_entity_sets, merge_source_layers


def test_source_wins_over_llm_duplicate_semantic_identity() -> None:
    source = EntitySet(
        hosts=[
            HostEntity(entity_id="s1", hostname="DEV-WKS-012", attributes={"provenance": "source"})
        ]
    )
    llm = EntitySet(
        hosts=[HostEntity(entity_id="l1", hostname="DEV-WKS-012", attributes={"provenance": "llm"})]
    )
    result = merge_entity_sets(source=source, llm=llm)
    assert len(result.entities.hosts) == 1
    assert result.entities.hosts[0].entity_id == "s1"
    assert result.conflicts == ()


def test_source_wins_over_llm_competing_hostname() -> None:
    source = EntitySet(
        hosts=[
            HostEntity(entity_id="s1", hostname="DEV-WKS-012", attributes={"provenance": "source"})
        ]
    )
    llm = EntitySet(
        hosts=[HostEntity(entity_id="l1", hostname="EVIL-HOST", attributes={"provenance": "llm"})]
    )
    result = merge_entity_sets(source=source, llm=llm)
    assert len(result.entities.hosts) == 1
    assert result.entities.hosts[0].hostname == "DEV-WKS-012"
    assert len(result.conflicts) == 1
    assert result.conflicts[0].entity_type == "host"
    assert result.conflicts[0].discarded_source == "llm"
    assert result.conflicts[0].discarded_value == "EVIL-HOST"


def test_semantic_dedupe_ignores_entity_id() -> None:
    source = EntitySet(
        accounts=[
            AccountEntity(
                entity_id="a1", username="dev-user-012", attributes={"provenance": "source"}
            )
        ]
    )
    llm = EntitySet(
        accounts=[
            AccountEntity(
                entity_id="different-id", username="dev-user-012", attributes={"provenance": "llm"}
            )
        ]
    )
    result = merge_entity_sets(source=source, llm=llm)
    assert len(result.entities.accounts) == 1
    assert result.entities.accounts[0].entity_id == "a1"


def test_competing_account_records_conflict() -> None:
    source = EntitySet(
        accounts=[
            AccountEntity(
                entity_id="a1", username="dev-user-012", attributes={"provenance": "source"}
            )
        ]
    )
    llm = EntitySet(
        accounts=[
            AccountEntity(entity_id="a2", username="other-user", attributes={"provenance": "llm"})
        ]
    )
    result = merge_entity_sets(source=source, llm=llm)
    assert len(result.entities.accounts) == 1
    assert result.entities.accounts[0].username == "dev-user-012"
    assert len(result.conflicts) == 1
    assert result.conflicts[0].entity_type == "account"


def test_text_extraction_empty_reason_when_source_present() -> None:
    source = EntitySet(
        hosts=[
            HostEntity(entity_id="s1", hostname="DEV-WKS-012", attributes={"provenance": "source"})
        ]
    )
    regex = EntitySet(
        hosts=[
            HostEntity(
                entity_id="r1", hostname="ransomware-like", attributes={"provenance": "regex"}
            )
        ]
    )
    result = merge_entity_sets(source=source, regex=regex)
    assert "text_extraction_empty" in result.degradation_reasons
    assert len(result.entities.hosts) == 1
    assert result.entities.hosts[0].hostname == "DEV-WKS-012"


def test_merge_source_layers_labels_discarded_as_source() -> None:
    base = EntitySet(
        hosts=[
            HostEntity(entity_id="s1", hostname="DEV-WKS-012", attributes={"provenance": "source"})
        ]
    )
    incoming = EntitySet(
        hosts=[
            HostEntity(entity_id="s2", hostname="EVIL-HOST", attributes={"provenance": "source"})
        ]
    )
    result = merge_source_layers(base, incoming)
    assert len(result.entities.hosts) == 1
    assert result.conflicts[0].discarded_source == "source"


def test_ip_on_host_skips_duplicate_ip_entity() -> None:
    source = EntitySet(hosts=[HostEntity(entity_id="h1", hostname="DEV-WKS-012", ip="10.60.1.10")])
    llm = EntitySet(ips=[IPEntity(entity_id="ip1", address="10.60.1.10")])
    result = merge_entity_sets(source=source, llm=llm)
    assert result.entities.ips == []


def test_competing_process_records_conflict() -> None:
    source = EntitySet(
        processes=[
            ProcessEntity(entity_id="p1", name="good.exe", attributes={"provenance": "source"})
        ]
    )
    regex = EntitySet(
        processes=[
            ProcessEntity(entity_id="p2", name="bad.exe", attributes={"provenance": "regex"})
        ]
    )
    result = merge_entity_sets(source=source, regex=regex)
    assert len(result.entities.processes) == 1
    assert result.entities.processes[0].name == "good.exe"
    assert len(result.conflicts) == 1


def test_same_layer_keeps_multiple_distinct_hostnames() -> None:
    llm = EntitySet(
        hosts=[
            HostEntity(entity_id="h1", hostname="DEV-WKS-012", attributes={"provenance": "llm"}),
            HostEntity(entity_id="h2", hostname="WKS-HOST-007", attributes={"provenance": "llm"}),
        ]
    )
    result = merge_entity_sets(llm=llm)
    hostnames = {h.hostname for h in result.entities.hosts}
    assert hostnames == {"DEV-WKS-012", "WKS-HOST-007"}
    assert result.conflicts == ()
