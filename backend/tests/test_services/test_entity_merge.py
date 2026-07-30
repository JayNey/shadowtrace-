"""Tests for source-priority entity merge (ISSUE-099)."""

from __future__ import annotations

from app.models.entities import AccountEntity, EntitySet, HostEntity
from app.services.entity_merge import merge_entity_sets


def test_source_wins_over_llm_duplicate_semantic_identity() -> None:
    source = EntitySet(
        hosts=[HostEntity(entity_id="s1", hostname="DEV-WKS-012", attributes={"provenance": "source"})]
    )
    llm = EntitySet(
        hosts=[HostEntity(entity_id="l1", hostname="DEV-WKS-012", attributes={"provenance": "llm"})]
    )
    result = merge_entity_sets(source=source, llm=llm)
    assert len(result.entities.hosts) == 1
    assert result.entities.hosts[0].entity_id == "s1"
    assert result.conflicts == ()


def test_semantic_dedupe_ignores_entity_id() -> None:
    source = EntitySet(
        accounts=[
            AccountEntity(entity_id="a1", username="dev-user-012", attributes={"provenance": "source"})
        ]
    )
    llm = EntitySet(
        accounts=[
            AccountEntity(entity_id="different-id", username="dev-user-012", attributes={"provenance": "llm"})
        ]
    )
    result = merge_entity_sets(source=source, llm=llm)
    assert len(result.entities.accounts) == 1
    assert result.entities.accounts[0].entity_id == "a1"


def test_text_extraction_empty_reason_when_source_present() -> None:
    source = EntitySet(
        hosts=[HostEntity(entity_id="s1", hostname="DEV-WKS-012", attributes={"provenance": "source"})]
    )
    regex = EntitySet(
        hosts=[HostEntity(entity_id="r1", hostname="ransomware-like", attributes={"provenance": "regex"})]
    )
    result = merge_entity_sets(source=source, regex=regex)
    assert "text_extraction_empty" in result.degradation_reasons
