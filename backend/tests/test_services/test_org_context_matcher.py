"""Exact org-context matcher: suffix hits, near-miss misses, window bounds."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import Settings
from app.knowledge.org_context_seed import (
    mock_org_context_records,
    production_org_context_records,
    records_for_settings,
    records_to_chunks,
)
from app.models.agent_io import CollectionStatus, EvidenceOutput, TriageResult
from app.models.entities import AccountEntity, DomainEntity, EntitySet, IPEntity
from app.models.enums import EventType, Severity
from app.models.knowledge import ListedKnowledgeChunk
from app.services.org_context_matcher import (
    OrgContextFacts,
    OrgContextMatcher,
    extract_org_context_facts,
    facts_from_query,
    load_org_context_matches,
)

_OUTSIDE_WINDOW = datetime(2026, 8, 24, 15, 0, tzinfo=UTC)
_INSIDE_WINDOW = datetime(2026, 8, 24, 3, 0, tzinfo=UTC)


def _listed_from_seed() -> list[ListedKnowledgeChunk]:
    chunks: list[ListedKnowledgeChunk] = []
    for chunk in records_to_chunks(mock_org_context_records()):
        chunks.append(
            ListedKnowledgeChunk(
                chunk_id=chunk.chunk_id,
                kb_name=chunk.kb_name,
                content=chunk.content,
                metadata=chunk.metadata,
                created_at=_OUTSIDE_WINDOW,
            )
        )
    return chunks


def _triage_with(*, domains: list[str] | None = None, ips: list[str] | None = None) -> TriageResult:
    return TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(
            domains=[
                DomainEntity(entity_id=f"dom-{i}", fqdn=fqdn)
                for i, fqdn in enumerate(domains or [])
            ],
            ips=[
                IPEntity(entity_id=f"ip-{i}", address=addr, scope="external")
                for i, addr in enumerate(ips or [])
            ],
        ),
    )


class TestOrgContextSeed:
    def test_production_seed_is_empty(self) -> None:
        assert production_org_context_records() == []
        assert records_to_chunks([]) == []

    def test_mock_seed_has_destination_and_scanner(self) -> None:
        records = mock_org_context_records()
        kinds = {r.kind for r in records}
        assert "allowed_destination" in kinds
        assert "allowed_source" in kinds
        assert any("files.corp.internal" in r.domains for r in records)
        assert any("ops-change-bot" in r.accounts for r in records)
        assert any("unknown-upload-example.com" in r.domains for r in records)
        assert any("brand-new-cdn-example.net" in r.domains for r in records)

    def test_seed_chunks_stamp_global_tenant(self) -> None:
        from app.models.knowledge import GLOBAL_KB_TENANT_ID

        chunks = records_to_chunks(mock_org_context_records())
        assert chunks
        assert all(chunk.metadata.get("tenant_id") == GLOBAL_KB_TENANT_ID for chunk in chunks)


class TestOrgContextMatcher:
    def test_legal_suffix_hits_allowed_destination(self) -> None:
        facts = OrgContextFacts(domains=("mail.files.corp.internal",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_OUTSIDE_WINDOW)
        assert any(h.kind == "allowed_destination" for h in hits)
        assert any(h.matched_value == "mail.files.corp.internal" for h in hits)

    def test_exact_domain_hits(self) -> None:
        facts = OrgContextFacts(domains=("files.corp.internal",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_OUTSIDE_WINDOW)
        assert any(h.kind == "allowed_destination" for h in hits)

    def test_near_miss_spelling_does_not_hit(self) -> None:
        facts = OrgContextFacts(domains=("files.corp.internall",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_OUTSIDE_WINDOW)
        assert not any(h.kind == "allowed_destination" for h in hits)

    def test_unapproved_upload_domain_is_exact_hit(self) -> None:
        facts = OrgContextFacts(domains=("unknown-upload-example.com",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_OUTSIDE_WINDOW)
        assert any(h.matched_value == "unknown-upload-example.com" for h in hits)
        assert any(
            h.kind == "data_handling"
            and h.match_type == "restricted_domain"
            and h.matched_value == "unknown-upload-example.com"
            for h in hits
        )

    def test_cdn_example_net_is_exact_hit(self) -> None:
        facts = OrgContextFacts(domains=("brand-new-cdn-example.net",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_OUTSIDE_WINDOW)
        assert any(h.matched_value == "brand-new-cdn-example.net" for h in hits)
        assert any(
            h.kind == "data_handling"
            and h.match_type == "restricted_domain"
            and h.matched_value == "brand-new-cdn-example.net"
            for h in hits
        )

    def test_unrelated_domain_does_not_hit(self) -> None:
        facts = OrgContextFacts(domains=("evil.example.net",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_OUTSIDE_WINDOW)
        assert hits == []

    def test_cidr_hits_allowed_source(self) -> None:
        facts = OrgContextFacts(ips=("10.20.0.88",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_OUTSIDE_WINDOW)
        assert any(h.kind == "allowed_source" and h.match_type == "cidr" for h in hits)

    def test_account_exact_hit_is_case_insensitive(self) -> None:
        facts = OrgContextFacts(accounts=("SVC-BACKUP",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_OUTSIDE_WINDOW)
        assert any(h.kind == "account_role" for h in hits)

    def test_window_inside_hits(self) -> None:
        facts = OrgContextFacts(domains=("files.corp.internal",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_INSIDE_WINDOW)
        assert any(h.kind == "time_window" for h in hits)

    def test_window_outside_does_not_hit(self) -> None:
        facts = OrgContextFacts(domains=("files.corp.internal",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_OUTSIDE_WINDOW)
        assert not any(h.kind == "time_window" for h in hits)

    def test_unrelated_domain_inside_window_does_not_hit(self) -> None:
        facts = OrgContextFacts(domains=("evil.example.net",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_INSIDE_WINDOW)
        assert hits == []

    def test_unapproved_upload_domain_is_not_allow_hit(self) -> None:
        facts = OrgContextFacts(domains=("unknown-upload-example.com",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_OUTSIDE_WINDOW)
        assert not any(
            h.match_type in {"domain_exact", "domain_suffix"}
            and h.matched_value == "unknown-upload-example.com"
            for h in hits
        )
        assert not any(h.kind == "allowed_destination" for h in hits)

    def test_cdn_example_net_is_not_allow_hit(self) -> None:
        facts = OrgContextFacts(domains=("brand-new-cdn-example.net",))
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=_OUTSIDE_WINDOW)
        assert not any(
            h.match_type in {"domain_exact", "domain_suffix"}
            and h.matched_value == "brand-new-cdn-example.net"
            for h in hits
        )
        assert not any(h.kind == "allowed_destination" for h in hits)

    def test_restricted_domain_is_typed_exact_match(self) -> None:
        from app.services.org_context_matcher import is_exact_org_context_match

        assert is_exact_org_context_match("restricted_domain", retrieval_method="exact") is True
        assert is_exact_org_context_match("restricted_domain", retrieval_method="keyword") is False

    def test_window_skipped_without_event_time(self) -> None:
        facts = OrgContextFacts(domains=("files.corp.internal",), now=None)
        hits = OrgContextMatcher.match(facts, _listed_from_seed(), now=None)
        assert not any(h.kind == "time_window" for h in hits)

    def test_extract_facts_does_not_default_to_wall_clock(self) -> None:
        triage = _triage_with(domains=["files.corp.internal"])
        facts = extract_org_context_facts(
            triage,
            EvidenceOutput(collection_status=CollectionStatus.COMPLETED),
        )
        assert facts.now is None

    def test_is_exact_rejects_empty_retrieval_method(self) -> None:
        from app.services.org_context_matcher import is_exact_org_context_match

        assert is_exact_org_context_match("account_exact", retrieval_method="exact") is True
        assert is_exact_org_context_match("account_exact", retrieval_method="") is False
        assert is_exact_org_context_match("account_exact") is True

    def test_extract_facts_from_triage_entities(self) -> None:
        triage = _triage_with(domains=["files.corp.internal"], ips=["8.8.8.8"])
        facts = extract_org_context_facts(
            triage,
            EvidenceOutput(collection_status=CollectionStatus.COMPLETED),
        )
        assert "files.corp.internal" in facts.domains
        assert "8.8.8.8" in facts.ips
        assert facts.has_structured_entities()

    def test_facts_from_query_tokens(self) -> None:
        facts = facts_from_query(
            "Entities: Domain:files.corp.internal, IP:10.20.0.15, Account:svc-backup"
        )
        assert facts.domains == ("files.corp.internal",)
        assert facts.ips == ("10.20.0.15",)
        assert facts.accounts == ("svc-backup",)


def test_org_context_seed_path_loads_tenant_records(tmp_path: Path) -> None:
    payload = [
        {
            "record_id": "org-tenant-allow",
            "kind": "allowed_destination",
            "content": "share.example.com is a tenant-approved file share.",
            "domains": ["share.example.com"],
        }
    ]
    seed_file = tmp_path / "org_context.json"
    seed_file.write_text(json.dumps(payload), encoding="utf-8")
    settings = Settings(
        SOURCE_MODE="file",
        ORG_CONTEXT_SEED_PATH=str(seed_file),
    )
    records = records_for_settings(settings)
    assert len(records) == 1
    assert records[0].domains == ("share.example.com",)
    assert production_org_context_records() == []


@pytest.mark.asyncio
async def test_load_org_context_matches_does_not_upsert() -> None:
    store = MagicMock()
    store.list_chunks = AsyncMock(return_value=[])
    store.upsert_chunks = AsyncMock()
    store.count = AsyncMock(return_value=0)
    triage = TriageResult(
        event_type=EventType.ACCOUNT_ANOMALY,
        severity=Severity.MEDIUM,
        need_investigation=True,
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
    matches = await load_org_context_matches(
        store,
        triage_result=triage,
        evidence_output=None,
        tenant_id="tenant-demo",
        occurred_at=_OUTSIDE_WINDOW,
    )
    store.upsert_chunks.assert_not_awaited()
    assert matches == []
