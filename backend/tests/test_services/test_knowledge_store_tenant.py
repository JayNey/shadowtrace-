"""KnowledgeStore tenant isolation tests (ISSUE-138)."""

from __future__ import annotations

from app.services.knowledge_store import KnowledgeStore


def test_tenant_filter_permissive_includes_null_metadata() -> None:
    clause, params = KnowledgeStore._tenant_filter_clause(
        "tenant-a",
        tenant_isolation_strict=False,
    )
    assert "IS NULL" in clause
    assert params == {"tenant_id": "tenant-a"}


def test_tenant_filter_strict_requires_metadata_match() -> None:
    clause, params = KnowledgeStore._tenant_filter_clause(
        "tenant-a",
        tenant_isolation_strict=True,
    )
    assert "IS NULL" not in clause
    assert "= :tenant_id" in clause
    assert params == {"tenant_id": "tenant-a"}


def test_tenant_filter_absent_when_tenant_id_none() -> None:
    clause, params = KnowledgeStore._tenant_filter_clause(
        None,
        tenant_isolation_strict=True,
    )
    assert clause == ""
    assert params == {}
