"""Core auth helpers (ISSUE-180 trusted-proxy hardening)."""

from __future__ import annotations

from app.core.auth import Principal, _filter_known_roles


def test_filter_known_roles_keeps_valid_entries() -> None:
    assert _filter_known_roles(["analyst", "admin", "approver"]) == [
        "analyst",
        "admin",
        "approver",
    ]


def test_filter_known_roles_drops_unknown_entries() -> None:
    assert _filter_known_roles(["analyst", "superuser", "root"]) == ["analyst"]


def test_filter_known_roles_empty_when_all_unknown() -> None:
    assert _filter_known_roles(["superuser", "root"]) == []


def test_filter_known_roles_normalizes_case() -> None:
    assert _filter_known_roles(["Analyst", "ADMIN", "Approver"]) == [
        "analyst",
        "admin",
        "approver",
    ]


def test_has_read_access_requires_known_role() -> None:
    assert Principal(subject="a", roles=["analyst"]).has_read_access()
    assert Principal(subject="a", roles=["admin"]).has_read_access()
    assert not Principal(subject="a", roles=[]).has_read_access()
    assert not Principal(subject="a", roles=["viewer"]).has_read_access()
    assert not Principal(subject="a", roles=["superuser"]).has_read_access()
