"""Canonical evidence query tool ordering (ISSUE-033 / ISSUE-115)."""

from __future__ import annotations

EVIDENCE_QUERY_ORDER: tuple[str, ...] = (
    "query_account_login",
    "query_edr_process",
    "query_file_access",
    "query_network_flow",
    "query_dns",
    "query_asset_info",
    "query_threat_intel",
)

SEVEN_EVIDENCE_TOOLS: tuple[str, ...] = EVIDENCE_QUERY_ORDER

__all__ = ["EVIDENCE_QUERY_ORDER", "SEVEN_EVIDENCE_TOOLS"]
