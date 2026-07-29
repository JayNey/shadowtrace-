"""Regression scenario registry (ISSUE-087)."""

from __future__ import annotations

# Three legacy demo scenarios (ISSUE-039) — subset of the eight EventType packs.
DEMO_SCENARIOS: tuple[str, ...] = (
    "insider_data_exfiltration",
    "account_anomaly_fp",
    "suspicious_domain_access",
)

# Eight EventType system packs (ISSUE-086); includes the three demo scenarios above.
EVENT_TYPE_SCENARIOS: tuple[str, ...] = (
    "insider_data_exfiltration",
    "account_anomaly_fp",
    "suspicious_domain_access",
    "host_compromise",
    "malicious_process",
    "insider_privilege_abuse",
    "lateral_movement",
    "other_unclassified",
)

REGRESSION_SCENARIOS: tuple[str, ...] = EVENT_TYPE_SCENARIOS

SNAPSHOT_SCHEMA_VERSION = 1
