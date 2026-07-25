"""Deterministic verification tool mapping (ISSUE-060).

Maps response tool_name × target_type → verification tool (or None for
non-verifiable actions like create_ticket / notify_security_team).

The mapping is keyed by ``tool_name`` then ``target_type`` so the same
response tool can map to different verification tools for different target
types, even though the current baseline maps one response tool to exactly
one verification tool. Provider manifests may extend this table at runtime
but must pass schema validation before activation.

``update_source_event_disposition`` is excluded — it is a POST_VERIFY
deferred action and is never verified by entity-effect observation tools.
"""

from __future__ import annotations

from typing import Any

# Outer key: response/rollback tool_name.
# Inner key: target_type → verification tool name (str) or None (no verification).
# A tool_name absent from the outer dict is treated as "no mapping registered"
# (unverifiable via tool observation).
VERIFICATION_MAPPING: dict[str, dict[str, str | None]] = {
    # Network containment
    "block_ip": {"ip": "check_ip_block_status"},
    "block_domain": {"domain": "check_domain_block_status"},
    "unblock_ip": {"ip": "check_ip_block_status"},
    "unblock_domain": {"domain": "check_domain_block_status"},
    # Host / endpoint
    "isolate_host": {"host": "check_host_isolation_status"},
    "cancel_host_isolation": {"host": "check_host_isolation_status"},
    "quarantine_file": {"file": "check_file_quarantine_status"},
    "restore_file": {"file": "check_file_quarantine_status"},
    "block_process": {"process": "check_process_block_status"},
    "scan_host_for_virus": {"host": "check_virus_scan_status"},
    # Account / credential
    "disable_account": {"account": "check_account_status"},
    "restore_account": {"account": "check_account_status"},
    "force_logout": {"account": "check_account_status"},
    "reset_password": {"account": "check_account_status"},
    "revoke_token": {"account": "check_account_status"},
    # Non-verifiable (no observable entity side-effect)
    "create_ticket": {"ticket": None},
    "close_false_positive_ticket": {"ticket": None},
    "notify_security_team": {"channel": None},
    # Cross-cutting observation tools that self-map (verification tool name
    # equals response tool name).  This is NOT "submitter self-certifying":
    # the verification call is a fresh independent observation scoped to a
    # different entity domain — check_new_alerts re-queries the alert feed
    # for the same event rather than trusting the alert that triggered the
    # response, and check_traffic_drop observes network telemetry which is
    # a separate data source from the containment action's execution path.
    "check_new_alerts": {"event": "check_new_alerts"},
    "check_traffic_drop": {"ip": "check_traffic_drop", "host": "check_traffic_drop"},
}


def resolve_verification_tool(
    tool_name: str,
    target_type: str | None,
    *,
    provider_manifest_overrides: dict[str, Any] | None = None,
) -> str | None:
    """Return the verification tool name for a response tool + target_type.

    Returns ``None`` when the response tool has no registered verification
    counterpart (e.g. ``create_ticket`` → effect_status=skipped).

    ``provider_manifest_overrides`` allows a live Provider to extend or
    restrict the baseline mapping at runtime. Overrides are validated
    against the same schema before acceptance.
    """
    # 1. Check provider overrides first (live capability extension).
    if provider_manifest_overrides:
        override = provider_manifest_overrides.get(tool_name, {}).get(target_type or "")
        if override is not None:
            return override

    # 2. Baseline mapping.
    inner = VERIFICATION_MAPPING.get(tool_name)
    if inner is None:
        return None
    if target_type is not None and target_type in inner:
        return inner[target_type]
    if target_type is not None:
        # Unknown target_type → no precise mapping; return None rather
        # than guessing via fallback (which could observe the wrong
        # entity type, e.g. returning check_traffic_drop for
        # target_type="process" when only ip/host are registered).
        return None
    # Fallback: target_type is None → return the first mapping.
    if inner:
        return next(iter(inner.values()))
    return None


__all__ = [
    "VERIFICATION_MAPPING",
    "resolve_verification_tool",
]
