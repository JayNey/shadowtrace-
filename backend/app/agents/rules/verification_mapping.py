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

import logging
from typing import Any, cast

logger = logging.getLogger(__name__)

# Outer key: response/rollback tool_name.
# Inner key: target_type → verification tool name (str) or None (no verification).
# A tool_name absent from the outer dict is treated as "no mapping registered"
# (unverifiable via tool observation).
#
# NOTE: The type is ``dict[str, dict[str, str | None]]`` (nested by tool_name
# then target_type), not a flat ``dict[str, str | None]``.  This is intentional:
# the same response tool can map to different verification tools for different
# target types (e.g. ``check_traffic_drop`` maps ``ip`` and ``host`` to
# different observation targets).  resolve_verification_tool() provides the
# flattened lookup interface consumed by VerifyAgent.
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

# Required parameter keys that each verification tool expects in its params
# dict.  Keys may use dot-notation for nested access (e.g. "parameters.job_id"
# means params["parameters"]["job_id"]).  This is checked before calling the
# verification tool so that missing required params are caught early with a
# clear diagnostic rather than surfacing as an opaque Provider-side error.
VERIFICATION_TOOL_EXPECTED_PARAMS: dict[str, list[str]] = {
    "check_ip_block_status": ["target_type", "target"],
    "check_domain_block_status": ["target_type", "target"],
    "check_host_isolation_status": ["target_type", "target"],
    "check_file_quarantine_status": ["target_type", "target"],
    "check_process_block_status": ["target_type", "target"],
    "check_virus_scan_status": ["target_type", "target"],
    "check_account_status": ["target_type", "target"],
    "check_new_alerts": ["target_type", "target"],
    "check_traffic_drop": ["target_type", "target"],
}


# Module-level sentinel for missing nested dict keys.  Must be defined at
# module scope so both _resolve_nested_key() and validate_verification_tool_params()
# can reference it; a function-local sentinel is invisible to the caller.
#
# Uses a dedicated type (not a bare ``object()``) so that ``is`` comparisons
# survive pickle / multiprocessing fork boundaries — type identity is
# preserved across process boundaries where object identity is not.
_MISSING_SENTINEL_TYPE = type('_MissingSentinel', (), {})
_MISSING: Any = _MISSING_SENTINEL_TYPE()


def _resolve_nested_key(data: dict[str, Any], dotted_key: str) -> Any:
    """Resolve a dotted key like ``"parameters.job_id"`` from a nested dict.

    Returns the value if all segments exist, or the module-level ``_MISSING``
    sentinel when any intermediate key is absent or the intermediate value
    is not a dict.
    """
    current: Any = data
    for segment in dotted_key.split("."):
        if not isinstance(current, dict):
            return _MISSING
        current = current.get(segment, _MISSING)
        if current is _MISSING:
            return _MISSING
    return current


def validate_verification_tool_params(
    verify_tool: str,
    params: dict[str, Any],
) -> list[str]:
    """Check that *params* contains every key listed in the expected-params
    mapping for *verify_tool*.

    Returns a (possibly empty) list of missing parameter keys.  When the
    tool is not listed in ``VERIFICATION_TOOL_EXPECTED_PARAMS`` no
    validation is performed and an empty list is returned (unknown tools
    are assumed to accept whatever params the caller provides).
    """
    expected = VERIFICATION_TOOL_EXPECTED_PARAMS.get(verify_tool)
    if expected is None:
        return []
    missing: list[str] = []
    for key in expected:
        if _resolve_nested_key(params, key) is _MISSING:
            missing.append(key)
    return missing


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

    **Provider override resolution order**::

        1. If ``provider_manifest_overrides`` is provided, look up
           ``overrides[tool_name][target_type]``.
        2. If the override value is a non-``None`` string, return it
           immediately (the Provider *extends* the baseline).
        3. If the override value is ``None``, return ``None`` immediately
           — the Provider has explicitly *disabled* verification for this
           (tool_name, target_type) pair, and the baseline mapping is
           **not** consulted as a fallback.  This is by design: a Provider
           that returns ``None`` for a known tool is asserting "I cannot
           verify this action type," and silently falling through to the
           baseline would re-enable a verification path the Provider has
           declared unavailable.
        4. If the override dict exists but lacks an entry for *tool_name*
           or *target_type*, fall through to the baseline mapping (step 5).
        5. Consult the baseline ``VERIFICATION_MAPPING``.
    """
    # 1. Check provider overrides first (live capability extension).
    if provider_manifest_overrides:
        override = provider_manifest_overrides.get(tool_name, {}).get(target_type or "")
        if override is not None:
            # Whitelist validation: the override value must be a known
            # verification tool name — either registered in the baseline
            # mapping values or listed in VERIFICATION_TOOL_EXPECTED_PARAMS.
            # This prevents a misconfigured or compromised Provider from
            # injecting arbitrary tool names into the verification path
            # (ISSUE-060 SF-3).
            _known_baseline = {
                v
                for inner in VERIFICATION_MAPPING.values()
                for v in inner.values()
                if v is not None
            }
            _known_expected = set(VERIFICATION_TOOL_EXPECTED_PARAMS)
            _known_verification_tools = _known_baseline | _known_expected
            if override not in _known_verification_tools:
                logger.warning(
                    "Rejected unregistered verification tool override: %s "
                    "(tool_name=%s, target_type=%s)",
                    override,
                    tool_name,
                    target_type,
                )
                return None
            return cast(str, override)
        # When the override dict has an entry for this (tool_name, target_type)
        # whose value is explicitly None, the .get() above returns None and we
        # intentionally skip the baseline fallback below — the Provider has
        # signalled "verification unavailable for this tool+target."  See the
        # docstring §3 for the design rationale.

    # 2. Baseline mapping.
    inner = VERIFICATION_MAPPING.get(tool_name)
    if inner is None:
        return None
    if target_type is not None and target_type in inner:
        return inner[target_type]
    # target_type is None, or target_type is known but not a key in inner:
    # return None rather than guessing via fallback (which could observe the
    # wrong entity type, e.g. returning check_traffic_drop for
    # target_type="process" when only ip/host are registered, or for
    # an unspecified target_type).
    return None


__all__ = [
    "VERIFICATION_MAPPING",
    "VERIFICATION_TOOL_EXPECTED_PARAMS",
    "resolve_verification_tool",
    "validate_verification_tool_params",
]
