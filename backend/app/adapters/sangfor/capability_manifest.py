"""Sangfor CapabilityManifest for live ResponseAgent (alignment plan Layer 8a).

Agents must not import this module. Overlay only narrows ToolMeta owners;
isolate_host / disable_account stay in allowed_operations.
"""

from __future__ import annotations

from typing import Any

from app.adapters.sangfor.capability_overlay import (
    SANGFOR_ADAPTER_KIND,
    apply_capability_overlay,
)
from app.adapters.sangfor.runtime_config import overlay_config_from_settings
from app.core.config import Settings, get_settings
from app.models.enums import (
    CapabilityState,
    DispositionIntentKind,
    SourceObjectKind,
)
from app.models.tool_meta import (
    TERMINAL_DISPOSITION_TOOL,
    CapabilityBindingEntry,
    CapabilityManifest,
    ExecutionChannel,
)
from app.tools.specs import baseline_tool_index

_QUERY_TOOL_PREFIX = "query_"
_SANGFOR_PROVIDER = "sangfor_xdr"


def build_sangfor_capability_manifest() -> CapabilityManifest:
    """Live Sangfor pack: same kernel operations as Mock, no Mock provider_name."""
    index = baseline_tool_index()
    response_ops = sorted(
        name
        for name, meta in index.items()
        if meta.tool_category.value == "response"
        and not name.startswith(_QUERY_TOOL_PREFIX)
    )
    return CapabilityManifest(
        provider_name=_SANGFOR_PROVIDER,
        online=True,
        source_read=CapabilityState.UNKNOWN,
        event_disposition=CapabilityState.SUPPORTED,
        entity_response=CapabilityState.SUPPORTED,
        allowed_intents=[
            DispositionIntentKind.EVENT_STATUS_UPDATE,
            DispositionIntentKind.ENTITY_ACTION_SUBMIT,
            DispositionIntentKind.EXECUTION_RESULT_RECORD,
        ],
        allowed_operations=response_ops + [TERMINAL_DISPOSITION_TOOL],
        allowed_target_types=sorted(
            {target for name in response_ops for target in index[name].target_types}
            | {"source_object"}
        ),
        allowed_source_kinds=[SourceObjectKind.INCIDENT, SourceObjectKind.ALERT],
        allowed_native_source_object_types=["xdr_incident"],
        supports_status_query=True,
        supports_lookup_by_idempotency=False,
        supports_idempotency=True,
        supports_concurrency_control=False,
        supports_fencing=False,
        allowed_execution_channels=[
            ExecutionChannel.TOOL_PROVIDER,
            ExecutionChannel.DISPOSITION_ADAPTER,
        ],
        bindings=[
            CapabilityBindingEntry(
                intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
                operation_code="set_event_disposition",
                source_kind=SourceObjectKind.INCIDENT,
                native_source_object_type="xdr_incident",
                state=CapabilityState.SUPPORTED,
            ),
            *[
                CapabilityBindingEntry(
                    intent_kind=DispositionIntentKind.EXECUTION_RESULT_RECORD,
                    operation_code=name,
                    state=CapabilityState.SUPPORTED,
                )
                for name in response_ops
                if name != TERMINAL_DISPOSITION_TOOL
            ],
        ],
    )


def response_agent_overrides_for_kind(
    kind: str,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Return ResponseAgent kwargs for live Sangfor. Empty for KIND=mock."""
    normalized = (kind or "").strip().lower()
    if normalized != SANGFOR_ADAPTER_KIND:
        return {}
    overlay = overlay_config_from_settings(settings or get_settings())
    return {
        "tool_index": apply_capability_overlay(baseline_tool_index(), overlay),
        "capability_manifest": build_sangfor_capability_manifest(),
    }
