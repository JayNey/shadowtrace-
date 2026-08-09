"""Resolve event-level writeback readiness from adapter probes (ISSUE-280).

Readiness recheck must consult real disposition adapter capability,
connectivity, and credential availability — never a fixed placeholder.
"""

from __future__ import annotations

import os
import re
from typing import Any

from app.adapters.disposition.base import BaseDispositionAdapter
from app.models.disposition import SourceObjectLocator
from app.models.enums import (
    CapabilityState,
    ConnectorStatus,
    DispositionIntentKind,
    WritebackReadiness,
)

# Env-style credential refs match adapter config conventions (uppercase NAME).
_ENV_CREDENTIAL_REF = re.compile(r"^[A-Z][A-Z0-9_]*$")


class WritebackReadinessResolver:
    """Map connector + adapter state to ``WritebackReadiness`` for an event locator."""

    async def resolve_for_locator(
        self,
        *,
        locator: SourceObjectLocator,
        connector: Any | None,
        adapter: BaseDispositionAdapter,
    ) -> tuple[WritebackReadiness, str | None]:
        _ = locator  # locator retained for call-site symmetry / future typed filters
        if connector is None:
            return WritebackReadiness.CONNECTOR_UNAVAILABLE, "connector_missing"

        blocked = self._credential_block_reason(connector)
        if blocked is not None:
            return WritebackReadiness.PERMISSION_DENIED, blocked

        try:
            health = await adapter.health_check()
        except Exception:
            return WritebackReadiness.CONNECTOR_UNAVAILABLE, "connector_health_probe_failed"

        if health is ConnectorStatus.OFFLINE:
            return WritebackReadiness.CONNECTOR_UNAVAILABLE, "connector_offline"

        caps = adapter.capabilities()
        intent_state = caps.intents.get(
            DispositionIntentKind.EVENT_STATUS_UPDATE,
            CapabilityState.UNKNOWN,
        )
        if intent_state is CapabilityState.SUPPORTED:
            return WritebackReadiness.READY, None
        if intent_state is CapabilityState.UNSUPPORTED:
            return WritebackReadiness.CAPABILITY_UNSUPPORTED, "capability_unsupported"
        return WritebackReadiness.CAPABILITY_UNKNOWN, "capability_unknown"

    @staticmethod
    def _credential_block_reason(connector: Any) -> str | None:
        cred_ref = getattr(connector, "disposition_credential_ref", None)
        if not cred_ref:
            return None
        ref = str(cred_ref).strip()
        if not ref:
            return None
        # Managed secret URIs (e.g. secret://…) are not env names — do not short-circuit.
        if "://" in ref or not _ENV_CREDENTIAL_REF.fullmatch(ref):
            return None
        if ref not in os.environ:
            return "credential_unavailable"
        return None
