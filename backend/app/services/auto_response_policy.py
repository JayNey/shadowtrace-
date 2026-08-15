"""Optional auto-response eligibility policy (ISSUE-109 / #613 Phase 1)."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import (
    Settings,
    get_settings,
    is_mock_disposition_mode,
    is_mock_source_mode,
    is_mock_tool_mode,
)
from app.db import models as orm
from app.models.enums import ActionLevel, EventStatus, Severity
from app.models.investigation_intent import PRIMARY_LINK_ROLE, PROVISIONAL_LINK_ROLE
from app.models.workflow import AUTO_APPROVABLE_ACTION_LEVELS, parse_action_level_label
from app.services.action_approval_policy import APPROVAL_POLICY_VERSION
from app.services.investigation_guidance import full_loop_available

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass(frozen=True)
class AutoResponseDecision:
    eligible: bool
    reason: str


class AutoResponsePolicyService:
    """Decide whether auto-investigate dispatch may enter the response phase."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def enabled(self) -> bool:
        return bool(self._settings.auto_response_enabled)

    @property
    def policy_version(self) -> str:
        return APPROVAL_POLICY_VERSION

    def min_severity(self) -> Severity:
        raw = (self._settings.auto_response_min_severity or "high").strip().lower()
        try:
            return Severity(raw)
        except ValueError:
            return Severity.HIGH

    def max_auto_level(self) -> ActionLevel:
        """Configured auto-approve ceiling for mock auto-response (#613).

        Used both to validate policy entry and as the runtime ApprovalEngine cap
        while ``AUTO_RESPONSE_ENABLED`` is true.
        """
        raw = self._settings.auto_response_max_auto_level or "L1"
        return parse_action_level_label(raw) or ActionLevel.L1

    def event_type_allowlist(self) -> frozenset[str]:
        raw = (self._settings.auto_response_event_types or "").strip()
        if not raw:
            return frozenset()
        return frozenset(item.strip().lower() for item in raw.split(",") if item.strip())

    def evaluate(
        self,
        event: orm.SecurityEvent,
        *,
        link_role: str,
        source_product: str | None = None,
    ) -> AutoResponseDecision:
        if not self.enabled:
            return AutoResponseDecision(False, "disabled")
        if not full_loop_available(self._settings.orchestration_mode):
            return AutoResponseDecision(False, "orchestration_analysis_only")
        if not is_mock_source_mode(self._settings.source_mode):
            return AutoResponseDecision(False, "source_mode_not_mock_xdr")
        if not is_mock_tool_mode(self._settings.tool_mode):
            return AutoResponseDecision(False, "tool_mode_not_mock")
        if not is_mock_disposition_mode(self._settings.disposition_mode):
            return AutoResponseDecision(False, "disposition_mode_not_mock")
        if link_role == PROVISIONAL_LINK_ROLE:
            return AutoResponseDecision(False, "provisional_hold")
        if link_role != PRIMARY_LINK_ROLE:
            return AutoResponseDecision(False, "link_role_not_primary")
        if event.status != EventStatus.NEW.value:
            return AutoResponseDecision(False, "status_not_new")
        if not _trusted_mock_provenance(event, source_product=source_product):
            return AutoResponseDecision(False, "untrusted_provenance")
        try:
            severity = Severity(str(event.severity).lower())
        except ValueError:
            return AutoResponseDecision(False, "invalid_severity")
        if _SEVERITY_RANK[severity] < _SEVERITY_RANK[self.min_severity()]:
            return AutoResponseDecision(False, "below_min_severity")
        allowlist = self.event_type_allowlist()
        if allowlist and str(event.event_type).lower() not in allowlist:
            return AutoResponseDecision(False, "event_type_not_allowed")
        max_level = self.max_auto_level()
        if max_level not in AUTO_APPROVABLE_ACTION_LEVELS:
            return AutoResponseDecision(False, "max_auto_level_not_auto_approvable")
        return AutoResponseDecision(True, "auto_response:policy_match")


def _trusted_mock_provenance(
    event: orm.SecurityEvent,
    *,
    source_product: str | None,
) -> bool:
    products: list[str] = []
    if source_product:
        products.append(source_product.strip().lower())
    creation = event.creation_source_ref or {}
    product = creation.get("source_product")
    if isinstance(product, str) and product.strip():
        products.append(product.strip().lower())
    if event.source_type:
        products.append(str(event.source_type).strip().lower())
    if not products:
        return False
    return any(is_mock_source_mode(product) for product in products)


def format_auto_response_audit_reason(decision: AutoResponseDecision) -> str:
    """Map policy outcomes to ISSUE-109 audit reason strings."""
    if decision.eligible:
        return decision.reason
    return f"auto_response:skipped_{decision.reason}"


__all__ = ["AutoResponseDecision", "AutoResponsePolicyService", "format_auto_response_audit_reason"]
