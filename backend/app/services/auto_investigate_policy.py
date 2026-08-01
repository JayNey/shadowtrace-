"""Auto-investigate eligibility policy (ISSUE-108 / #612)."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import Settings, get_settings
from app.db import models as orm
from app.models.enums import EventStatus, Severity

_PROVISIONAL_LINK_ROLE = "provisional"

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass(frozen=True)
class AutoInvestigateDecision:
    eligible: bool
    reason: str


class AutoInvestigatePolicyService:
    """Evaluate whether a NEW event may receive a durable auto-investigate intent."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def enabled(self) -> bool:
        return bool(self._settings.auto_investigate_enabled)

    def min_severity(self) -> Severity:
        raw = (self._settings.auto_investigate_min_severity or "medium").strip().lower()
        try:
            return Severity(raw)
        except ValueError:
            return Severity.MEDIUM

    def event_type_allowlist(self) -> frozenset[str]:
        raw = (self._settings.auto_investigate_event_types or "").strip()
        if not raw:
            return frozenset()
        return frozenset(item.strip().lower() for item in raw.split(",") if item.strip())

    def evaluate(
        self,
        event: orm.SecurityEvent,
        *,
        link_role: str,
        source_product: str | None = None,
    ) -> AutoInvestigateDecision:
        if not self.enabled:
            return AutoInvestigateDecision(False, "disabled")
        if self._settings.source_mode.strip().lower() != "mock_xdr":
            return AutoInvestigateDecision(False, "source_mode_not_mock_xdr")
        if link_role == _PROVISIONAL_LINK_ROLE:
            return AutoInvestigateDecision(False, "provisional_hold")
        if event.status != EventStatus.NEW.value:
            return AutoInvestigateDecision(False, "status_not_new")
        if not _trusted_mock_provenance(event, source_product=source_product):
            return AutoInvestigateDecision(False, "untrusted_provenance")
        try:
            severity = Severity(str(event.severity).lower())
        except ValueError:
            return AutoInvestigateDecision(False, "invalid_severity")
        if _SEVERITY_RANK[severity] < _SEVERITY_RANK[self.min_severity()]:
            return AutoInvestigateDecision(False, "below_min_severity")
        allowlist = self.event_type_allowlist()
        if allowlist and str(event.event_type).lower() not in allowlist:
            return AutoInvestigateDecision(False, "event_type_not_allowed")
        return AutoInvestigateDecision(True, "auto_investigate:policy_match")


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
    return any("mock" in product for product in products)


__all__ = ["AutoInvestigateDecision", "AutoInvestigatePolicyService"]
