"""Guard-approved agent output publication (ISSUE-270 / ID-SEC-005).

Single ``proposal → guard → publication`` chain: durable writes for RiskAgent and
ReportAgent happen only after OutputGuard approves (or sanitizes) the proposal.
Publication commits canonical DB state in one transaction, then projects to
WorkingMemory / EventBus / snapshot flags.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError as PydanticValidationError

from app.agents.triage_risk_consistency import (
    TRIAGE_RISK_INCONSISTENCY_FLAG,
    should_flag_triage_risk_inconsistency,
)
from app.core.errors import GuardrailViolationError
from app.models.agent_io import RiskAssessment, TriageResult
from app.models.enums import FinalVerdict
from app.models.report import InvestigationReport
from app.services.working_memory import BoundWorkingMemory

logger = logging.getLogger(__name__)

_PUBLICATION_SECRET = object()

_AGENT_PUBLICATION_OPERATORS = frozenset({"RiskAgent", "ReportAgent"})


@dataclass(frozen=True, slots=True)
class GuardApprovedPublication:
    """Opaque capability token issued only after OutputGuard approval."""

    agent_name: str
    event_id: str
    _secret: object = field(default=_PUBLICATION_SECRET, repr=False)

    @classmethod
    def issue(cls, *, agent_name: str, event_id: str) -> GuardApprovedPublication:
        return cls(agent_name=agent_name, event_id=event_id)

    def verify(self) -> None:
        if self._secret is not _PUBLICATION_SECRET:
            raise GuardrailViolationError(
                "invalid guard-approved publication token",
                error_code="guardrail_violation",
                details={"agent_name": self.agent_name, "event_id": self.event_id},
            )


def assert_guard_approved_publication(
    *,
    operator: str | None,
    publication: GuardApprovedPublication | None,
) -> None:
    """Fence legacy agent durable writers during migration (ISSUE-270 §5)."""
    if operator not in _AGENT_PUBLICATION_OPERATORS:
        return
    if publication is None or publication._secret is not _PUBLICATION_SECRET:
        raise GuardrailViolationError(
            f"{operator} durable writes must go through AgentPublicationService "
            "after OutputGuard approval",
            error_code="guardrail_violation",
            details={"operator": operator},
        )


def _revalidate_model(model: type[Any], value: Any) -> Any:
    """Re-validate sanitized proposal before durable publication."""
    if hasattr(value, "model_dump"):
        payload = value.model_dump(mode="json")
    elif isinstance(value, dict):
        payload = value
    else:
        raise GuardrailViolationError(
            "publication proposal is not a structured model",
            error_code="guardrail_violation",
        )
    try:
        return model.model_validate(payload)
    except PydanticValidationError as exc:
        raise GuardrailViolationError(
            "sanitized proposal failed schema re-validation",
            error_code="guardrail_violation",
            details={"errors": exc.errors(include_url=False)},
        ) from exc


class AgentPublicationService:
    """Atomic publication of guard-approved RiskAgent / ReportAgent outputs."""

    def __init__(
        self,
        event_service: Any,
        *,
        degraded_flags: Any | None = None,
        event_bus: Any | None = None,
        context_store: Any | None = None,
    ) -> None:
        self._event_service = event_service
        self._degraded_flags = degraded_flags
        self._event_bus = event_bus
        self._context_store = context_store

    async def publish_risk_assessment(
        self,
        *,
        event_id: str,
        assessment: RiskAssessment,
        verdict: FinalVerdict,
        triage: TriageResult | None,
        working_memory: BoundWorkingMemory | None,
        publication: GuardApprovedPublication,
    ) -> RiskAssessment:
        publication.verify()
        if publication.event_id != event_id or publication.agent_name != "risk_agent":
            raise GuardrailViolationError(
                "publication token scope mismatch for risk_agent",
                error_code="guardrail_violation",
                details={
                    "expected_event_id": publication.event_id,
                    "event_id": event_id,
                    "agent_name": publication.agent_name,
                },
            )

        canonical = _revalidate_model(RiskAssessment, assessment)
        changed, result, summary = await self._event_service.publish_risk_assessment(
            event_id,
            assessment=canonical,
            verdict=verdict,
            operator="RiskAgent",
            publication=publication,
        )

        if working_memory is not None:
            try:
                await working_memory.write(
                    event_id,
                    "risk_assessment",
                    canonical.model_dump(mode="json"),
                )
            except Exception:
                logger.warning(
                    "failed to project risk_assessment to working memory event=%s",
                    event_id,
                    exc_info=True,
                )
                await self._mark_projection_degraded(event_id, "risk_assessment")

        if changed:
            await self._event_service.publish_final_verdict_mutation(
                event_id,
                verdict,
                result=result,
                summary=summary,
            )
        else:
            await self._event_service.sync_event_summary_mutation(
                event_id,
                result=result,
                summary=summary,
            )

        await self._maybe_flag_triage_risk_inconsistency(
            event_id=event_id,
            triage=triage,
            risk_score=canonical.risk_score,
            final_verdict=verdict,
        )
        return canonical

    async def publish_report(
        self,
        *,
        event_id: str,
        report: InvestigationReport,
        working_memory: BoundWorkingMemory | None,
        publication: GuardApprovedPublication,
        plan_revision: int = 1,
        persist_report: bool = True,
    ) -> InvestigationReport:
        publication.verify()
        if publication.event_id != event_id or publication.agent_name != "report_agent":
            raise GuardrailViolationError(
                "publication token scope mismatch for report_agent",
                error_code="guardrail_violation",
                details={
                    "expected_event_id": publication.event_id,
                    "event_id": event_id,
                    "agent_name": publication.agent_name,
                },
            )

        canonical = _revalidate_model(InvestigationReport, report)
        if not persist_report:
            return canonical

        persisted = await self._event_service.publish_investigation_report(
            canonical,
            plan_revision=plan_revision,
            operator="ReportAgent",
            publication=publication,
        )

        if working_memory is not None:
            try:
                await working_memory.write(
                    event_id,
                    "report",
                    persisted.model_dump(mode="json"),
                )
            except Exception:
                logger.warning(
                    "failed to project report to working memory event=%s",
                    event_id,
                    exc_info=True,
                )
                await self._mark_projection_degraded(event_id, "report")

        await self._publish_report_generated(persisted)
        await self._persist_report_generated_flag(event_id, True)
        return persisted

    async def _publish_report_generated(self, report: InvestigationReport) -> None:
        if self._event_bus is None:
            return
        try:
            payload: dict[str, Any] = {
                "report_id": report.report_id,
                "sections": len(report.sections),
            }
            if report.generated_at is not None:
                payload["generated_at"] = report.generated_at.isoformat()
            await self._event_bus.publish_event(
                report.event_id,
                "report_generated",
                payload,
            )
        except Exception:
            logger.warning(
                "event_bus report_generated failed event=%s",
                report.event_id,
                exc_info=True,
            )

    async def _persist_report_generated_flag(self, event_id: str, generated: bool) -> None:
        if self._context_store is not None:
            try:
                await self._context_store.set(event_id, "report_generated", generated)
            except Exception:
                logger.warning(
                    "failed to persist report_generated=%s event=%s",
                    generated,
                    event_id,
                    exc_info=True,
                )
                await self._mark_projection_degraded(event_id, "report_generated")
        try:
            await self._event_service.merge_report_generated_context_snapshot(
                event_id,
                generated,
            )
        except Exception:
            logger.warning(
                "failed to merge report_generated snapshot event=%s",
                event_id,
                exc_info=True,
            )
            await self._mark_projection_degraded(event_id, "report_generated_snapshot")

    async def _maybe_flag_triage_risk_inconsistency(
        self,
        *,
        event_id: str,
        triage: TriageResult | None,
        risk_score: int,
        final_verdict: FinalVerdict,
    ) -> None:
        if triage is None:
            return
        if not should_flag_triage_risk_inconsistency(
            triage=triage,
            risk_score=risk_score,
            final_verdict=final_verdict,
        ):
            return
        if self._degraded_flags is None:
            return
        try:
            await self._degraded_flags.set_flag(
                event_id,
                TRIAGE_RISK_INCONSISTENCY_FLAG,
                True,
                writer="RiskAgent",
            )
        except Exception:
            logger.warning(
                "Failed to persist degraded flag %s for event=%s",
                TRIAGE_RISK_INCONSISTENCY_FLAG,
                event_id,
                exc_info=True,
            )

    async def _mark_projection_degraded(self, event_id: str, field: str) -> None:
        if self._degraded_flags is None:
            return
        try:
            await self._degraded_flags.set_flag(
                event_id,
                "agent_publication_projection_degraded",
                field,
                writer="AgentPublicationService",
            )
        except Exception:
            logger.debug(
                "failed to mark projection degraded event=%s field=%s",
                event_id,
                field,
                exc_info=True,
            )


def generate_report_action_fingerprint(event_id: str, plan_revision: int) -> str:
    material = f"{event_id}|{int(plan_revision)}|generate_report|system|system||immediate|"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


__all__ = [
    "AgentPublicationService",
    "GuardApprovedPublication",
    "assert_guard_approved_publication",
    "generate_report_action_fingerprint",
]
