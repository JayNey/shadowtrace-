"""VerifyAgent — two-phase disposition effect verification (ISSUE-060).

Phase 1 (effect): independently observe every IMMEDIATE response/rollback
Action that entered an execution state. POST_VERIFY deferred Actions are
skipped with ``detail=deferred_pending_activation`` and must never appear
in ``failed_actions``.

Phase 2 (disposition): when phase 1 produces no ``need_action_replan`` or
``need_manual_resolution`` and ``disposition_policy=required``, activate
the deferred terminal writeback via ``EventDispositionService``, then
evaluate every required writeback receipt for CONFIRMED.

Routing flags (``need_action_replan`` / ``need_writeback_recovery`` /
``need_manual_resolution``) are orthogonal — only effect failures trigger
action replan; writeback problems stay in the writeback/recovery path.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.base import BaseAgent
from app.agents.rules.verification_mapping import resolve_verification_tool
from app.db import models as orm
from app.models.action import Action
from app.models.agent_io import (
    EffectStatus,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationResult,
    VerifyAgentInput,
)
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionStatus,
    DispositionPolicy,
    ExecutionJobStatus,
    ExecutionOwner,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.execution import ActionExecutionJob

from app.models.tool_meta import ToolResult, ToolResultStatus
from app.services.working_memory import BoundWorkingMemory

logger = logging.getLogger(__name__)

# ── Writeback status → phase‑2 routing table (ISSUE-060 acceptance step 5) ──
# Returns (confirmed: bool, need_recovery: bool, need_manual: bool, detail_suffix)
_WRITEBACK_STATUS_ROUTING: dict[
    WritebackStatus | None, tuple[bool, bool, bool, str]
] = {
    WritebackStatus.CONFIRMED: (True, False, False, "writeback_confirmed"),
    WritebackStatus.PENDING: (False, True, False, "writeback_pending_waiting"),
    WritebackStatus.SENDING: (False, True, False, "writeback_sending_waiting"),
    WritebackStatus.ACCEPTED: (False, True, False, "writeback_accepted_waiting"),
    WritebackStatus.UNKNOWN: (False, False, True, "writeback_unknown_requires_lookup"),
    WritebackStatus.PARTIAL: (False, True, False, "writeback_partial_recovery"),
    WritebackStatus.FAILED: (False, True, False, "writeback_failed_recovery"),
    WritebackStatus.CONFLICT: (False, False, True, "writeback_conflict_manual"),
    None: (False, True, False, "writeback_no_status_waiting"),
}

# Actions whose observable entity effect is not verifiable via tool observation.
_SKIP_VERIFICATION_TOOLS: frozenset[str] = frozenset(
    {"create_ticket", "close_false_positive_ticket", "notify_security_team"}
)

# Terminal / non-terminal job statuses for effect evaluation.
_TERMINAL_JOB_STATUSES: frozenset[ExecutionJobStatus] = frozenset(
    {
        ExecutionJobStatus.SUCCESS,
        ExecutionJobStatus.PARTIAL_SUCCESS,
        ExecutionJobStatus.FAILED,
        ExecutionJobStatus.TIMED_OUT,
        ExecutionJobStatus.CANCELLED,
    }
)

# Effect‑side action execution statuses the VerifyAgent considers.
# ActionStatus.EXECUTING is deliberately excluded — asynchronous actions
# that are still running must not be prematurely verified (their effect
# may not have materialised yet, which would produce false FAILED results
# and trigger unnecessary re-planning).
_EXECUTED_STATUSES: frozenset[ActionStatus] = frozenset(
    {
        ActionStatus.SUCCESS,
        ActionStatus.PARTIAL_SUCCESS,
        ActionStatus.FAILED,
        ActionStatus.UNKNOWN,
    }
)

_VERIFY_OPERATOR = "VerifyAgent"


# ── EventDispositionService protocol (ISSUE-059A) ──
# Not yet implemented; the agent accepts an optional callable matching this
# signature. When absent, phase 2 marks need_manual_resolution=true.


class _ActivateResult:
    """Minimal result envelope from EventDispositionService.activate_and_submit."""

    def __init__(
        self,
        *,
        success: bool,
        terminal_writeback_id: str | None = None,
        terminal_disposition_id: str | None = None,
        error_code: str | None = None,
        error_detail: str | None = None,
    ) -> None:
        self.success = success
        self.terminal_writeback_id = terminal_writeback_id
        self.terminal_disposition_id = terminal_disposition_id
        self.error_code = error_code
        self.error_detail = error_detail


# --------------------------------------------------------------------------- #
# VerifyAgent
# --------------------------------------------------------------------------- #


class VerifyAgent(BaseAgent[VerifyAgentInput, VerificationResult]):
    """Two-phase verification of response actions and disposition writebacks."""

    agent_name = "verify_agent"

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        tool_executor: Any | None = None,
        working_memory: BoundWorkingMemory | None = None,
        budget_service: Any | None = None,
        output_guard: Any | None = None,
        trace_service: Any | None = None,
        audit_service: Any | None = None,
        event_bus: Any | None = None,
        # VerifyAgent‑specific dependencies
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        event_disposition_service: Any | None = None,
        disposition_sync_service: Any | None = None,
    ) -> None:
        super().__init__(
            llm_client=llm_client,
            tool_executor=tool_executor,
            working_memory=working_memory,
            budget_service=budget_service,
            output_guard=output_guard,
            trace_service=trace_service,
            audit_service=audit_service,
            event_bus=event_bus,
        )
        self._session_factory = session_factory
        self._event_disposition_service = event_disposition_service
        self._disposition_sync_service = disposition_sync_service

    # ------------------------------------------------------------------ #
    # _run
    # ------------------------------------------------------------------ #

    async def _run(self, input: VerifyAgentInput) -> VerificationResult:
        event_id = input.event_id
        response_plan = input.response_plan

        # 1. Load actions & execution context from the database.
        disposition_policy = await self._load_disposition_policy(event_id)
        actions, jobs_map, outbox_map = await self._load_execution_state(
            event_id, response_plan
        )

        # 2. Phase 1 — entity effect verification for IMMEDIATE actions.
        phase1_results, phase1_failed, phase1_need_replan, phase1_need_manual = (
            await self._verify_phase1_effects(
                event_id=event_id,
                actions=actions,
                jobs_map=jobs_map,
            )
        )

        # 3. Phase 2 — terminal writeback activation & verification.
        (
            phase2_results,
            phase2_failed_wb,
            phase2_blocked_wb,
            overall_status,
            need_wb_recovery,
            need_manual,
        ) = await self._verify_phase2_disposition(
            event_id=event_id,
            disposition_policy=disposition_policy,
            phase1_need_replan=phase1_need_replan,
            phase1_need_manual=phase1_need_manual,
            actions=actions,
            jobs_map=jobs_map,
            outbox_map=outbox_map,
        )

        # 4. Assemble final result.
        all_results = phase1_results + phase2_results
        failed_actions = list(phase1_failed)
        failed_writebacks = list(phase2_failed_wb)
        blocked_writebacks = list(phase2_blocked_wb)

        need_action_replan = phase1_need_replan
        need_writeback_recovery = need_wb_recovery
        need_manual_resolution = phase1_need_manual or need_manual

        # None of the routing flags may be set when overall_status=success.
        if overall_status == VerificationOverallStatus.SUCCESS:
            need_action_replan = False
            need_writeback_recovery = False
            need_manual_resolution = False
        elif overall_status == VerificationOverallStatus.PARTIAL:
            # Partial may still need replan on the failed subset.
            need_action_replan = phase1_need_replan
        elif overall_status == VerificationOverallStatus.WAITING:
            need_action_replan = False
        elif overall_status == VerificationOverallStatus.MANUAL_RESOLUTION:
            need_action_replan = False
            need_manual_resolution = True

        result = VerificationResult(
            results=all_results,
            overall_status=overall_status,
            failed_actions=failed_actions,
            failed_writebacks=failed_writebacks,
            blocked_writebacks=blocked_writebacks,
            need_action_replan=need_action_replan,
            need_writeback_recovery=need_writeback_recovery,
            need_manual_resolution=need_manual_resolution,
            verification_phase=input.verification_phase,
        )

        # 5. Persist verification result to working memory.
        await self._write_verification_result(event_id, result)

        # 6. Publish action_verified events.
        await self._publish_action_verified_events(event_id, result)

        return result

    # ------------------------------------------------------------------ #
    # Phase 1 — effect verification
    # ------------------------------------------------------------------ #

    async def _verify_phase1_effects(
        self,
        *,
        event_id: str,
        actions: list[Action],
        jobs_map: dict[str, ActionExecutionJob],
    ) -> tuple[
        list[VerificationActionResult],
        set[str],
        bool,
        bool,
    ]:
        """Verify IMMEDIATE entity effects. Returns (results, failed_ids, replan, manual)."""
        results: list[VerificationActionResult] = []
        failed_action_ids: set[str] = set()
        need_replan = False
        need_manual = False

        for action in actions:
            # POST_VERIFY deferred → skipped, never in failed_actions.
            if action.execution_phase is ActionExecutionPhase.POST_VERIFY:
                results.append(
                    _make_skipped_result(
                        action,
                        detail="deferred_pending_activation",
                    )
                )
                continue

            # Actions without execution phase = IMMEDIATE implicitly.
            # Still executing → skip (don't verify prematurely; the async
            # effect may not have materialised yet).
            if action.status is ActionStatus.EXECUTING:
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.SKIPPED,
                        writeback_required=action.writeback_required,
                        writeback_readiness=action.writeback_readiness,
                        writeback_status=action.writeback_status,
                        writeback_ids=[],
                        detail="pending_execution",
                    )
                )
                continue

            # Not executed yet → skip (not an error).
            if action.status not in _EXECUTED_STATUSES:
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.SKIPPED,
                        writeback_required=action.writeback_required,
                        writeback_readiness=action.writeback_readiness,
                        writeback_status=None,
                        writeback_ids=[],
                        detail="action_not_executed",
                    )
                )
                continue

            # Verification/system actions are self-verifying.
            if action.action_category in (
                ActionCategory.VERIFICATION,
                ActionCategory.SYSTEM,
            ):
                results.append(
                    _make_self_verifying_result(action)
                )
                continue

            # Determine the verification tool.
            verify_tool = resolve_verification_tool(
                action.tool_name,
                action.target_type,
            )

            # No verification tool registered → treat as non-verifiable (skipped).
            if verify_tool is None:
                detail = "no_verification_tool_registered"
                if action.tool_name in _SKIP_VERIFICATION_TOOLS:
                    detail = "non_verifiable_action"
                results.append(
                    _make_skipped_result(action, detail=detail)
                )
                continue

            # Execute the verification tool (independent observation).
            job = jobs_map.get(action.action_id)
            result = await self._run_verification_tool(
                event_id=event_id,
                action=action,
                verify_tool=verify_tool,
                job=job,
            )
            results.append(result)

            # Classify effect status for routing.
            if result.effect_status is EffectStatus.VERIFIED:
                continue
            elif result.effect_status is EffectStatus.UNVERIFIABLE:
                need_manual = True
            elif result.effect_status is EffectStatus.FAILED:
                failed_action_ids.add(action.action_id)
                need_replan = True
            # SKIPPED does not trigger replan/failed.

        return results, failed_action_ids, need_replan, need_manual

    async def _run_verification_tool(
        self,
        *,
        event_id: str,
        action: Action,
        verify_tool: str,
        job: ActionExecutionJob | None,
    ) -> VerificationActionResult:
        """Run one verification tool observation and classify the result."""
        verification_action_id: str | None = None
        verification_action: Action | None = None

        try:
            # Persist a verification Action.
            verification_action = await self._create_verification_action(
                event_id=event_id,
                source_action=action,
                verify_tool=verify_tool,
            )
            verification_action_id = verification_action.action_id

            params: dict[str, Any] = {
                "target_type": action.target_type or "",
                "target": action.target or "",
            }
            if job is not None:
                params["parameters"] = {"job_id": job.job_id}

            tool_result: ToolResult | None = None
            if self.tool_executor is not None:
                tool_result = await self.tool_executor.call(
                    tool_name=verify_tool,
                    params=params,
                    event_id=event_id,
                )

            if tool_result is None:
                effect_status = EffectStatus.UNVERIFIABLE
                detail = "verification_tool_unavailable_degraded"
            elif tool_result.status == ToolResultStatus.SUCCESS:
                data = tool_result.data or {}
                is_verified = data.get("is_verified", False)
                if is_verified:
                    effect_status = EffectStatus.VERIFIED
                    detail = "effect_verified"
                else:
                    effect_status = EffectStatus.FAILED
                    detail = data.get("detail", "effect_not_observed")
                await self._finalize_verification_action(
                    verification_action,
                    target_status=ActionStatus.SUCCESS,
                )
            elif tool_result.status == ToolResultStatus.FAILED:
                effect_status = EffectStatus.UNVERIFIABLE
                detail = f"verification_tool_error: {tool_result.error_detail or 'unknown'}"
                await self._finalize_verification_action(
                    verification_action,
                    target_status=ActionStatus.FAILED,
                )
            else:
                effect_status = EffectStatus.UNVERIFIABLE
                detail = f"verification_tool_status_{tool_result.status.value}"
                await self._finalize_verification_action(
                    verification_action,
                    target_status=ActionStatus.UNKNOWN,
                )
        except Exception as exc:
            logger.warning(
                "Verification tool %s failed for action %s: %s",
                verify_tool,
                action.action_id,
                exc,
            )
            effect_status = EffectStatus.UNVERIFIABLE
            # Sanitise: only expose the exception type name, not the full
            # message (which may contain IPs, paths, or provider internals).
            # The full traceback is logged above for debugging.
            detail = f"verification_exception: {type(exc).__name__}"
            try:
                if verification_action is not None:
                    await self._finalize_verification_action(
                        verification_action,
                        target_status=ActionStatus.FAILED,
                    )
            except Exception:
                logger.warning(
                    "Failed to finalize verification action %s during exception"
                    " handling for source action %s",
                    verification_action_id,
                    action.action_id,
                    exc_info=True,
                )

        # Build writeback fields for this action.
        wb_required = action.writeback_required
        wb_readiness = action.writeback_readiness
        wb_status = action.writeback_status

        if effect_status is EffectStatus.UNVERIFIABLE:
            # writeback_required preserves the business obligation — it must
            # never be reversed by technical unavailability (§4.5 item 6).
            # The model validator on VerificationActionResult permits
            # writeback_required=True + writeback_readiness=NOT_REQUIRED
            # + writeback_status=None when effect_status=UNVERIFIABLE.
            wb_readiness = WritebackReadiness.NOT_REQUIRED
            wb_status = None

        return VerificationActionResult(
            action_id=action.action_id,
            effect_status=effect_status,
            writeback_required=wb_required,
            writeback_readiness=wb_readiness,
            writeback_status=wb_status,
            writeback_ids=[],
            verification_action_id=verification_action_id,
            detail=detail,
        )

    # ------------------------------------------------------------------ #
    # Phase 2 — writeback activation & verification
    # ------------------------------------------------------------------ #

    async def _verify_phase2_disposition(
        self,
        *,
        event_id: str,
        disposition_policy: DispositionPolicy | None,
        phase1_need_replan: bool,
        phase1_need_manual: bool,
        actions: list[Action],
        jobs_map: dict[str, ActionExecutionJob],
        outbox_map: dict[str, list[Any]],
    ) -> tuple[
        list[VerificationActionResult],
        set[str],
        set[str],
        VerificationOverallStatus,
        bool,  # need_writeback_recovery
        bool,  # need_manual_resolution
    ]:
        """Phase 2: activate deferred terminal writeback, then verify receipts."""
        results: list[VerificationActionResult] = []
        failed_wb: set[str] = set()
        blocked_wb: set[str] = set()
        need_wb_recovery = False
        need_manual = False
        overall_status = VerificationOverallStatus.SUCCESS

        # If phase 1 already requires replan or manual, skip activation.
        if phase1_need_replan or phase1_need_manual:
            logger.info(
                "Phase 2 skipped: phase1 need_replan=%s need_manual=%s event=%s",
                phase1_need_replan,
                phase1_need_manual,
                event_id,
            )
            if phase1_need_replan:
                overall_status = VerificationOverallStatus.PARTIAL
            elif phase1_need_manual:
                overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
            return results, failed_wb, blocked_wb, overall_status, need_wb_recovery, need_manual

        # If disposition is not required, no writeback to verify.
        if disposition_policy is DispositionPolicy.NOT_REQUIRED:
            logger.info("Phase 2 skipped: disposition_policy=not_required event=%s", event_id)
            return results, failed_wb, blocked_wb, overall_status, need_wb_recovery, need_manual

        # disposition_policy is None or REQUIRED:
        # Attempt to activate deferred terminal writeback.
        terminal_activated = False
        has_ed_svc = self._event_disposition_service is not None
        if disposition_policy is DispositionPolicy.REQUIRED and has_ed_svc:
            try:
                activate_result: _ActivateResult = (
                    await self._event_disposition_service.activate_and_submit(
                        event_id=event_id,
                    )
                )
                terminal_activated = activate_result.success
                if not terminal_activated:
                    logger.warning(
                        "Phase 2 activation failed: %s event=%s",
                        activate_result.error_code,
                        event_id,
                    )
                    need_manual = True
                    blocked_wb.add(
                        activate_result.terminal_writeback_id
                        or f"terminal_wb_{event_id}"
                    )
                    overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
            except Exception as exc:
                logger.error(
                    "Phase 2 activation exception event=%s: %s",
                    event_id,
                    exc,
                )
                need_manual = True
                overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
        elif disposition_policy is DispositionPolicy.REQUIRED:
            # No EventDispositionService available → manual resolution.
            logger.warning(
                "Phase 2 activation unavailable: no EventDispositionService event=%s",
                event_id,
            )
            need_manual = True
            overall_status = VerificationOverallStatus.MANUAL_RESOLUTION

        # Evaluate writeback statuses for all applicable required actions.
        # Only do this when activation succeeded — if activation failed we
        # are already in MANUAL_RESOLUTION and evaluating "stale" writeback
        # receipts would produce misleading routing decisions.
        if terminal_activated:
            wb_eval = await self._evaluate_writeback_statuses(
                event_id=event_id,
                actions=actions,
                outbox_map=outbox_map,
            )
            results = wb_eval["results"]
            failed_wb = wb_eval["failed_wb"]
            blocked_wb = wb_eval["blocked_wb"]
            need_wb_recovery = wb_eval["need_recovery"]
            need_manual_from_wb = wb_eval["need_manual"]

            if need_manual_from_wb:
                need_manual = True
                if overall_status == VerificationOverallStatus.SUCCESS:
                    overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
            if need_wb_recovery:
                if overall_status == VerificationOverallStatus.SUCCESS:
                    overall_status = VerificationOverallStatus.WAITING
            if failed_wb:
                if overall_status not in (
                    VerificationOverallStatus.MANUAL_RESOLUTION,
                    VerificationOverallStatus.FAILED,
                ):
                    overall_status = VerificationOverallStatus.PARTIAL

        return results, failed_wb, blocked_wb, overall_status, need_wb_recovery, need_manual

    async def _evaluate_writeback_statuses(
        self,
        *,
        event_id: str,
        actions: list[Action],
        outbox_map: dict[str, list[Any]],
    ) -> dict[str, Any]:
        """Evaluate writeback status for every applicable required action."""
        results: list[VerificationActionResult] = []
        failed_wb: set[str] = set()
        blocked_wb: set[str] = set()
        need_recovery = False
        need_manual = False

        for action in actions:
            if action.action_category not in (
                ActionCategory.RESPONSE,
                ActionCategory.ROLLBACK,
            ):
                continue
            if not action.writeback_required:
                continue
            if action.superseded_by_revision is not None:
                continue
            if action.status is ActionStatus.REJECTED:
                continue
            # POST_VERIFY deferred actions are handled by phase 2 activation,
            # not by direct writeback status evaluation.
            if action.execution_phase is ActionExecutionPhase.POST_VERIFY:
                continue

            wb_status = action.writeback_status
            wb_readiness = action.writeback_readiness
            wb_ids = await self._collect_writeback_ids(event_id, action, outbox_map)

            if not action.writeback_applicable:
                # Obligation exists at the event level but doesn't land on
                # this specific action.  The VerificationActionResult must
                # satisfy its own validator, so writeback_required is set to
                # False here — the CLOSED gate still checks the event-level
                # obligation separately.
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.SKIPPED,
                        writeback_required=False,
                        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                        writeback_status=None,
                        writeback_ids=wb_ids,
                        detail="writeback_not_applicable",
                    )
                )
                continue

            # Required but not READY → blocked.
            if wb_readiness is not WritebackReadiness.READY:
                blocked_wb.add(action.action_id)
                need_manual = True
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.SKIPPED,
                        writeback_required=True,
                        writeback_readiness=wb_readiness,
                        writeback_status=None,
                        writeback_ids=wb_ids,
                        detail=f"writeback_blocked_{wb_readiness.value}",
                    )
                )
                continue

            # READY — evaluate the eight WritebackStatus values.
            routing = _WRITEBACK_STATUS_ROUTING.get(
                wb_status,
                (False, True, False, "writeback_status_unknown"),
            )
            confirmed, rec, man, detail_suffix = routing

            if confirmed:
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.VERIFIED,
                        writeback_required=True,
                        writeback_readiness=wb_readiness,
                        writeback_status=wb_status,
                        writeback_ids=wb_ids,
                        detail=detail_suffix,
                    )
                )
            elif man:
                need_manual = True
                blocked_wb.add(action.action_id)
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.UNVERIFIABLE,
                        writeback_required=True,
                        writeback_readiness=wb_readiness,
                        writeback_status=wb_status,
                        writeback_ids=wb_ids,
                        detail=detail_suffix,
                    )
                )
            else:
                # Recovery path: PENDING / SENDING / ACCEPTED / PARTIAL / FAILED
                need_recovery = True
                if wb_status in (WritebackStatus.FAILED, WritebackStatus.PARTIAL):
                    failed_wb.add(action.action_id)
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.VERIFIED,
                        writeback_required=True,
                        writeback_readiness=wb_readiness,
                        writeback_status=wb_status,
                        writeback_ids=wb_ids,
                        detail=detail_suffix,
                    )
                )

        return {
            "results": results,
            "failed_wb": failed_wb,
            "blocked_wb": blocked_wb,
            "need_recovery": need_recovery,
            "need_manual": need_manual,
        }

    # ------------------------------------------------------------------ #
    # Data loading
    # ------------------------------------------------------------------ #

    async def _load_execution_state(
        self,
        event_id: str,
        response_plan: Any,
    ) -> tuple[
        list[Action],
        dict[str, ActionExecutionJob],
        dict[str, list[Any]],
    ]:
        """Load Actions, Jobs, and Outbox records from the database."""
        if self._session_factory is None:
            return _plan_actions(response_plan), {}, {}

        async with self._session_factory() as session:
            # Load persisted Actions for this event's current plan revision.
            action_ids = [a.action_id for a in _plan_actions(response_plan)]
            actions: list[Action] = []
            if action_ids:
                rows = (
                    await session.scalars(
                        select(orm.Action).where(orm.Action.action_id.in_(action_ids))
                    )
                ).all()
                actions = [_action_from_row(r) for r in rows]
            if not actions:
                actions = _plan_actions(response_plan)

            # Load jobs.
            job_ids = [a.execution_job_id for a in actions if a.execution_job_id]
            jobs_map: dict[str, ActionExecutionJob] = {}
            if job_ids:
                job_rows = (
                    await session.scalars(
                        select(orm.ActionExecutionJob).where(
                            orm.ActionExecutionJob.job_id.in_(job_ids)
                        )
                    )
                ).all()
                jobs_map = {r.job_id: _job_from_row(r) for r in job_rows}

            # Load outbox records.
            outbox_map: dict[str, list[Any]] = {}
            if action_ids:
                outbox_rows = (
                    await session.scalars(
                        select(orm.DispositionOutbox).where(
                            orm.DispositionOutbox.action_id.in_(action_ids)
                        )
                    )
                ).all()
                for r in outbox_rows:
                    outbox_map.setdefault(r.action_id, []).append(r)

            return actions, jobs_map, outbox_map

    async def _load_disposition_policy(
        self, event_id: str
    ) -> DispositionPolicy | None:
        """Read disposition_policy from the event row or working memory."""
        # Attempt reading from working memory first.  disposition_policy is
        # stored on the SecurityEvent row, not on triage_result — but some
        # codepaths may cache it in working memory under the event key.
        if self.working_memory is not None:
            try:
                policy_raw = await self.working_memory.read(
                    event_id, "disposition_policy"
                )
                if policy_raw is not None:
                    if isinstance(policy_raw, DispositionPolicy):
                        return policy_raw
                    if isinstance(policy_raw, str):
                        return DispositionPolicy(policy_raw)
            except Exception:
                pass

        if self._session_factory is None:
            return None

        async with self._session_factory() as session:
            event_row = await session.get(orm.SecurityEvent, event_id)
            if event_row is not None and event_row.disposition_policy:
                return DispositionPolicy(event_row.disposition_policy)
            return None

    async def _collect_writeback_ids(
        self,
        event_id: str,
        action: Action,
        outbox_map: dict[str, list[Any]],
    ) -> list[str]:
        """Collect writeback IDs associated with an action."""
        wb_ids: list[str] = []
        outboxes = outbox_map.get(action.action_id, [])
        for ob in outboxes:
            # Direct attribute access — getattr(ob, "writeback_id", None)
            # silently returns [] on field renames, masking refactor bugs.
            wb_id = ob.writeback_id
            if wb_id:
                wb_ids.append(wb_id)
        return wb_ids

    # ------------------------------------------------------------------ #
    # Verification action lifecycle
    # ------------------------------------------------------------------ #

    async def _create_verification_action(
        self,
        *,
        event_id: str,
        source_action: Action,
        verify_tool: str,
    ) -> Action:
        """Persist a verification Action and transition PENDING → EXECUTING.

        Verification actions: action_category=verification,
        execution_owner=null, writeback_required=false.
        """
        action_id = _deterministic_verification_action_id(
            event_id=event_id,
            source_action_id=source_action.action_id,
            verify_tool=verify_tool,
        )
        verification_action = Action(
            action_id=action_id,
            event_id=event_id,
            plan_revision=source_action.plan_revision,
            action_fingerprint=f"verify:{verify_tool}:{source_action.action_id}",
            action_category=ActionCategory.VERIFICATION,
            action_name=f"verify_{source_action.action_name}",
            tool_name=verify_tool,
            action_level=source_action.action_level,
            execution_phase=ActionExecutionPhase.IMMEDIATE,
            target_type=source_action.target_type,
            target=source_action.target,
            parameters={
                "target_type": source_action.target_type,
                "target": source_action.target,
                "source_action_id": source_action.action_id,
            },
            status=ActionStatus.EXECUTING,
            execution_owner=None,
            writeback_required=False,
            writeback_applicable=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            writeback_status=None,
        )

        if self._session_factory is not None:
            try:
                async with self._session_factory() as session:
                    async with session.begin():
                        row = orm.Action(
                            action_id=verification_action.action_id,
                            event_id=verification_action.event_id,
                            plan_revision=verification_action.plan_revision,
                            action_fingerprint=verification_action.action_fingerprint,
                            action_category=verification_action.action_category.value,
                            action_name=verification_action.action_name,
                            tool_name=verification_action.tool_name,
                            action_level=verification_action.action_level.value,
                            execution_phase=verification_action.execution_phase.value,
                            target_type=verification_action.target_type,
                            target=verification_action.target,
                            parameters=verification_action.parameters,
                            status=verification_action.status.value,
                            execution_owner=None,
                            writeback_required=False,
                            writeback_applicable=False,
                            writeback_readiness=verification_action.writeback_readiness.value,
                        )
                        session.add(row)
            except Exception as exc:
                logger.warning(
                    "Failed to persist verification action %s: %s",
                    action_id,
                    exc,
                )

        return verification_action

    async def _finalize_verification_action(
        self,
        action: Action,
        *,
        target_status: ActionStatus,
    ) -> None:
        """Transition a verification Action to its terminal status."""
        action.status = target_status
        if self._session_factory is not None:
            try:
                async with self._session_factory() as session:
                    async with session.begin():
                        row = await session.get(
                            orm.Action,
                            action.action_id,
                            with_for_update=True,
                        )
                        if row is not None:
                            row.status = target_status.value
                            row.updated_at = datetime.now(UTC)
            except Exception as exc:
                logger.warning(
                    "Failed to finalize verification action %s: %s",
                    action.action_id,
                    exc,
                )

    # ------------------------------------------------------------------ #
    # Working memory & event bus
    # ------------------------------------------------------------------ #

    async def _write_verification_result(
        self,
        event_id: str,
        result: VerificationResult,
    ) -> None:
        """Persist the VerificationResult to EventContext via WorkingMemory."""
        if self.working_memory is None:
            return
        try:
            await self.working_memory.write(
                event_id,
                "verification_result",
                result.model_dump(mode="json"),
            )
        except Exception as exc:
            logger.warning(
                "Failed to write verification_result for event=%s: %s",
                event_id,
                exc,
            )

    async def _publish_action_verified_events(
        self,
        event_id: str,
        result: VerificationResult,
    ) -> None:
        """Publish action_verified SocketEvent for each per-action result."""
        if self.event_bus is None:
            return
        for item in result.results:
            try:
                await self.event_bus.publish_event(
                    event_id,
                    "action_verified",
                    {
                        "action_id": item.action_id,
                        "effect_status": item.effect_status.value,
                        "writeback_status": (
                            item.writeback_status.value
                            if item.writeback_status
                            else None
                        ),
                        "verification_action_id": item.verification_action_id,
                        "detail": item.detail,
                    },
                )
            except Exception:
                logger.debug(
                    "event_bus action_verified failed event=%s action=%s",
                    event_id,
                    item.action_id,
                    exc_info=True,
                )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _plan_actions(response_plan: Any) -> list[Action]:
    """Extract Action list from a ResponsePlan object or dict."""
    if hasattr(response_plan, "actions"):
        return list(response_plan.actions)
    if isinstance(response_plan, dict):
        raw = response_plan.get("actions", [])
        return [Action.model_validate(a) if isinstance(a, dict) else a for a in raw]
    return []


def _make_skipped_result(
    action: Action,
    *,
    detail: str,
) -> VerificationActionResult:
    """Build a skipped VerificationActionResult with writeback fields that
    are consistent with the VerificationActionResult validator.

    For deferred POST_VERIFY actions that are writeback_required but not yet
    applicable, the writeback fields report the obligation as not (yet) active
    so the validator accepts the combination.
    """
    wb_required = action.writeback_required and action.writeback_applicable
    wb_readiness = (
        action.writeback_readiness
        if wb_required
        else WritebackReadiness.NOT_REQUIRED
    )
    wb_status = action.writeback_status if wb_required else None
    return VerificationActionResult(
        action_id=action.action_id,
        effect_status=EffectStatus.SKIPPED,
        writeback_required=wb_required,
        writeback_readiness=wb_readiness,
        writeback_status=wb_status,
        writeback_ids=[],
        detail=detail,
    )


def _make_self_verifying_result(action: Action) -> VerificationActionResult:
    """Verification/system actions don't need external observation."""
    return VerificationActionResult(
        action_id=action.action_id,
        effect_status=EffectStatus.VERIFIED,
        writeback_required=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        writeback_status=None,
        writeback_ids=[],
        detail="self_verifying",
    )


def _action_from_row(row: orm.Action) -> Action:
    """Reconstruct Action domain model from ORM row."""
    return Action(
        action_id=row.action_id,
        event_id=row.event_id,
        plan_revision=row.plan_revision,
        action_fingerprint=row.action_fingerprint,
        action_category=ActionCategory(row.action_category),
        action_name=row.action_name,
        tool_name=row.tool_name,
        action_level=row.action_level,
        execution_phase=(
            ActionExecutionPhase(row.execution_phase)
            if row.execution_phase
            else ActionExecutionPhase.IMMEDIATE
        ),
        activation_condition=row.activation_condition,
        approved_operation_template_hash=row.approved_operation_template_hash,
        approved_terminal_dispositions=row.approved_terminal_dispositions or [],
        target_type=row.target_type,
        target=row.target,
        parameters=row.parameters or {},
        status=ActionStatus(row.status),
        auto_execute=row.auto_execute,
        reason=row.reason,
        provider_name=row.provider_name,
        execution_owner=(
            ExecutionOwner(row.execution_owner)
            if row.execution_owner
            else None
        ),
        execution_job_id=row.execution_job_id,
        tool_call_id=row.tool_call_id,
        idempotency_key=row.idempotency_key,
        writeback_required=bool(row.writeback_required),
        writeback_applicable=bool(row.writeback_applicable),
        writeback_readiness=(
            WritebackReadiness(row.writeback_readiness)
            if row.writeback_readiness
            else WritebackReadiness.NOT_REQUIRED
        ),
        writeback_block_reason=row.writeback_block_reason,
        writeback_status=(
            WritebackStatus(row.writeback_status)
            if row.writeback_status
            else None
        ),
        disposition_source_ref=row.disposition_source_ref,
        superseded_by_revision=row.superseded_by_revision,
        executed_at=row.executed_at,
        effect_verification_status=row.effect_verification_status,
        rollback_status=(
            ActionStatus(row.rollback_status)
            if row.rollback_status
            else None
        ),
        source_action_id=row.source_action_id,
        updated_at=row.updated_at,
    )


def _job_from_row(row: orm.ActionExecutionJob) -> ActionExecutionJob:
    """Reconstruct ActionExecutionJob domain model from ORM row."""
    return ActionExecutionJob(
        job_id=row.job_id,
        event_id=row.event_id,
        action_id=row.action_id,
        provider_name=row.provider_name,
        idempotency_key=row.idempotency_key,
        provider_job_id=row.provider_job_id,
        status=ExecutionJobStatus(row.status),
        claimed_by=row.claimed_by,
        lease_expires_at=row.lease_expires_at,
        poll_after_ms=row.poll_after_ms,
        attempt=row.attempt,
        provider_code=row.provider_code,
        provider_message=row.provider_message,
        raw_result=row.raw_result or {},
        created_at=row.created_at,
        updated_at=row.updated_at,
        started_at=row.started_at,
        finished_at=row.finished_at,
    )


__all__ = [
    "VerifyAgent",
]


def _deterministic_verification_action_id(
    *,
    event_id: str,
    source_action_id: str,
    verify_tool: str,
) -> str:
    """Derive a deterministic action_id for a verification Action.

    Uses SHA-256(event_id + source_action_id + verify_tool) so that if
    VerifyAgent crashes after writing the verification_result to
    WorkingMemory but before the trace record completes, re-execution
    produces the SAME action_id — the ORM insert becomes an idempotent
    upsert (the database layer must treat duplicate-action-id as a
    no-op or use INSERT … ON CONFLICT DO NOTHING).
    """
    digest = hashlib.sha256(
        f"verify:{event_id}:{source_action_id}:{verify_tool}".encode("utf-8")
    ).hexdigest()[:8]
    return f"act-{digest}"
