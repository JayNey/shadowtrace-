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
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.base import BaseAgent
from app.agents.rules.verification_mapping import (
    VERIFICATION_MAPPING,
    resolve_verification_tool,
    validate_verification_tool_params,
)
from app.db import models as orm
from app.models.action import Action
from app.models.agent_io import (
    EffectStatus,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationResult,
    VerifyAgentInput,
)
from app.models.disposition import SourceObjectLocator
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
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
_WRITEBACK_STATUS_ROUTING: dict[WritebackStatus, tuple[bool, bool, bool, str]] = {
    WritebackStatus.CONFIRMED: (True, False, False, "writeback_confirmed"),
    WritebackStatus.PENDING: (False, True, False, "writeback_pending_waiting"),
    WritebackStatus.SENDING: (False, True, False, "writeback_sending_waiting"),
    WritebackStatus.ACCEPTED: (False, True, False, "writeback_accepted_waiting"),
    # UNKNOWN → recovery (not manual). Per ISSUE-060 spec §4.5:
    # "UNKNOWN→先查证、无法查证时 need_manual_resolution=true".
    # WritebackRecoveryHandler (ISSUE-062) will attempt a provider-side
    # lookup first; manual resolution is the fallback only when lookup
    # is infeasible.  Before ISSUE-062 lands, the recovery flag still
    # correctly signals "don't give up yet" — the caller can poll the
    # writeback status or escalate after a timeout.
    #
    # TODO(ISSUE-062): The current routing maps UNKNOWN → need_recovery=True,
    # need_manual=False, which sends the writeback into an infinite recovery
    # loop with no timeout or retry-exhaustion guard.  ISSUE-062
    # (WritebackRecoveryHandler) must implement the second half of §4.5:
    # when provider-side lookup is infeasible, set need_manual_resolution=True
    # so the writeback is promoted to an operator-facing resolution path.
    # Until then, callers that observe UNKNOWN writebacks should impose their
    # own timeout (e.g. 3 recovery cycles → escalate to need_manual=True).
    WritebackStatus.UNKNOWN: (False, True, False, "writeback_unknown_requires_lookup"),
    WritebackStatus.PARTIAL: (False, True, False, "writeback_partial_recovery"),
    WritebackStatus.FAILED: (False, True, False, "writeback_failed_recovery"),
    WritebackStatus.CONFLICT: (False, False, True, "writeback_conflict_manual"),
    # None key intentionally omitted — callers must handle wb_status is None
    # explicitly before consulting this table.  See _evaluate_writeback_statuses
    # for the explicit None check.
}


# Exception types that indicate transient infrastructure failures rather
# than permanent logic errors.  Used by _finalize_verification_action to
# distinguish retry-eligible failures from zombie-creating ones.
_TRANSIENT_EXC_TYPES = (
    ConnectionError,
    TimeoutError,
)


# Tools whose observable entity effect is not verifiable via tool observation.
# Derived dynamically from VERIFICATION_MAPPING so the two stay in sync —
# a tool is "non-verifiable" when every target_type mapping in the baseline
# resolves to None.
def _derive_skip_verification_tools() -> frozenset[str]:
    return frozenset(
        tool_name
        for tool_name, targets in VERIFICATION_MAPPING.items()
        if targets and all(v is None for v in targets.values())
    )


# Cache at module level so _verify_phase1_effects doesn't recompute
# on every Action in the phase 1 loop.
#
# DEPRECATED: This cache is computed once at import time and will not pick up
# Provider manifest extensions registered after startup.  The real-time check
# in _verify_phase1_effects (``verify_tool is None`` path) already recomputes
# the effective skip list on every call, so this module-level cache is only
# used by tests (which verify cache consistency).  Remove once those tests
# are migrated to the real-time path.
_SKIP_VERIFICATION_TOOLS: frozenset[str] = _derive_skip_verification_tools()


# Effect‑side action execution statuses the VerifyAgent considers.
# ActionStatus.UNKNOWN is deliberately excluded — when an Action execution
# status cannot be confirmed, we must NOT run a verification tool against it
# (the tool could return a false-positive is_verified and mask the fact that
# the Action's actual execution state is unknown).  UNKNOWN actions go
# directly to manual resolution.
# ActionStatus.EXECUTING is also excluded — asynchronous actions that are
# still running must not be prematurely verified (their effect may not have
# materialised yet, which would produce false FAILED results and trigger
# unnecessary re-planning).
_EXECUTED_STATUSES: frozenset[ActionStatus] = frozenset(
    {
        ActionStatus.SUCCESS,
        ActionStatus.PARTIAL_SUCCESS,
        ActionStatus.FAILED,
    }
)

_VERIFY_OPERATOR = "VerifyAgent"


# ── EventDispositionService protocol (ISSUE-059A) ──
# Not yet implemented; the agent accepts an optional callable matching this
# signature. When absent, phase 2 marks need_manual_resolution=true.


class _ActivateResult:
    """Result envelope matching EventDispositionService.DispositionActivationResult.

    Mirrors the canonical ``DispositionActivationResult`` from
    ``app.services.event_disposition_service`` so the VerifyAgent stays
    decoupled from the service module at import time.  The Protocol below
    enforces structural compatibility with the real service.
    """

    def __init__(
        self,
        *,
        activated: bool,
        action_id: str | None = None,
        skipped_reason: str | None = None,
        derived_disposition: Any | None = None,
        disposition_id: str | None = None,
        writeback_id: str | None = None,
    ) -> None:
        self.activated = activated
        self.action_id = action_id
        self.skipped_reason = skipped_reason
        self.derived_disposition = derived_disposition
        self.disposition_id = disposition_id
        self.writeback_id = writeback_id


class _EventDispositionServiceProtocol(Protocol):
    """Structural interface for EventDispositionService (ISSUE-059A).

    Signature matches the real ``EventDispositionService.activate_and_submit``
    (ISSUE-059A) so that injection of the concrete service satisfies the
    Protocol without adapters.  Using Protocol instead of ``Any`` lets mypy
    catch mismatched injection objects at import/type-check time rather than
    at runtime inside the except-Exception handler.
    """

    async def activate_and_submit(
        self, *, event_id: str, plan_revision: int, principal_or_system: str
    ) -> _ActivateResult: ...


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
        event_disposition_service: _EventDispositionServiceProtocol | None = None,
        disposition_sync_service: Any | None = None,
        provider_manifest_overrides: dict[str, dict[str, str]] | None = None,
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
        self._session_factory: async_sessionmaker[AsyncSession] | None = session_factory
        self._event_disposition_service: _EventDispositionServiceProtocol | None = (
            event_disposition_service
        )
        self._disposition_sync_service: Any | None = disposition_sync_service
        self._provider_manifest_overrides: dict[str, dict[str, str]] | None = (
            provider_manifest_overrides
        )

    # ------------------------------------------------------------------ #
    # _run
    # ------------------------------------------------------------------ #

    async def _run(self, input: VerifyAgentInput) -> VerificationResult:
        event_id = input.event_id
        response_plan = input.response_plan

        # 1. Load actions & execution context from the database.
        disposition_policy = await self._load_disposition_policy(event_id)
        actions, jobs_map, outbox_map = await self._load_execution_state(event_id, response_plan)

        # 2. Phase 1 — entity effect verification for IMMEDIATE actions.
        (
            phase1_results,
            phase1_failed,
            phase1_need_replan,
            phase1_need_manual,
        ) = await self._verify_phase1_effects(
            event_id=event_id,
            actions=actions,
            jobs_map=jobs_map,
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

        # ── Systemic tool unavailability check (PR#7 Blocker #2) ──────────
        # When ALL Phase 1 actions are UNVERIFIABLE with zero FAILED, the
        # verification tooling is systemically unavailable (e.g. Provider
        # completely down, tool_executor=None, every check_* call returned
        # None).  Per ISSUE-060 degradation spec this must produce
        # overall_status=FAILED — not MANUAL_RESOLUTION — so that
        # route_after_verify triggers an alert rather than quietly queuing
        # for manual triage.
        all_phase1_unverifiable = (
            len(phase1_results) > 0
            and all(r.effect_status == EffectStatus.UNVERIFIABLE for r in phase1_results)
            and len(phase1_failed) == 0
        )
        if all_phase1_unverifiable and phase1_need_manual:
            overall_status = VerificationOverallStatus.FAILED
            # need_manual_resolution stays True per spec (escalated=true).

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
            if action.execution_phase == ActionExecutionPhase.POST_VERIFY:
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
            if action.status == ActionStatus.EXECUTING:
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

            # UNKNOWN execution status → direct to manual resolution.
            # The Action was submitted but its execution result cannot be
            # confirmed.  Running a verification tool on an UNKNOWN action
            # risks producing a false-positive is_verified that masks the
            # fact that we don't know whether the action actually executed.
            if action.status == ActionStatus.UNKNOWN:
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.UNVERIFIABLE,
                        writeback_required=action.writeback_required,
                        writeback_readiness=action.writeback_readiness,
                        writeback_status=action.writeback_status,
                        writeback_ids=[],
                        detail="action_execution_unknown",
                    )
                )
                need_manual = True
                continue

            # WAITING_APPROVAL / APPROVED — the action has been approved
            # but not yet executed.  Distinguish from PENDING (not yet
            # submitted) with a more precise detail message.
            if action.status in (ActionStatus.WAITING_APPROVAL, ActionStatus.APPROVED):
                detail = (
                    "approved_pending_execution"
                    if action.writeback_required
                    else "action_not_executed"
                )
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.SKIPPED,
                        writeback_required=action.writeback_required,
                        writeback_readiness=action.writeback_readiness,
                        writeback_status=action.writeback_status,
                        writeback_ids=[],
                        detail=detail,
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
                results.append(_make_self_verifying_result(action))
                continue

            # Determine the verification tool.
            verify_tool = resolve_verification_tool(
                action.tool_name,
                action.target_type,
                provider_manifest_overrides=self._provider_manifest_overrides,
            )

            # No verification tool registered → treat as non-verifiable (skipped).
            if verify_tool is None:
                # Live lookup avoids the stale _SKIP_VERIFICATION_TOOLS
                # module-level cache (PR#7 Should-Fix: provider manifest
                # runtime extension could change mappings).
                # Match the original _derive_skip_verification_tools logic:
                # "non_verifiable_action" only when ALL target_type entries
                # for this tool resolve to None (i.e. the tool is known but
                # inherently unobservable).
                tool_mapping = VERIFICATION_MAPPING.get(action.tool_name)
                is_non_verifiable = (
                    tool_mapping is not None
                    and len(tool_mapping) > 0
                    and all(v is None for v in tool_mapping.values())
                )
                detail = (
                    "non_verifiable_action"
                    if is_non_verifiable
                    else "no_verification_tool_registered"
                )
                results.append(_make_skipped_result(action, detail=detail))
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
            if result.effect_status == EffectStatus.VERIFIED:
                continue
            elif result.effect_status == EffectStatus.UNVERIFIABLE:
                need_manual = True
            elif result.effect_status == EffectStatus.FAILED:
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

            # Validate that params match the verification tool's contract.
            # Missing required params are caught early with a clear diagnostic
            # rather than surfacing as an opaque Provider-side error.
            missing_params = validate_verification_tool_params(verify_tool, params)
            if missing_params:
                logger.warning(
                    "Verification tool %s (action=%s) missing expected params: %s",
                    verify_tool,
                    action.action_id,
                    missing_params,
                )

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
                await self._finalize_verification_action(
                    verification_action,
                    target_status=ActionStatus.UNKNOWN,
                )
            elif tool_result.status == ToolResultStatus.SUCCESS:
                data = tool_result.data or {}
                if "is_verified" not in data:
                    # Provider returned SUCCESS but didn't include the
                    # is_verified key — the observation is inconclusive,
                    # not failed.  Treating it as FAILED would trigger
                    # a spurious re-plan that wastes agent budget.
                    effect_status = EffectStatus.UNVERIFIABLE
                    detail = "verification_result_missing_is_verified_field"
                elif data["is_verified"]:
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
                # ToolResultStatus values other than SUCCESS/FAILED
                # (e.g. DEGRADED, TIMEOUT, or future additions) are
                # all treated as UNVERIFIABLE — the observation did not
                # produce a conclusive result, so we escalate to manual
                # rather than guessing.
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
                # The verification Action may be left in EXECUTING status
                # (stuck as a zombie) because _finalize_verification_action
                # itself failed.  Attach a distinguishing marker so
                # downstream consumers can tell "verification action
                # correctly finalized" from "verification action state
                # unknown" — the latter may need manual cleanup.
                detail = f"{detail};verification_action_dirty"
                logger.warning(
                    "Failed to finalize verification action %s during exception"
                    " handling for source action %s",
                    verification_action_id or "N/A",
                    action.action_id,
                    exc_info=True,
                )

        # Build writeback fields for this action.
        wb_required = action.writeback_required
        wb_readiness = action.writeback_readiness
        wb_status = action.writeback_status

        if effect_status == EffectStatus.UNVERIFIABLE:
            # writeback_required preserves the business obligation — it must
            # never be reversed by technical unavailability (§4.5 item 6).
            # The model validator on VerificationActionResult permits
            # writeback_required=True + writeback_readiness=NOT_REQUIRED
            # + writeback_status=… when effect_status=UNVERIFIABLE.
            #
            # Preserve the original writeback_status — UNVERIFIABLE means
            # we couldn't observe the entity effect, not that the writeback
            # status changed.  Losing PENDING/SENDING/CONFIRMED state here
            # would silently break downstream writeback recovery paths.
            wb_readiness = WritebackReadiness.NOT_REQUIRED
            wb_status = action.writeback_status

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
        """Phase 2: activate deferred terminal writeback, then verify receipts.

        Contract with EventDispositionService (ISSUE-059A):
        ``activate_and_submit`` MUST synchronously persist the terminal
        writeback receipt with status CONFIRMED before returning
        ``_ActivateResult(success=True)``.  This method independently
        verifies the receipt via ``_evaluate_terminal_writeback_status``
        so that a PENDING/FAILED terminal writeback is never reported
        as SUCCESS.
        """
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
            if phase1_need_replan and phase1_need_manual:
                # Both effect FAILED (replan) and UNVERIFIABLE (manual)
                # conditions exist — FAILED captures the higher severity
                # while both routing flags remain independently set for
                # the caller to act on.
                overall_status = VerificationOverallStatus.FAILED
            elif phase1_need_replan:
                overall_status = VerificationOverallStatus.PARTIAL
            elif phase1_need_manual:
                overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
            return results, failed_wb, blocked_wb, overall_status, need_wb_recovery, need_manual

        # If disposition is not required, no writeback to verify.
        if disposition_policy == DispositionPolicy.NOT_REQUIRED:
            logger.info("Phase 2 skipped: disposition_policy=not_required event=%s", event_id)
            return results, failed_wb, blocked_wb, overall_status, need_wb_recovery, need_manual

        # disposition_policy is None → unknown; the event's disposition
        # requirement cannot be determined.  Escalate to manual resolution
        # rather than silently returning SUCCESS when a policy may exist.
        if disposition_policy is None:
            logger.warning(
                "disposition_policy unknown for event=%s, requiring manual resolution",
                event_id,
            )
            need_manual = True
            overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
            return results, failed_wb, blocked_wb, overall_status, need_wb_recovery, need_manual

        # disposition_policy is REQUIRED (NOT_REQUIRED and None are
        # already handled above):
        # Attempt to activate deferred terminal writeback.
        terminal_activated = False
        if self._event_disposition_service is not None:
            # Derive plan_revision from the response plan's actions.
            # All actions in a single ResponsePlan share the same revision;
            # fall back to 1 when the plan is empty (defensive).
            # Use direct indexing instead of a truthiness loop — int(0) is
            # a valid revision but is falsy in Python, so `if a.plan_revision:`
            # would silently skip it (ISSUE-060 review B2).
            _plan_revision = actions[0].plan_revision if actions else 1
            try:
                activate_result: _ActivateResult = (
                    await self._event_disposition_service.activate_and_submit(
                        event_id=event_id,
                        plan_revision=_plan_revision,
                        principal_or_system=_VERIFY_OPERATOR,
                    )
                )
                terminal_activated = activate_result.activated
                if not terminal_activated:
                    logger.warning(
                        "Phase 2 activation skipped: %s event=%s",
                        activate_result.skipped_reason,
                        event_id,
                    )
                    need_manual = True
                    blocked_wb.add(activate_result.writeback_id or f"terminal_wb_{event_id}")
                    overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
            except Exception as exc:
                logger.error(
                    "Phase 2 activation exception event=%s: %s",
                    event_id,
                    exc,
                )
                need_manual = True
                overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
        else:
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

            # Additionally verify the terminal disposition writeback receipt
            # that activate_and_submit just submitted (ISSUE-059A contract:
            # the service is expected to synchronously persist a CONFIRMED
            # receipt before returning).  If the receipt is not yet CONFIRMED
            # we surface it via the same routing flags.
            terminal_wb_eval = await self._evaluate_terminal_writeback_status(
                event_id=event_id,
                activate_result=activate_result,
            )
            if terminal_wb_eval["need_manual"]:
                need_manual_from_wb = need_manual_from_wb or terminal_wb_eval["need_manual"]
                blocked_wb.update(terminal_wb_eval["blocked_wb"])
            if terminal_wb_eval["need_recovery"]:
                need_wb_recovery = need_wb_recovery or terminal_wb_eval["need_recovery"]
                failed_wb.update(terminal_wb_eval["failed_wb"])

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
            if action.status == ActionStatus.REJECTED:
                continue
            # POST_VERIFY deferred actions are handled by phase 2 activation,
            # not by direct writeback status evaluation.
            if action.execution_phase == ActionExecutionPhase.POST_VERIFY:
                continue

            wb_status = action.writeback_status
            wb_readiness = action.writeback_readiness
            wb_ids = await self._collect_writeback_ids(event_id, action, outbox_map)

            if not action.writeback_applicable:
                # Obligation exists at the event level but doesn't land on
                # this specific action.  writeback_required expresses the
                # event-level business obligation and MUST NOT be rewritten
                # by writeback_applicable (§4.5 item 6).  The SKIPPED
                # effect_status is permitted by the VerificationActionResult
                # validator regardless of writeback_required; the CLOSED gate
                # separately checks the event-level obligation.
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.SKIPPED,
                        writeback_required=action.writeback_required,
                        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                        writeback_status=None,
                        writeback_ids=wb_ids,
                        detail="writeback_not_applicable",
                    )
                )
                continue

            # Required but not READY → blocked.
            if wb_readiness != WritebackReadiness.READY:
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
            if wb_status is None:
                # No writeback command has been issued yet — route to
                # recovery so the caller polls/wait for a status to appear.
                confirmed, rec, man, detail_suffix = (
                    False, True, False, "writeback_no_status_waiting"
                )
            else:
                routing = _WRITEBACK_STATUS_ROUTING.get(
                    wb_status,
                    (False, True, False, "writeback_status_unknown"),
                )
                confirmed, rec, man, detail_suffix = routing

            if confirmed:
                # Phase 2 writeback receipt confirmed — effect_status=VERIFIED
                # here means "writeback receipt confirmed", NOT "entity effect
                # verified" (phase 1).  Downstream consumers that route on
                # effect_status alone must also check the `detail` field
                # ("writeback_confirmed" vs "effect_verified") or the
                # verification_phase marker on the parent VerificationResult.
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
            actions = _plan_actions(response_plan)
            # Build minimal jobs_map from Action.execution_job_id so that
            # _run_verification_tool receives the job_id context even
            # without DB access.  Missing job metadata (provider_name,
            # status) degrades gracefully — the observation tool can still
            # use the job_id to scope its independent observation.
            jobs_map: dict[str, ActionExecutionJob] = {}
            for a in actions:
                if a.execution_job_id:
                    jobs_map[a.action_id] = ActionExecutionJob(
                        job_id=a.execution_job_id,
                        event_id=a.event_id or event_id,
                        action_id=a.action_id,
                        provider_name=getattr(a, "provider_name", None) or "",
                        idempotency_key=getattr(a, "idempotency_key", None)
                        or f"idem-{a.action_id}",
                        status=ExecutionJobStatus.UNKNOWN,
                    )
            return actions, jobs_map, {}

        async with self._session_factory() as session:
            # Load persisted Actions for this event's current plan revision.
            # Baseline from plan — DB rows patch on top so that actions
            # present in the plan but not yet persisted are NOT silently
            # dropped (PR#7 Blocker #1: partial DB hit → dropped actions).
            plan_actions_list = _plan_actions(response_plan)
            if not plan_actions_list:
                actions = []
            else:
                plan_actions_map = {a.action_id: a for a in plan_actions_list}
                action_ids = list(plan_actions_map)
                rows = (
                    await session.scalars(
                        select(orm.Action).where(orm.Action.action_id.in_(action_ids))
                    )
                ).all()
                db_actions = {r.action_id: _action_from_row(r) for r in rows}
                missing = set(plan_actions_map) - set(db_actions)
                if missing:
                    logger.warning(
                        "Actions in plan but not in DB for event=%s: %s",
                        event_id,
                        missing,
                    )
                # DB-persisted state takes priority over plan defaults.
                final = {**plan_actions_map, **db_actions}
                actions = list(final.values())

            # Load jobs.
            job_ids = [a.execution_job_id for a in actions if a.execution_job_id]
            jobs_map = {}
            if job_ids:
                job_rows = (
                    await session.scalars(
                        select(orm.ActionExecutionJob).where(
                            orm.ActionExecutionJob.job_id.in_(job_ids)
                        )
                    )
                ).all()
                jobs_map = {r.action_id: _job_from_row(r) for r in job_rows}

            # Load outbox records.
            outbox_map: dict[str, list[Any]] = {}
            action_ids_for_outbox = [a.action_id for a in actions]
            if action_ids_for_outbox:
                outbox_rows = (
                    await session.scalars(
                        select(orm.DispositionOutbox).where(
                            orm.DispositionOutbox.action_id.in_(action_ids_for_outbox)
                        )
                    )
                ).all()
                for r in outbox_rows:
                    outbox_map.setdefault(r.action_id, []).append(r)

            return actions, jobs_map, outbox_map

    async def _load_disposition_policy(self, event_id: str) -> DispositionPolicy | None:
        """Read disposition_policy from the SecurityEvent row.

        ``disposition_policy`` is a SecurityEvent column, **not** an
        EventContext field.  Attempting to read it via working_memory with
        key ``"disposition_policy"`` would trigger a ``GuardrailViolationError``
        because ``"disposition_policy"`` is not registered in ``FIELD_OWNERSHIP``.
        The correct path is the DB query below.
        """
        if self._session_factory is None:
            logger.debug(
                "No session_factory available — cannot load disposition_policy for event=%s",
                event_id,
            )
            return None

        async with self._session_factory() as session:
            event_row = await session.get(orm.SecurityEvent, event_id)
            if event_row is None:
                logger.debug(
                    "SecurityEvent row not found for event=%s — disposition_policy unknown",
                    event_id,
                )
                return None
            if not event_row.disposition_policy:
                logger.debug(
                    "disposition_policy is empty/falsy for event=%s — treating as unknown",
                    event_id,
                )
                return None
            try:
                return DispositionPolicy(event_row.disposition_policy)
            except ValueError:
                logger.warning(
                    "Unknown disposition_policy %r for event=%s, treating as None",
                    event_row.disposition_policy,
                    event_id,
                )
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

    async def _evaluate_terminal_writeback_status(
        self,
        *,
        event_id: str,
        activate_result: _ActivateResult,
    ) -> dict[str, Any]:
        """Evaluate the terminal disposition's writeback receipt after activation.

        ISSUE-059A contract: ``EventDispositionService.activate_and_submit``
        is expected to synchronously persist the terminal writeback receipt
        with status CONFIRMED before returning.  This method independently
        verifies that the receipt was persisted and evaluates its status.

        Returns a dict with the same shape as ``_evaluate_writeback_statuses``
        so phase 2 can merge the terminal writeback evaluation into its
        final routing decision.
        """
        failed_wb_set: set[str] = set()
        blocked_wb_set: set[str] = set()
        empty: dict[str, Any] = {
            "results": [],
            "failed_wb": failed_wb_set,
            "blocked_wb": blocked_wb_set,
            "need_recovery": False,
            "need_manual": False,
        }
        terminal_wb_id = activate_result.writeback_id
        if terminal_wb_id is None:
            return empty
        if self._session_factory is None:
            logger.warning(
                "Cannot verify terminal writeback %s: no session_factory"
                " event=%s — escalating to manual resolution",
                terminal_wb_id,
                event_id,
            )
            empty["need_manual"] = True
            blocked_wb_set.add(terminal_wb_id)
            return empty

        try:
            async with self._session_factory() as session:
                # Read the latest (highest sequence) receipt for this writeback.
                receipt_row = (
                    await session.scalars(
                        select(orm.DispositionReceipt)
                        .where(orm.DispositionReceipt.writeback_id == terminal_wb_id)
                        .order_by(orm.DispositionReceipt.sequence.desc())
                        .limit(1)
                    )
                ).first()

                if receipt_row is None:
                    logger.warning(
                        "Terminal writeback receipt not found: wb_id=%s event=%s",
                        terminal_wb_id,
                        event_id,
                    )
                    blocked_wb_set.add(terminal_wb_id)
                    empty["need_manual"] = True
                    return empty

                # Map the receipt status string to a WritebackStatus enum value.
                try:
                    wb_status = WritebackStatus(receipt_row.status)
                except ValueError:
                    logger.warning(
                        "Unknown terminal writeback status %s for wb_id=%s event=%s",
                        receipt_row.status,
                        terminal_wb_id,
                        event_id,
                    )
                    wb_status = WritebackStatus.UNKNOWN

                routing = _WRITEBACK_STATUS_ROUTING.get(
                    wb_status,
                    (False, True, False, "writeback_status_unknown"),
                )
                confirmed, rec, man, detail_suffix = routing

                # CONFIRMED is the happy path — the terminal writeback
                # receipt was persisted synchronously by activate_and_submit
                # per the ISSUE-059A contract.  The routing table maps
                # CONFIRMED → (True, False, False, …), so none of `man`,
                # `rec`, or `failed_wb` are set.  The empty dict returned
                # by the CONFIRMED branch is intentional: "no action
                # needed" is the correct routing decision.
                if not confirmed:
                    logger.warning(
                        "Terminal writeback %s status=%s → %s event=%s",
                        terminal_wb_id,
                        wb_status.value,
                        detail_suffix,
                        event_id,
                    )
                    if man:
                        empty["need_manual"] = True
                        blocked_wb_set.add(terminal_wb_id)
                    elif rec:
                        empty["need_recovery"] = True
                        if wb_status in (WritebackStatus.FAILED, WritebackStatus.PARTIAL):
                            failed_wb_set.add(terminal_wb_id)

                return empty
        except Exception as exc:
            logger.warning(
                "Failed to evaluate terminal writeback %s event=%s: %s",
                terminal_wb_id,
                event_id,
                exc,
            )
            empty["need_manual"] = True
            if terminal_wb_id:
                blocked_wb_set.add(terminal_wb_id)
            return empty

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
            action_name=f"verify_{source_action.action_name}"[:255],
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
                # Distinguish integrity errors (idempotent re-run — the row
                # already exists, which is fine) from other DB failures
                # (connection lost, constraint violation, …) which leave an
                # audit gap.  We still return the in-memory Action so the
                # observation can proceed, but the warning now carries the
                # explicit audit-gap marker.
                from sqlalchemy.exc import IntegrityError

                if isinstance(exc, IntegrityError):
                    logger.debug(
                        "Verification action %s already persisted (idempotent re-run)",
                        action_id,
                    )
                else:
                    logger.warning(
                        "Failed to persist verification action %s — audit trail"
                        " incomplete for this verification (source_action=%s): %s",
                        action_id,
                        source_action.action_id,
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
                # Commit succeeded — update the domain object to stay
                # consistent with the persisted row.
                action.status = target_status
            except Exception as exc:
                # Distinguish transient errors (network blip, connection
                # pool exhaustion, deadlock retry) from permanent errors
                # (schema mismatch, constraint violation).  Transient
                # failures are warnings — the caller can retry on the next
                # cycle.  Permanent failures are errors that risk leaving
                # the verification Action as a zombie in EXECUTING status.
                if isinstance(exc, _TRANSIENT_EXC_TYPES):
                    logger.warning(
                        "Transient failure finalizing verification action %s "
                        "(will retry next cycle): %s",
                        action.action_id,
                        exc,
                    )
                else:
                    logger.error(
                        "Permanent failure finalizing verification action %s "
                        "(action may be stuck in EXECUTING status): %s",
                        action.action_id,
                        exc,
                        exc_info=True,
                    )

    # ------------------------------------------------------------------ #
    # Working memory & event bus
    # ------------------------------------------------------------------ #

    async def _write_verification_result(
        self,
        event_id: str,
        result: VerificationResult,
    ) -> None:
        """Persist the VerificationResult to EventContext via WorkingMemory.

        Sets ``result.wm_persisted`` to indicate whether the write succeeded
        so that downstream consumers (report generator, SuperAgent routing)
        can distinguish "verification not yet run" from "verification ran
        but its output failed to persist."
        """
        if self.working_memory is None:
            result.wm_persisted = False
            logger.debug(
                "No working_memory available — verification_result not persisted for event=%s",
                event_id,
            )
            return
        try:
            await self.working_memory.write(
                event_id,
                "verification_result",
                result.model_dump(mode="json"),
            )
            result.wm_persisted = True
        except Exception as exc:
            result.wm_persisted = False
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
        """Publish action_verified SocketEvent for each per-action result.

        Publish failures are collected in ``result.publish_failures`` so the
        caller can detect gaps in the event-bus delivery without blocking the
        verification pipeline.

        .. note::

           VerifyAgent itself does **not** retry failed publishes.  The
           ``publish_failures`` list is surfaced to the caller (SuperAgent /
           orchestration layer) which owns the retry decision.  Callers
           SHOULD inspect ``result.publish_failures`` after ``execute()``
           returns and re-publish any failed action_ids.
        """
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
                            item.writeback_status.value if item.writeback_status else None
                        ),
                        "verification_action_id": item.verification_action_id,
                        "detail": item.detail,
                    },
                )
            except Exception:
                result.publish_failures.append(item.action_id)
                logger.warning(
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
        try:
            return list(response_plan.actions)
        except TypeError:
            logger.warning(
                "response_plan.actions is not iterable — returning empty list"
            )
            return []
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

    For deferred POST_VERIFY actions (``detail="deferred_pending_activation"``)
    the writeback obligation is preserved even though the action has not yet
    been activated — the obligation exists at the event level; it just hasn't
    landed on this specific action yet.  The validator permits
    ``writeback_required=True + writeback_readiness=NOT_REQUIRED`` for
    SKIPPED results.
    """
    if detail == "deferred_pending_activation":
        # Preserve the business obligation — it hasn't been discharged yet,
        # it's just waiting for phase 2 activation.
        return VerificationActionResult(
            action_id=action.action_id,
            effect_status=EffectStatus.SKIPPED,
            writeback_required=action.writeback_required,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            writeback_status=None,
            writeback_ids=[],
            detail=detail,
        )
    # writeback_required expresses the event-level business obligation and
    # MUST NOT be rewritten by technical capability flags like
    # writeback_applicable (§4.5 item 6).  The SKIPPED effect_status is
    # already exempt from the Validator's writeback-consistency check,
    # so preserving the original obligation is safe.
    wb_required = action.writeback_required
    wb_readiness = WritebackReadiness.NOT_REQUIRED
    wb_status = None
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
        action_level=ActionLevel(row.action_level),
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
        execution_owner=(ExecutionOwner(row.execution_owner) if row.execution_owner else None),
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
        writeback_status=(WritebackStatus(row.writeback_status) if row.writeback_status else None),
        disposition_source_ref=(
            SourceObjectLocator.model_validate(row.disposition_source_ref)
            if row.disposition_source_ref
            else None
        ),
        superseded_by_revision=row.superseded_by_revision,
        executed_at=row.executed_at,
        effect_verification_status=row.effect_verification_status,
        rollback_status=(ActionStatus(row.rollback_status) if row.rollback_status else None),
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
    "_SKIP_VERIFICATION_TOOLS",
    "_derive_skip_verification_tools",
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
        f"verify:{event_id}:{source_action_id}:{verify_tool}".encode()
    ).hexdigest()[:12]
    return f"act-{digest}"
