"""Mock XDR observation bridge for adversarial full-loop verify (ISSUE-204).

Production response actions on the Mock XDR path execute via ``DispositionSync``
(``entity_action_submit``) and persist ``DispositionReceipt`` rows. VerifyAgent
phase1 uses ``check_*`` tools that normally read ``MockEnvironmentState``, which
is **not** updated by Mock XDR writeback.

This module derives verification observations from persisted Action +
DispositionReceipt facts so VerifyAgent can reach phase2 terminal activation
without sunset shims or post-hoc verification seeding.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.verify_agent import VerifyAgent
from app.db import models as orm
from app.models.action import Action
from app.models.agent_io import EffectStatus, VerificationActionResult
from app.models.enums import ActionCategory, ActionStatus, WritebackStatus
from app.models.ids import new_call_id
from app.models.tool_meta import ToolResult, ToolResultStatus

_PROVIDER_NAME = "mock_xdr_writeback_observation"


async def verified_via_xdr_writeback(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    target: str,
) -> bool:
    """Return True when a response action for ``target`` completed on Mock XDR."""
    normalized = target.strip().lower()
    if not normalized:
        return False
    async with session_factory() as session:
        action_row = await session.scalar(
            select(orm.Action)
            .where(
                orm.Action.event_id == event_id,
                func.lower(orm.Action.target) == normalized,
                orm.Action.action_category == ActionCategory.RESPONSE.value,
            )
            .limit(1)
        )
        if action_row is None:
            return False
        if action_row.status not in {
            ActionStatus.SUCCESS.value,
            ActionStatus.EXECUTING.value,
        }:
            return False
        receipt_status = await session.scalar(
            select(orm.DispositionReceipt.status)
            .where(orm.DispositionReceipt.action_id == action_row.action_id)
            .order_by(orm.DispositionReceipt.sequence.desc())
            .limit(1)
        )
    verified_by_receipt = receipt_status in {
        WritebackStatus.CONFIRMED.value,
        WritebackStatus.ACCEPTED.value,
    }
    verified_by_action_status = action_row.status == ActionStatus.SUCCESS.value
    # Action SUCCESS is an execution claim, not an independent external
    # observation.  Require both the successful action fact and a provider-side
    # receipt before VerifyAgent may treat the entity effect as established.
    return verified_by_receipt and verified_by_action_status


class AdversarialVerifyAgent(VerifyAgent):
    """VerifyAgent wired for adversarial full loop (ISSUE-204).

    Entity response actions carry ``writeback_required=true`` at the event
    policy level but ``writeback_applicable=false`` on the row.  Production
    VerifyAgent builds phase-1 ``VERIFIED`` results with
    ``writeback_readiness=NOT_REQUIRED``, which violates
    ``VerificationActionResult`` validation.  The obligation is discharged on
    the deferred POST_VERIFY terminal action, not on entity side-effects.
    """

    async def _run_verification_tool(
        self,
        *,
        event_id: str,
        action: Action,
        verify_tool: str,
        job: Any,
    ) -> VerificationActionResult:
        patched_action = action
        if not action.writeback_applicable and action.writeback_required:
            patched_action = action.model_copy(update={"writeback_required": False})
        result = await super()._run_verification_tool(
            event_id=event_id,
            action=patched_action,
            verify_tool=verify_tool,
            job=job,
        )
        if (
            not action.writeback_applicable
            and action.writeback_required
            and result.effect_status is EffectStatus.UNVERIFIABLE
        ):
            return result.model_copy(update={"writeback_required": True})
        return result


class XdrManagedVerifyToolExecutor:
    """Route ``check_*`` verify tools through XDR writeback/execution facts."""

    def __init__(self, inner: Any, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._inner = inner
        self._session_factory = session_factory

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def call(
        self,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        *,
        action_id: str | None = None,
        execution_job_id: str | None = None,
        idempotency_key: str | None = None,
        execution_owner: Any = None,
        timeout: float | None = None,
        retry_policy: Any = None,
        agent_name: str = "tool_agent",
    ) -> ToolResult:
        if tool_name.startswith("check_"):
            target = str(params.get("target") or "").strip()
            if not target:
                return ToolResult(
                    call_id=new_call_id(),
                    tool_name=tool_name,
                    provider_name=_PROVIDER_NAME,
                    status=ToolResultStatus.SUCCESS,
                    data={"is_verified": False, "detail": "missing_target"},
                )
            verified = await verified_via_xdr_writeback(
                self._session_factory,
                event_id,
                target,
            )
            return ToolResult(
                call_id=new_call_id(),
                tool_name=tool_name,
                provider_name=_PROVIDER_NAME,
                status=ToolResultStatus.SUCCESS,
                data={
                    "is_verified": verified,
                    "detail": "xdr_writeback_observation",
                },
            )
        return await self._inner.call(
            tool_name,
            params,
            event_id,
            action_id=action_id,
            execution_job_id=execution_job_id,
            idempotency_key=idempotency_key,
            execution_owner=execution_owner,
            timeout=timeout,
            retry_policy=retry_policy,
            agent_name=agent_name,
        )


__all__ = [
    "AdversarialVerifyAgent",
    "XdrManagedVerifyToolExecutor",
    "verified_via_xdr_writeback",
]
