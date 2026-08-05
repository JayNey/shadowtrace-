"""Unit tests for Mock XDR verify observation bridge (ISSUE-204)."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.models.action import Action
from app.models.agent_io import (
    EffectStatus,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
)
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    DispositionPolicy,
    ExecutionOwner,
    FinalVerdict,
    SourceDisposition,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.tool_meta import ToolResultStatus
from tests.adversarial.xdr_verify_observation import (
    AdversarialTerminalDispositionResolver,
    AdversarialVerifyAgent,
    XdrManagedVerifyToolExecutor,
    verified_via_xdr_writeback,
)

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_state")]


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


async def _seed_response_action(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    target: str,
    action_status: str = ActionStatus.SUCCESS.value,
) -> tuple[str, str]:
    event_id = f"evt-xdr-obs-{_sfx()}"
    action_id = f"act-xdr-obs-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="insider_threat",
                    title="xdr-verify-observation-test",
                    status="executing_response",
                    disposition_policy="required",
                    creation_source_ref={"source_object_id": f"INC-{_sfx()}"},
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{action_id}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level=ActionLevel.L2.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    target=target,
                    status=action_status,
                    execution_owner="xdr_managed",
                )
            )
    return event_id, action_id


@pytest.mark.asyncio
async def test_verified_via_xdr_writeback_success_action(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    target = "198.51.100.44"
    event_id, _ = await _seed_response_action(session_factory, target=target)
    assert await verified_via_xdr_writeback(session_factory, event_id, target) is True
    assert await verified_via_xdr_writeback(session_factory, event_id, target.upper()) is True


@pytest.mark.asyncio
async def test_verified_via_xdr_writeback_missing_action(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = f"evt-xdr-obs-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="insider_threat",
                    title="empty",
                    status="new",
                    disposition_policy="required",
                    creation_source_ref={"source_object_id": f"INC-{_sfx()}"},
                )
            )
    assert await verified_via_xdr_writeback(session_factory, event_id, "10.0.0.1") is False


@pytest.mark.asyncio
async def test_xdr_managed_executor_routes_check_tools(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    target = "wks-data-031"
    event_id, _ = await _seed_response_action(session_factory, target=target)
    inner = AsyncMock()
    inner.call = AsyncMock(
        return_value=type(
            "ToolResult",
            (),
            {"status": ToolResultStatus.SUCCESS, "data": {"is_verified": False}},
        )()
    )
    executor = XdrManagedVerifyToolExecutor(inner, session_factory)
    result = await executor.call(
        "check_host_isolation_status",
        {"target": target},
        event_id,
        agent_name="verify_agent",
    )
    assert result.status == ToolResultStatus.SUCCESS
    assert result.data["is_verified"] is True
    assert result.data["detail"] == "xdr_writeback_observation"
    inner.call.assert_not_called()


@pytest.mark.asyncio
async def test_xdr_managed_executor_delegates_non_check_tools(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    inner = AsyncMock()
    expected: dict[str, Any] = {"status": ToolResultStatus.SUCCESS, "data": {"ok": True}}
    inner.call = AsyncMock(return_value=expected)
    executor = XdrManagedVerifyToolExecutor(inner, session_factory)
    params = {"query": "test"}
    await executor.call("search_logs", params, "evt-delegate", agent_name="evidence_agent")
    inner.call.assert_awaited_once_with(
        "search_logs",
        params,
        "evt-delegate",
        action_id=None,
        execution_job_id=None,
        idempotency_key=None,
        execution_owner=None,
        timeout=None,
        retry_policy=None,
        agent_name="evidence_agent",
    )


def test_adversarial_terminal_resolver_ignores_non_verifiable_skipped() -> None:
    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id="act-ticket",
                effect_status=EffectStatus.SKIPPED,
                writeback_required=True,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                writeback_status=None,
                writeback_ids=[],
                detail="non_verifiable_action",
                verification_phase=VerificationPhase.EFFECT,
            ),
            VerificationActionResult(
                action_id="act-block",
                effect_status=EffectStatus.VERIFIED,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                writeback_status=None,
                writeback_ids=[],
                detail="effect_verified",
                verification_phase=VerificationPhase.EFFECT,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    resolver = AdversarialTerminalDispositionResolver()
    result = resolver.resolve(
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        verification=verification,
        approved_terminal_dispositions=[SourceDisposition.CONTAINED],
        disposition_only=False,
        disposition_policy=DispositionPolicy.REQUIRED,
        writeback_readiness=WritebackReadiness.READY,
    )
    assert result.disposition is SourceDisposition.CONTAINED


async def _seed_action_with_receipt(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    target: str,
    action_status: str,
    receipt_status: str | None,
) -> str:
    event_id = f"evt-xdr-obs-{_sfx()}"
    action_id = f"act-xdr-obs-{_sfx()}"
    connector_id = f"conn-{_sfx()}"
    source_record_id = f"src-{_sfx()}"
    writeback_id = f"wbk-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="insider_threat",
                    title="xdr-verify-receipt-test",
                    status="executing_response",
                    disposition_policy="required",
                    creation_source_ref={"source_object_id": f"INC-{_sfx()}"},
                )
            )
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name="Mock",
                )
            )
            session.add(
                orm.SourceObject(
                    source_record_id=source_record_id,
                    source_product="mock_xdr",
                    source_tenant_id="tenant-adversarial-audit",
                    connector_id=connector_id,
                    source_kind="incident",
                    source_object_id=f"INC-{_sfx()}",
                    source_object_type="correlation_incident",
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{action_id}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level=ActionLevel.L2.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    target=target,
                    status=action_status,
                    execution_owner="xdr_managed",
                )
            )
            if receipt_status is not None:
                session.add(
                    orm.DispositionReceipt(
                        writeback_id=writeback_id,
                        sequence=1,
                        disposition_id=f"disp-{_sfx()}",
                        action_id=action_id,
                        source_record_id=source_record_id,
                        status=receipt_status,
                        confirmation_evidence="adapter_acknowledged",
                    )
                )
    return event_id


@pytest.mark.asyncio
async def test_verified_via_xdr_writeback_accepted_receipt_while_executing(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    target = "198.51.100.55"
    event_id = await _seed_action_with_receipt(
        session_factory,
        target=target,
        action_status=ActionStatus.EXECUTING.value,
        receipt_status=WritebackStatus.ACCEPTED.value,
    )
    assert await verified_via_xdr_writeback(session_factory, event_id, target) is True


def _writeback_not_applicable_action() -> Action:
    return Action(
        action_id="act-adv-verify",
        event_id="evt-adv-verify",
        plan_revision=1,
        action_fingerprint="fp:block_ip",
        action_category=ActionCategory.RESPONSE,
        action_name="block ip",
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        target_type="ip",
        target="198.51.100.44",
        status=ActionStatus.SUCCESS,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
    )


@pytest.mark.asyncio
async def test_adversarial_verify_agent_verified_writeback_not_applicable() -> None:
    from app.agents.verify_agent import VerifyAgent

    action = _writeback_not_applicable_action()
    agent = AdversarialVerifyAgent()

    async def parent_run(
        self: VerifyAgent,
        *,
        event_id: str,
        action: Action,
        verify_tool: str,
        job: Any,
    ) -> VerificationActionResult:
        assert action.writeback_required is False
        return VerificationActionResult(
            action_id=action.action_id,
            effect_status=EffectStatus.VERIFIED,
            writeback_required=action.writeback_required,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            writeback_status=None,
            writeback_ids=[],
            detail="effect_verified",
            verification_phase=VerificationPhase.EFFECT,
        )

    with patch.object(VerifyAgent, "_run_verification_tool", parent_run):
        result = await agent._run_verification_tool(
            event_id=action.event_id,
            action=action,
            verify_tool="check_ip_block_status",
            job=None,
        )

    assert result.effect_status is EffectStatus.VERIFIED
    assert result.writeback_required is False


@pytest.mark.asyncio
async def test_adversarial_verify_agent_unverifiable_restores_obligation() -> None:
    from app.agents.verify_agent import VerifyAgent

    action = _writeback_not_applicable_action()
    agent = AdversarialVerifyAgent()

    async def parent_run(
        self: VerifyAgent,
        *,
        event_id: str,
        action: Action,
        verify_tool: str,
        job: Any,
    ) -> VerificationActionResult:
        return VerificationActionResult(
            action_id=action.action_id,
            effect_status=EffectStatus.UNVERIFIABLE,
            writeback_required=action.writeback_required,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            writeback_status=None,
            writeback_ids=[],
            detail="verification_tool_unavailable_degraded",
            verification_phase=VerificationPhase.EFFECT,
        )

    with patch.object(VerifyAgent, "_run_verification_tool", parent_run):
        result = await agent._run_verification_tool(
            event_id=action.event_id,
            action=action,
            verify_tool="check_ip_block_status",
            job=None,
        )

    assert result.effect_status is EffectStatus.UNVERIFIABLE
    assert result.writeback_required is True
