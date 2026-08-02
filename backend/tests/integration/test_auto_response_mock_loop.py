"""Auto-response mock-loop contract tests (ISSUE-109 / #613 Phase 1)."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.models.action import Action
from app.models.approval import ApprovalDecisionKind
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    EventStatus,
    ExecutionOwner,
    Severity,
)
from app.services.approval_engine import evaluate_level_rules
from app.services.auto_response_policy import AutoResponsePolicyService


def _response_action(*, level: ActionLevel, action_id: str) -> Action:
    return Action.model_validate(
        {
            "action_id": action_id,
            "event_id": "evt-gate",
            "plan_revision": 1,
            "action_fingerprint": f"fp-{action_id}",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "isolate_host",
            "tool_name": "isolate_host",
            "action_level": level,
            "execution_owner": ExecutionOwner.DIRECT_TOOL,
            "execution_phase": ActionExecutionPhase.IMMEDIATE,
            "status": ActionStatus.PENDING,
            "writeback_required": False,
            "writeback_applicable": False,
            "reason": "test",
        }
    )


def test_l3_actions_still_require_human_after_auto_response_entry() -> None:
    """Policy may enter response phase; ApprovalEngine still gates L2-L5."""
    action = _response_action(level=ActionLevel.L3, action_id="act-l3-gate")
    decision = evaluate_level_rules(action, confidence=0.99, severity=Severity.CRITICAL)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
    assert decision.rule_applied == "level_l3_requires_human"


@pytest.mark.parametrize(
    ("level", "rule"),
    [
        (ActionLevel.L2, "level_l2_requires_human"),
        (ActionLevel.L4, "level_l4_l5_manual"),
    ],
)
def test_high_levels_never_auto_approve(level: ActionLevel, rule: str) -> None:
    action = _response_action(level=level, action_id=f"act-{level.value}")
    decision = evaluate_level_rules(action, confidence=1.0, severity=Severity.CRITICAL)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
    assert decision.rule_applied == rule


def test_mock_response_phase_l1_auto_l3_human_after_policy_entry() -> None:
    """Scenario B contract: eligible auto-response entry does not bypass approval gates."""
    from app.db import models as orm

    policy = AutoResponsePolicyService(
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
        )
    )
    event = orm.SecurityEvent(
        event_id="evt-scenario-b",
        event_type="malicious_process",
        title="test",
        description="",
        status=EventStatus.NEW.value,
        severity=Severity.HIGH.value,
        final_verdict="none",
        creation_source_ref={"source_product": "mock_xdr"},
        source_reference_snapshots=[],
        disposition_policy="not_required",
        raw_alert_ids=[],
        source_type="mock_xdr",
    )
    entry = policy.evaluate(event, link_role="primary", source_product="mock_xdr")
    assert entry.eligible is True
    assert entry.reason == "auto_response:policy_match"

    l1 = _response_action(level=ActionLevel.L1, action_id="act-l1-auto")
    l3 = _response_action(level=ActionLevel.L3, action_id="act-l3-human")
    cap = policy.max_auto_level()
    l1_decision = evaluate_level_rules(
        l1,
        confidence=0.99,
        severity=Severity.CRITICAL,
        max_auto_level=cap,
    )
    l3_decision = evaluate_level_rules(l3, confidence=0.99, severity=Severity.CRITICAL)
    assert l1_decision.decision is ApprovalDecisionKind.AUTO_APPROVE
    assert l3_decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL


def test_l1_requires_approval_when_max_auto_level_l0() -> None:
    action = _response_action(level=ActionLevel.L1, action_id="act-l1-cap")
    decision = evaluate_level_rules(
        action,
        confidence=0.99,
        severity=Severity.CRITICAL,
        max_auto_level=ActionLevel.L0,
    )
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
    assert decision.rule_applied == "level_exceeds_auto_cap"


@pytest.mark.asyncio
async def test_malicious_process_generates_security_response_actions() -> None:
    """ISSUE-109 acceptance: auto-response path yields non-report response actions."""
    from datetime import UTC, datetime
    from types import SimpleNamespace
    from typing import Any
    from uuid import uuid4

    from app.agents.response_agent import ResponseAgent, build_mock_capability_manifest
    from app.models.action import Action
    from app.models.agent_io import (
        CollectionStatus,
        EvidenceOutput,
        ResponseAgentInput,
        RiskAssessment,
        RiskFactor,
        ScoringMode,
        TriageResult,
    )
    from app.models.entities import EntitySet, HostEntity
    from app.models.enums import DispositionPolicy, EventType, FinalVerdict, SourceObjectKind
    from app.models.source import SourceReference

    class _FakeWM:
        def __init__(self) -> None:
            self.values: dict[tuple[str, str], Any] = {}

        async def read(self, event_id: str, key: str) -> Any:
            return self.values.get((event_id, key))

        async def write(self, event_id: str, key: str, value: Any) -> None:
            self.values[(event_id, key)] = value

        async def append_scratchpad(self, event_id: str, note: str) -> None:
            return None

    class _FakeEventService:
        def __init__(self) -> None:
            self.actions_by_fp: dict[str, dict[str, Any]] = {}

        async def get_event(self, event_id: str) -> Any:
            return SimpleNamespace(
                event_id=event_id,
                disposition_policy=DispositionPolicy.REQUIRED,
                final_verdict=FinalVerdict.NONE,
                creation_source_ref=SourceReference(
                    source_kind=SourceObjectKind.INCIDENT,
                    source_product="mock_xdr",
                    source_tenant_id="tenant-demo",
                    connector_id="conn-mock",
                    source_object_id="INC-001",
                    ingested_at=datetime.now(UTC),
                ),
            )

        async def upsert_response_plan_actions(
            self,
            event_id: str,
            *,
            plan_revision: int,
            actions: list[Any],
            response_plan: Any | None = None,
        ) -> list[Any]:
            stored: list[Any] = []
            for action in actions:
                self.actions_by_fp[action.action_fingerprint] = action.model_dump(mode="json")
                stored.append(action)
            return stored

        async def supersede_undeployed_deferred(
            self,
            event_id: str,
            *,
            old_revision: int,
            new_revision: int,
        ) -> int:
            return 0

    class _FailingLLM:
        async def complete(self, *_args: object, **_kwargs: object) -> str:
            raise RuntimeError("force template path")

    event_id = f"evt-auto-resp-{uuid4().hex[:8]}"
    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id="INC-001",
        ingested_at=datetime.now(UTC),
    )
    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(
            hosts=[HostEntity(entity_id="host-1", hostname="PC-FIN-023", source_refs=[ref])]
        ),
        reasoning="malicious process triage",
    )
    wm = _FakeWM()
    wm.values[(event_id, "triage_result")] = triage.model_dump(mode="json")
    wm.values[(event_id, "execution_plan")] = {
        "plan_id": "pln-test",
        "event_id": event_id,
        "revision": 0,
        "steps": [],
    }
    wm.values[(event_id, "event")] = {
        "event_id": event_id,
        "disposition_policy": DispositionPolicy.REQUIRED.value,
        "creation_source_ref": ref.model_dump(mode="json"),
    }
    wm.values[(event_id, "disposition_only_intent")] = False

    event_service = _FakeEventService()
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(
        ResponseAgentInput(
            event_id=event_id,
            risk_assessment=RiskAssessment(
                risk_score=85,
                severity=Severity.HIGH,
                confidence=0.9,
                risk_factors=[
                    RiskFactor(
                        factor_name="impact",
                        weight=1.0,
                        raw_score=85.0,
                        weighted_score=85.0,
                        reasoning="test",
                    )
                ],
                scoring_mode=ScoringMode.LLM_AND_RULE,
            ),
            evidence_output=EvidenceOutput(
                evidence_list=[],
                collection_status=CollectionStatus.COMPLETED,
                overall_confidence=0.9,
            ),
        )
    )

    security_actions = [
        action
        for action in plan.actions
        if action.action_category is ActionCategory.RESPONSE
        and action.tool_name not in {"generate_report", "update_source_event_disposition"}
    ]
    assert security_actions, "expected at least one security response action"
    assert any(action.action_level is ActionLevel.L3 for action in security_actions)
    l3 = next(action for action in security_actions if action.action_level is ActionLevel.L3)
    gate = evaluate_level_rules(l3, confidence=0.99, severity=Severity.HIGH)
    assert gate.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
    persisted = [
        Action.model_validate(row)
        for row in event_service.actions_by_fp.values()
        if row.get("event_id") == event_id
        and row.get("tool_name") not in {"generate_report", "update_source_event_disposition"}
    ]
    assert persisted


@pytest.mark.integration
@pytest.mark.asyncio
async def test_auto_response_intent_to_execute_investigation_full_loop(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ingest → ENQUEUED include_response → execute_investigation forwards full-loop (#614)."""
    from contextlib import nullcontext
    from typing import Any
    from unittest.mock import AsyncMock, MagicMock
    from uuid import uuid4

    from app.db import models as orm
    from app.services.auto_investigate_policy import AutoInvestigatePolicyService
    from app.services.context_service import EventContextStore
    from app.services.degraded_flag_service import DegradedFlagService
    from app.services.event_service import EventService
    from app.services.investigation_intent_service import InvestigationIntentService
    from app.tasks import investigation_tasks as tasks
    from tests.integration.test_auto_investigate_mock import _incident_source

    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        AUTO_RESPONSE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        TOOL_MODE="mock",
        DISPOSITION_MODE="mock_xdr",
    )
    intent_service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        degraded_flags=degraded,
        settings=settings,
    )
    events = EventService(
        session_factory,
        store,
        degraded_flags=degraded,
        investigation_intent=intent_service,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        lambda: None,
    )

    ingest = await events.ingest_source_object(
        _incident_source(object_id=f"inc-auto-resp-e2e-{uuid4().hex[:8]}")
    )
    claimed = await intent_service._claim_batch(limit=20)
    assert claimed
    our_intent_id = None
    async with session_factory() as session:
        for intent_id in claimed:
            row = await session.get(orm.InvestigationIntent, intent_id)
            if row is not None and row.event_id == ingest.event_id:
                our_intent_id = intent_id
                break
    assert our_intent_id is not None
    target = await intent_service._commit_enqueued_publish_target(our_intent_id)
    assert target is not None
    assert target.include_response_execution is True

    seen: dict[str, Any] = {}

    async def _investigate(event_id: str, **kwargs: Any) -> None:
        seen["event_id"] = event_id
        seen["include_response_execution"] = kwargs.get("include_response_execution")

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr("app.api.v1.deps._get_session_factory", lambda: session_factory)
    monkeypatch.setattr(
        "app.services.investigation_guidance.record_investigation_workflow_path",
        AsyncMock(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: nullcontext(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation(
        ingest.event_id,
        include_response_execution=target.include_response_execution,
    )
    assert result == {"status": "completed", "event_id": ingest.event_id}
    assert seen == {
        "event_id": ingest.event_id,
        "include_response_execution": True,
    }
