"""Shadow-isolated ReAct mock query pivot orchestrator (ISSUE-135 / #641 Phase A).

Runs a bounded observe→think→authorized query→reflect loop entirely inside the
shadow namespace. Production EventContext, decision_record, and grant ledgers
are never mutated.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from typing import Any

from app.core.config import Settings
from app.core.errors import ToolCallGrantUnavailableError
from app.core.llm.base import BaseLLMClient
from app.models.decision_record import DecisionRecord, DecisionStage
from app.models.react import ReActActionType, ReActRound, ReActStopReason
from app.models.shadow_run import (
    ShadowQueryArtifactKind,
    ShadowQueryPivotRequest,
    ShadowQueryPivotResult,
    ShadowRun,
    ShadowRunStatus,
)
from app.orchestration.react_engine import ReActEngine
from app.rag.pipeline import RetrievalPipeline
from app.services.react_mock_query_adapter import (
    MOCK_QUERY_AGENT_NAME,
    ReactMockQueryAdapter,
    ReactMockQueryContext,
    build_mock_query_agent_callable,
)
from app.services.shadow_run_service import ShadowRunService
from app.tools.tool_call_runtime import ReactToolExecutorFactory

logger = logging.getLogger(__name__)


def _record_hash(record: DecisionRecord) -> str:
    payload = record.model_dump(mode="json", exclude={"record_hash", "created_at"})
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ShadowQueryPivotService:
    """Entry point for shadow-only mock query pivot runs."""

    def __init__(
        self,
        shadow_run_service: ShadowRunService,
        *,
        settings: Settings,
    ) -> None:
        self._shadow_runs = shadow_run_service
        self._settings = settings

    async def run_pivot(
        self,
        request: ShadowQueryPivotRequest,
        *,
        llm_client: BaseLLMClient,
        react_factory: ReactToolExecutorFactory,
        pipeline: RetrievalPipeline,
        knowledge_release_service: Any | None = None,
    ) -> ShadowQueryPivotResult:
        cfg = self._settings
        if not cfg.react_shadow_pivot_enabled:
            return ShadowQueryPivotResult(
                shadow_run_id="",
                status=ShadowRunStatus.REJECTED,
                rejected_reasons=["shadow_pivot_disabled"],
                degraded=True,
            )

        if not request.tenant_id.strip() or not request.principal.strip():
            return ShadowQueryPivotResult(
                shadow_run_id="",
                status=ShadowRunStatus.REJECTED,
                rejected_reasons=["missing_tenant_or_principal"],
                degraded=True,
            )

        run = await self._shadow_runs.create_run(
            event_id=request.event_id,
            tenant_id=request.tenant_id,
            principal=request.principal,
            trigger="evidence_gap_pivot",
            max_steps=cfg.react_shadow_max_steps,
            max_tool_calls=cfg.react_shadow_max_tool_calls,
        )

        query_ctx = ReactMockQueryContext(
            event_id=request.event_id,
            tenant_id=request.tenant_id,
            principal=request.principal,
            trace_id=request.trace_id,
            shadow_run_id=run.shadow_run_id,
        )
        adapter = ReactMockQueryAdapter(
            pipeline,
            knowledge_release_service=knowledge_release_service,
            settings=cfg,
        )
        allowed_agents = {
            MOCK_QUERY_AGENT_NAME: build_mock_query_agent_callable(adapter, query_ctx),
        }

        try:
            react_exec = await react_factory.for_shadow_run(
                request.event_id,
                shadow_run_id=run.shadow_run_id,
                tenant_id=request.tenant_id,
                allowed_agents=allowed_agents,
                allowed_tools=request.allowed_query_tools or None,
                max_calls=cfg.react_shadow_max_tool_calls,
            )
        except ToolCallGrantUnavailableError as exc:
            await self._shadow_runs.finalize_run(
                run.shadow_run_id,
                status=ShadowRunStatus.REJECTED,
                step_count=0,
                tool_call_count=0,
                rejected_reasons=["grant_service_unavailable"],
                result_summary={"detail": str(exc)},
            )
            return ShadowQueryPivotResult(
                shadow_run_id=run.shadow_run_id,
                status=ShadowRunStatus.REJECTED,
                rejected_reasons=["grant_service_unavailable"],
                degraded=True,
            )

        context: dict[str, Any] = {
            "event_id": request.event_id,
            "tenant_id": request.tenant_id,
            "shadow_run_id": run.shadow_run_id,
            "gaps": "; ".join(request.evidence_gaps) or request.goal,
            "observation": request.observation[:2000],
        }

        engine = ReActEngine(
            llm_client,
            tool_call_budget=cfg.react_shadow_max_tool_calls,
            agent_name="shadow_query_pivot",
        )
        react_result = await engine.run(
            request.goal,
            context,
            react_exec,
            max_rounds=cfg.react_shadow_max_steps,
        )

        artifacts = await self._persist_round_artifacts(run, react_result.rounds)
        record_ids = await self._persist_shadow_decision_records(
            run,
            request,
            react_result.rounds,
        )

        tool_calls = sum(
            1
            for round_ in react_result.rounds
            if round_.action.action_type is ReActActionType.CALL_TOOL
        )
        status = ShadowRunStatus.COMPLETED
        if react_result.stop_reason is ReActStopReason.ERROR:
            status = ShadowRunStatus.FAILED

        finalized = await self._shadow_runs.finalize_run(
            run.shadow_run_id,
            status=status,
            step_count=len(react_result.rounds),
            tool_call_count=tool_calls,
            result_summary={
                "stop_reason": react_result.stop_reason.value,
                "confidence": react_result.final_confidence,
                "artifact_count": len(artifacts),
                "decision_record_count": len(record_ids),
            },
        )
        assert finalized is not None
        return ShadowQueryPivotResult(
            shadow_run_id=run.shadow_run_id,
            status=status,
            react_stop_reason=react_result.stop_reason.value,
            artifacts=artifacts,
            decision_record_ids=record_ids,
            degraded=status is not ShadowRunStatus.COMPLETED,
        )

    async def _persist_round_artifacts(
        self,
        run: ShadowRun,
        rounds: list[ReActRound],
    ) -> list:
        from app.models.shadow_run import ShadowQueryArtifact

        artifacts: list[ShadowQueryArtifact] = []
        for round_ in rounds:
            action_result = round_.action_result or {}
            if round_.action.action_type is ReActActionType.CALL_AGENT:
                if action_result.get("status") == "success":
                    artifact = await self._shadow_runs.persist_artifact(
                        run,
                        kind=ShadowQueryArtifactKind.RETRIEVAL_HIT,
                        payload={
                            "round": round_.round_index,
                            "agent": round_.action.target_name,
                            "chunk_count": action_result.get("data", {}).get("chunk_count", 0),
                            "plan_hash": action_result.get("data", {}).get("plan_hash", ""),
                            "chunks": action_result.get("data", {}).get("chunks", []),
                        },
                        provenance={"shadow_run_id": run.shadow_run_id},
                    )
                    artifacts.append(artifact)
            elif round_.action.action_type is ReActActionType.CALL_TOOL:
                if action_result.get("status") in {"success", "ok"}:
                    artifact = await self._shadow_runs.persist_artifact(
                        run,
                        kind=ShadowQueryArtifactKind.TOOL_PROJECTION,
                        payload={
                            "round": round_.round_index,
                            "tool_name": round_.action.target_name,
                            "projection_hash": action_result.get("projection_hash"),
                            "data": action_result.get("data", {}),
                        },
                        provenance={"shadow_run_id": run.shadow_run_id},
                    )
                    artifacts.append(artifact)
        if artifacts:
            summary = await self._shadow_runs.persist_artifact(
                run,
                kind=ShadowQueryArtifactKind.PIVOT_SUMMARY,
                payload={
                    "round_count": len(rounds),
                    "artifact_count": len(artifacts),
                },
                provenance={"shadow_run_id": run.shadow_run_id},
            )
            artifacts.append(summary)
        return artifacts

    async def _persist_shadow_decision_records(
        self,
        run: ShadowRun,
        request: ShadowQueryPivotRequest,
        rounds: list[ReActRound],
    ) -> list[str]:
        record_ids: list[str] = []
        for round_ in rounds:
            record_id = f"sdr-{secrets.token_hex(4)}"
            idempotency_key = f"shadow:{run.shadow_run_id}:reflect:round{round_.round_index}"
            record = DecisionRecord(
                record_id=record_id,
                event_id=request.event_id,
                stage=DecisionStage.REACT_REFLECT,
                actor="shadow_query_pivot",
                reason_codes=[round_.reason_code.value],
                decision_summary=round_.decision_summary[:512],
                confidence=round_.confidence,
                uncertainty_codes=[round_.uncertainty_code.value],
                idempotency_key=idempotency_key,
                retention_policy="shadow_pivot_v1",
                owner=run.namespace_key,
                selected={
                    "action_type": round_.action.action_type.value if round_.action else "",
                    "target_name": round_.action.target_name if round_.action else "",
                },
            )
            record = record.model_copy(update={"record_hash": _record_hash(record)})
            persisted = await self._shadow_runs.persist_decision_record(run, record)
            record_ids.append(persisted)
        return record_ids


__all__ = ["ShadowQueryPivotService"]
