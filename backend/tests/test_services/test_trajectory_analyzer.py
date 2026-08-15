"""TrajectoryAnalyzer tests (ISSUE-066)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.models.decision_trace import DecisionTrace, DecisionTraceEntry, DecisionTraceSummary
from app.models.enums import DecisionTraceEntryType, TrajectoryMetric
from app.models.trajectory import TrajectoryReport

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _entry(
    entry_type: DecisionTraceEntryType,
    actor: str = "test",
    detail: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
) -> DecisionTraceEntry:
    return DecisionTraceEntry(
        entry_id=f"dte-{actor}-{entry_type.value}",
        entry_type=entry_type,
        timestamp=timestamp or datetime(2026, 1, 1, tzinfo=UTC),
        actor=actor,
        title=f"{entry_type.value}: {actor}",
        detail=detail or {},
    )


def _mock_trace(entries: list[DecisionTraceEntry]) -> DecisionTrace:
    return DecisionTrace(
        event_id="evt-test",
        entries=entries,
        summary=DecisionTraceSummary(),
    )


async def _analyze_with_mock(mock_dt_service: MagicMock, event_id: str) -> TrajectoryReport:
    from app.services.trajectory_analyzer import TrajectoryAnalyzer

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "app.services.trajectory_analyzer.DecisionTraceService",
            lambda _sf: mock_dt_service,
        )
        return await TrajectoryAnalyzer(MagicMock()).analyze(event_id)


# --------------------------------------------------------------------------- #
# TrajectoryAnalyzer tests
# --------------------------------------------------------------------------- #


class TestTrajectoryAnalyzer:
    @pytest.mark.asyncio
    async def test_empty_trace_returns_insufficient(self) -> None:
        mock_dt_service = MagicMock()
        mock_dt_service.get_decision_trace = AsyncMock(return_value=_mock_trace([]))

        report = await _analyze_with_mock(mock_dt_service, "evt-empty")

        assert report.insufficient_trace is True
        assert report.total_steps == 0

    @pytest.mark.asyncio
    async def test_db_error_propagates(self) -> None:
        mock_dt_service = MagicMock()
        mock_dt_service.get_decision_trace = AsyncMock(side_effect=SQLAlchemyError("db down"))

        with pytest.raises(SQLAlchemyError):
            await _analyze_with_mock(mock_dt_service, "evt-db-error")

    @pytest.mark.asyncio
    async def test_redundant_tool_calls_detected(self) -> None:
        tool_detail = {
            "tool_name": "query_endpoint",
            "tool_category": "query",
            "status": "success",
            "duration_ms": 100,
            "retry_count": 0,
        }
        entries = [
            _entry(DecisionTraceEntryType.TOOL_CALL, "query_endpoint", tool_detail)
            for _ in range(4)
        ] + [
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "block_ip",
                {
                    "tool_name": "block_ip",
                    "tool_category": "action",
                    "status": "success",
                    "duration_ms": 50,
                    "retry_count": 0,
                },
            )
        ]
        mock_dt_service = MagicMock()
        mock_dt_service.get_decision_trace = AsyncMock(return_value=_mock_trace(entries))

        report = await _analyze_with_mock(mock_dt_service, "evt-test")

        redundant = report.metrics.get(TrajectoryMetric.REDUNDANT_TOOL_CALLS, 0)
        assert redundant == 2.0  # 4 calls → 2 excess above threshold 3
        assert any("冗余工具调用" in finding for finding in report.findings)

    @pytest.mark.asyncio
    async def test_no_redundant_when_below_threshold(self) -> None:
        entries = [
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "query_endpoint",
                {
                    "tool_name": "query_endpoint",
                    "tool_category": "query",
                    "status": "success",
                    "duration_ms": 100,
                    "retry_count": 0,
                },
            )
            for _ in range(2)
        ]
        mock_dt_service = MagicMock()
        mock_dt_service.get_decision_trace = AsyncMock(return_value=_mock_trace(entries))

        report = await _analyze_with_mock(mock_dt_service, "evt-test")

        assert report.metrics.get(TrajectoryMetric.REDUNDANT_TOOL_CALLS, 0) == 0.0

    @pytest.mark.asyncio
    async def test_loop_suspected_zero_for_normal_trace(self) -> None:
        entries = [
            _entry(DecisionTraceEntryType.AGENT_EXECUTION, "triage_agent"),
            _entry(DecisionTraceEntryType.AGENT_EXECUTION, "evidence_agent"),
            _entry(DecisionTraceEntryType.AGENT_EXECUTION, "risk_agent"),
        ]
        mock_dt_service = MagicMock()
        mock_dt_service.get_decision_trace = AsyncMock(return_value=_mock_trace(entries))

        report = await _analyze_with_mock(mock_dt_service, "evt-test")

        assert report.metrics.get(TrajectoryMetric.LOOP_SUSPECTED, 0) == 0.0

    @pytest.mark.asyncio
    async def test_replan_effectiveness_with_realistic_verify_detail(self) -> None:
        entries = [
            _entry(DecisionTraceEntryType.AGENT_EXECUTION, "PlannerAgent"),
            _entry(
                DecisionTraceEntryType.AGENT_EXECUTION,
                "VerifyAgent",
                {
                    "agent_name": "VerifyAgent",
                    "status": "completed",
                    "overall_status": "failed",
                    "need_action_replan": True,
                },
            ),
            _entry(DecisionTraceEntryType.AGENT_EXECUTION, "PlannerAgent"),
            _entry(
                DecisionTraceEntryType.AGENT_EXECUTION,
                "VerifyAgent",
                {
                    "agent_name": "VerifyAgent",
                    "status": "completed",
                    "overall_status": "success",
                    "need_action_replan": False,
                },
            ),
        ]
        mock_dt_service = MagicMock()
        mock_dt_service.get_decision_trace = AsyncMock(return_value=_mock_trace(entries))

        report = await _analyze_with_mock(mock_dt_service, "evt-test")

        assert report.metrics.get(TrajectoryMetric.REPLAN_EFFECTIVENESS, 0) == 1.0
        assert any("重规划有效" in finding for finding in report.findings)

    @pytest.mark.asyncio
    async def test_evidence_yield_uses_query_tools_only(self) -> None:
        entries = [
            _entry(
                DecisionTraceEntryType.AGENT_EXECUTION,
                "EvidenceAgent",
                {"status": "completed", "collection_status": "completed"},
            ),
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "query_dns",
                {"tool_name": "query_dns", "tool_category": "query", "status": "success"},
            ),
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "query_dns",
                {"tool_name": "query_dns", "tool_category": "query", "status": "success"},
            ),
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "block_ip",
                {"tool_name": "block_ip", "tool_category": "action", "status": "success"},
            ),
        ]
        mock_dt_service = MagicMock()
        mock_dt_service.get_decision_trace = AsyncMock(return_value=_mock_trace(entries))

        report = await _analyze_with_mock(mock_dt_service, "evt-test")

        assert report.metrics.get(TrajectoryMetric.EVIDENCE_YIELD, 0) == 0.5

    def test_api_response_structure(self) -> None:
        report = TrajectoryReport(
            event_id="evt-test",
            total_steps=5,
            agent_invocations=3,
            tool_calls=1,
            llm_calls=1,
            metrics={TrajectoryMetric.STEPS_TO_VERDICT: 5.0},
            findings=["轨迹分析未发现异常"],
        )
        data = report.model_dump()
        assert data["event_id"] == "evt-test"
        assert data["total_steps"] == 5
        assert data["metrics"]["steps_to_verdict"] == 5.0
        assert len(data["findings"]) == 1


class TestTrajectoryApi:
    def test_get_trajectory_returns_report_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from app.api.v1.deps import get_event_service, reset_deps
        from app.main import app
        from app.services.trajectory_analyzer import TrajectoryAnalyzer

        monkeypatch.setenv(
            "DEV_AUTH_TOKENS",
            json.dumps({"analyst-token": {"subject": "analyst-1", "roles": ["analyst"]}}),
        )
        reset_deps()

        event = MagicMock()
        event.event_id = "evt-traj-api"

        async def _get_event(_event_id: str) -> MagicMock:
            return event

        event_service = MagicMock()
        event_service.get_event = AsyncMock(side_effect=_get_event)
        app.dependency_overrides[get_event_service] = lambda: event_service

        monkeypatch.setattr(
            "app.api.v1.trajectory._try_get_session_factory",
            lambda: MagicMock(),
        )
        monkeypatch.setattr(
            TrajectoryAnalyzer,
            "analyze",
            AsyncMock(
                return_value=TrajectoryReport(
                    event_id="evt-traj-api",
                    total_steps=2,
                    agent_invocations=1,
                    metrics={TrajectoryMetric.LOOP_SUSPECTED: 0.0},
                    findings=["轨迹分析未发现异常"],
                )
            ),
        )

        client = TestClient(app)
        response = client.get("/api/v1/events/evt-traj-api/trajectory", headers=_auth_header())

        app.dependency_overrides.clear()
        reset_deps()

        assert response.status_code == 200
        body = response.json()
        assert body["event_id"] == "evt-traj-api"
        assert body["total_steps"] == 2
        assert body["metrics"]["loop_suspected"] == 0.0


def _auth_header() -> dict[str, str]:
    return {"Authorization": "Bearer analyst-token"}


__all__ = ["TestTrajectoryAnalyzer", "TestTrajectoryApi"]
