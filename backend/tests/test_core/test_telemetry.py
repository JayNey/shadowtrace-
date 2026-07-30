"""OpenTelemetry bootstrap tests (ISSUE-092)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from opentelemetry import trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import BaseModel, ConfigDict

from app.agents.base import BaseAgent
from app.core import metrics as metrics_module
from app.core.config import get_settings
from app.core.llm.base import (
    BaseLLMClient,
    InMemoryLLMCallAuditRecorder,
    LLMMessage,
    ProviderResponse,
)
from app.core.metrics import (
    observe_writeback_queue_age,
    record_action_unknown,
    record_writeback,
    record_writeback_retry,
    reset_metrics_for_tests,
)
from app.core.telemetry import (
    disposition_span,
    is_telemetry_enabled,
    reset_telemetry_for_tests,
    setup_telemetry,
    traced_operation,
)
from app.models.agent_io import TriageAgentInput
from app.models.enums import ToolCategory
from app.models.tool_meta import RoutingKind, ToolMeta, ToolResult, ToolResultStatus
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry


class _StubLLM(BaseLLMClient):
    async def _request(
        self,
        messages: list[LLMMessage],
        *,
        model_name: str,
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> ProviderResponse:
        del messages, temperature, max_tokens, json_mode
        return ProviderResponse(content='{"ok": true}', model_name=model_name)


def _metric_sum(metric_reader: InMemoryMetricReader, name: str) -> float:
    data = metric_reader.collect()
    if data is None:
        data = metric_reader.get_metrics_data()
    assert data is not None
    total = 0.0
    for resource_metrics in data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            for metric in scope_metrics.metrics:
                if metric.name != name:
                    continue
                for point in metric.data.data_points:
                    total += float(point.value)
    return total


@pytest.fixture(autouse=True)
def _reset_settings_cache(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    get_settings.cache_clear()
    monkeypatch.delenv("OTEL_ENABLED", raising=False)
    reset_telemetry_for_tests()
    reset_metrics_for_tests()
    yield
    get_settings.cache_clear()
    reset_telemetry_for_tests()
    reset_metrics_for_tests()


TelemetryReaders = tuple[InMemorySpanExporter, InMemoryMetricReader]


@pytest.fixture
def enabled_telemetry(monkeypatch: pytest.MonkeyPatch) -> Iterator[TelemetryReaders]:
    """Patch tracer/meter accessors without fighting global provider overrides."""
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))

    metric_reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[metric_reader])

    monkeypatch.setattr("app.core.telemetry._ENABLED", True)
    monkeypatch.setattr(
        "app.core.telemetry.get_tracer",
        lambda name: tracer_provider.get_tracer(name),
    )
    monkeypatch.setattr(
        "app.core.telemetry.get_meter",
        lambda name: meter_provider.get_meter(name),
    )
    reset_metrics_for_tests()
    yield span_exporter, metric_reader
    span_exporter.clear()
    reset_metrics_for_tests()


def test_otel_disabled_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "false")
    get_settings.cache_clear()

    setup_telemetry()
    assert is_telemetry_enabled() is False

    with traced_operation("api.request", route="/health"):
        with disposition_span(
            "disposition.submit",
            event_id="evt-test",
            action_id="act-test",
        ):
            record_writeback(status="confirmed", adapter="mock_xdr")
            record_writeback_retry(adapter="mock_xdr")
            record_action_unknown(adapter="mock_xdr")
            observe_writeback_queue_age(1.5)

    assert metrics_module._writeback_total is None


def test_celery_worker_init_calls_setup_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def _capture(**kwargs: object) -> None:
        calls.append(dict(kwargs))

    monkeypatch.setattr("app.core.telemetry.setup_telemetry", _capture)
    from app.core.celery_app import init_worker_telemetry

    init_worker_telemetry(sender=None)
    assert len(calls) == 1
    assert "engine" in calls[0]


def test_trace_hierarchy_api_agent_tool_llm(
    enabled_telemetry: TelemetryReaders,
) -> None:
    span_exporter, _ = enabled_telemetry

    with traced_operation("api.request", route="/events/evt-demo/graph"):
        with traced_operation("agent.execute", agent_name="EvidenceAgent", event_id="evt-demo"):
            with traced_operation(
                "tool.execute",
                tool_name="query_evidence",
                event_id="evt-demo",
                agent_name="EvidenceAgent",
            ):
                pass

    span_exporter.force_flush()
    finished = span_exporter.get_finished_spans()
    names = [span.name for span in finished]
    assert "api.request" in names
    assert "agent.execute" in names
    assert "tool.execute" in names

    by_name = {span.name: span for span in finished}
    assert by_name["tool.execute"].context.trace_id == by_name["api.request"].context.trace_id
    assert by_name["agent.execute"].parent.span_id == by_name["api.request"].context.span_id
    assert by_name["tool.execute"].parent.span_id == by_name["agent.execute"].context.span_id


@pytest.mark.asyncio
async def test_llm_chat_emits_span_under_active_trace(
    enabled_telemetry: TelemetryReaders,
) -> None:
    from app.core.llm.base import InMemoryLLMCallAuditRecorder

    span_exporter, _ = enabled_telemetry
    llm = _StubLLM(
        primary_model="mock-model",
        audit_recorder=InMemoryLLMCallAuditRecorder(),
    )

    with traced_operation("api.request", route="/investigate"):
        with traced_operation("agent.execute", agent_name="TriageAgent", event_id="evt-llm"):
            await llm.chat(
                [LLMMessage(role="user", content="hello")],
                event_id="evt-llm",
                agent_name="TriageAgent",
                prompt_key="triage_extract",
            )

    span_exporter.force_flush()
    names = [span.name for span in span_exporter.get_finished_spans()]
    assert "llm.chat" in names


class _ChainOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True


def _telemetry_tool_registry() -> ToolRegistry:
    registry = ToolRegistry()

    async def ok_execute(params: dict[str, Any]) -> dict[str, Any]:
        del params
        return ToolResult(
            call_id="call-telemetry-test",
            tool_name="telemetry_ok",
            provider_name="test",
            status=ToolResultStatus.SUCCESS,
            data={"ok": True},
        ).model_dump(mode="json")

    registry.register(
        ToolMeta(
            tool_name="telemetry_ok",
            tool_category=ToolCategory.QUERY,
            routing_kind=RoutingKind.TOOL_PROVIDER_ONLY,
            default_timeout_s=5.0,
            input_schema={"type": "object", "additionalProperties": False},
            output_schema={"type": "object"},
        ),
        ok_execute,
    )
    return registry


class _TelemetryChainAgent(BaseAgent[TriageAgentInput, _ChainOutput]):
    agent_name = "triage_agent"

    async def _run(self, input: TriageAgentInput) -> _ChainOutput:
        assert self.tool_executor is not None
        assert self.llm_client is not None
        await self.tool_executor.call(
            "telemetry_ok",
            {},
            input.event_id,
            agent_name="triage_agent",
        )
        await self.llm_client.chat(
            [LLMMessage(role="user", content="ping")],
            event_id=input.event_id,
            agent_name="triage_agent",
            prompt_key="triage_extract",
        )
        return _ChainOutput()


@pytest.mark.asyncio
async def test_investigation_trace_links_agent_tool_llm(
    enabled_telemetry: TelemetryReaders,
) -> None:
    span_exporter, _ = enabled_telemetry
    llm = _StubLLM(
        primary_model="mock-model",
        audit_recorder=InMemoryLLMCallAuditRecorder(),
    )
    executor = ToolExecutor(registry=_telemetry_tool_registry())
    agent = _TelemetryChainAgent(llm_client=llm, tool_executor=executor)

    with traced_operation("api.request", route="/investigate"):
        await agent.execute(TriageAgentInput(event_id="evt-chain"))

    span_exporter.force_flush()
    names = [span.name for span in span_exporter.get_finished_spans()]
    assert "api.request" in names
    assert "agent.execute" in names
    assert "tool.execute" in names
    assert "llm.chat" in names

    by_name = {span.name: span for span in span_exporter.get_finished_spans()}
    trace_id = by_name["api.request"].context.trace_id
    assert by_name["agent.execute"].context.trace_id == trace_id
    assert by_name["tool.execute"].context.trace_id == trace_id
    assert by_name["llm.chat"].context.trace_id == trace_id
    assert by_name["agent.execute"].parent.span_id == by_name["api.request"].context.span_id
    assert by_name["tool.execute"].parent.span_id == by_name["agent.execute"].context.span_id
    assert by_name["llm.chat"].parent.span_id == by_name["agent.execute"].context.span_id


def test_business_metrics_record_when_enabled(
    enabled_telemetry: TelemetryReaders,
) -> None:
    _, metric_reader = enabled_telemetry

    record_writeback(status="confirmed", adapter="mock_xdr")
    record_writeback(status="unknown", adapter="mock_xdr")
    record_writeback_retry(adapter="mock_xdr")
    record_action_unknown(adapter="mock_xdr")
    observe_writeback_queue_age(2.0)

    assert _metric_sum(metric_reader, "shadowtrace_writeback_total") >= 2.0
    assert _metric_sum(metric_reader, "shadowtrace_writeback_retry_total") >= 1.0
    assert _metric_sum(metric_reader, "shadowtrace_action_unknown_total") >= 1.0


def test_tool_executor_import_with_otel_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "false")
    get_settings.cache_clear()
    setup_telemetry()
    assert ToolExecutor is not None
    assert trace.get_tracer(__name__) is not None


def test_main_app_imports_with_otel_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "false")
    get_settings.cache_clear()
    import importlib

    main = importlib.import_module("app.main")
    assert main.app.title == "ShadowTrace"
