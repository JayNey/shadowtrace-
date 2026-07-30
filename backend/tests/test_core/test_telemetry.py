"""OpenTelemetry bootstrap tests (ISSUE-092)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from opentelemetry import trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from app.core.config import get_settings
from app.core.llm.base import BaseLLMClient, LLMMessage, ProviderResponse
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
from app.tools.executor import ToolExecutor


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


def test_business_metrics_record_when_enabled(
    enabled_telemetry: tuple[InMemorySpanExporter, InMemoryMetricReader],
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
