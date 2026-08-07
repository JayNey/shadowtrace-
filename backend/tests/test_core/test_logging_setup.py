"""Logging redaction bootstrap tests (ISSUE-223)."""

from __future__ import annotations

import importlib
import io
import logging

import pytest

from app.core.logging_setup import configure_logging, reset_logging_setup_for_tests
from app.core.sanitization import RedactingFormatter
from app.core.telemetry import disposition_span


@pytest.fixture(autouse=True)
def _reset_logging_state() -> None:
    reset_logging_setup_for_tests()
    yield
    reset_logging_setup_for_tests()


def test_configure_logging_applies_redacting_formatter_to_root() -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(logging.StreamHandler())

    configure_logging()

    assert root.handlers
    assert all(isinstance(handler.formatter, RedactingFormatter) for handler in root.handlers)


def test_configure_logging_redacts_sensitive_log_output() -> None:
    stream = io.StringIO()
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(stream)
    root.addHandler(handler)
    root.setLevel(logging.INFO)

    configure_logging()

    logger = logging.getLogger("app.tests.logging_redaction")
    logger.info(
        "auth failed token=super-secret-token password='plain-text-password' "
        "Authorization: Bearer jwt-like-token-value"
    )

    output = stream.getvalue()
    assert "super-secret-token" not in output
    assert "plain-text-password" not in output
    assert "jwt-like-token-value" not in output
    assert "[REDACTED]" in output


def test_configure_logging_is_idempotent_without_double_wrap() -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(logging.StreamHandler())

    configure_logging()
    first_formatter = root.handlers[0].formatter
    configure_logging()
    second_formatter = root.handlers[0].formatter

    assert first_formatter is second_formatter
    assert isinstance(second_formatter, RedactingFormatter)


def test_main_import_installs_redacting_formatter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "false")
    from app.core.config import get_settings

    get_settings.cache_clear()
    reset_logging_setup_for_tests()

    main = importlib.import_module("app.main")
    assert main.app.title == "ShadowTrace"

    root = logging.getLogger()
    assert root.handlers
    assert any(isinstance(handler.formatter, RedactingFormatter) for handler in root.handlers)


def test_disposition_span_still_records_only_identifier_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))

    monkeypatch.setattr("app.core.telemetry._ENABLED", True)
    monkeypatch.setattr(
        "app.core.telemetry.get_tracer",
        lambda name: tracer_provider.get_tracer(name),
    )

    with disposition_span(
        "disposition.submit",
        event_id="evt-logging-test",
        action_id="act-logging-test",
        disposition_id="disp-logging-test",
        writeback_id="wbk-logging-test",
    ):
        pass

    span_exporter.force_flush()
    finished = span_exporter.get_finished_spans()
    assert len(finished) == 1
    attrs = dict(finished[0].attributes or {})
    assert attrs["shadowtrace.event_id"] == "evt-logging-test"
    assert attrs["shadowtrace.action_id"] == "act-logging-test"
    assert attrs["shadowtrace.disposition_id"] == "disp-logging-test"
    assert attrs["shadowtrace.writeback_id"] == "wbk-logging-test"
    assert "password" not in attrs
    assert "token" not in attrs
