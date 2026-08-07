"""Logging redaction bootstrap tests (ISSUE-223)."""

from __future__ import annotations

import importlib
import io
import logging

import pytest
from uvicorn.config import Config

from app.core.logging_setup import configure_logging, reset_logging_setup_for_tests
from app.core.sanitization import RedactingFormatter


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


def test_configure_logging_redacts_uvicorn_logger_output() -> None:
    stream = io.StringIO()
    root = logging.getLogger()
    root.handlers.clear()
    configure_logging()

    Config("app.main:socket_app", host="127.0.0.1", port=8000, log_level="info")
    configure_logging(force=True)

    uvicorn_logger = logging.getLogger("uvicorn")
    assert uvicorn_logger.handlers
    from app.core.logging_setup import _RedactingFormatterAdapter

    assert isinstance(uvicorn_logger.handlers[0].formatter, _RedactingFormatterAdapter)

    for handler in uvicorn_logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.stream = stream

    uvicorn_logger.info("startup token=super-secret-token password='plain-text-password'")
    output = stream.getvalue()
    assert "super-secret-token" not in output
    assert "plain-text-password" not in output
    assert "[REDACTED]" in output


def test_main_import_installs_redacting_formatter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "false")
    from app.core.config import get_settings

    get_settings.cache_clear()
    reset_logging_setup_for_tests()

    import app.main as main

    main = importlib.reload(main)
    assert main.app.title == "ShadowTrace"

    root = logging.getLogger()
    assert root.handlers
    assert any(isinstance(handler.formatter, RedactingFormatter) for handler in root.handlers)


def test_celery_worker_init_configures_redacting_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    original = configure_logging

    def _spy(*args: object, **kwargs: object) -> None:
        calls.append((args, kwargs))
        original(*args, **kwargs)

    monkeypatch.setattr("app.core.logging_setup.configure_logging", _spy)
    from app.core.celery_app import init_worker_telemetry
    from app.db.session_provider import reset_session_provider

    reset_session_provider()
    init_worker_telemetry(sender=None)

    assert calls
    assert calls[0][1].get("force") is None
