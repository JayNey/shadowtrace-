"""Application logging bootstrap with secret redaction (ISSUE-223)."""

from __future__ import annotations

import logging
import sys

from app.core.sanitization import RedactingFormatter, redact_sensitive_text

_DEFAULT_FORMAT = "%(levelname)s:%(name)s:%(message)s"
_APP_LOGGER_NAME = "app"
_THIRD_PARTY_LOGGER_NAMES = ("uvicorn", "uvicorn.error", "uvicorn.access")

_CONFIGURED = False


class _RedactingFormatterAdapter(logging.Formatter):
    """Wrap an existing formatter and redact its rendered output."""

    def __init__(self, delegate: logging.Formatter) -> None:
        super().__init__()
        self._delegate = delegate

    def format(self, record: logging.LogRecord) -> str:
        return redact_sensitive_text(self._delegate.format(record))


def _apply_redacting_formatter(handler: logging.Handler) -> None:
    existing = handler.formatter
    if isinstance(existing, (RedactingFormatter, _RedactingFormatterAdapter)):
        return
    if existing is None:
        handler.setFormatter(RedactingFormatter(_DEFAULT_FORMAT))
    else:
        handler.setFormatter(_RedactingFormatterAdapter(existing))


def _configure_logger_handlers(logger: logging.Logger) -> None:
    for handler in logger.handlers:
        _apply_redacting_formatter(handler)


def configure_logging(*, force: bool = False) -> None:
    """Install ``RedactingFormatter`` on root/app and known process loggers."""
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    root = logging.getLogger()
    if root.level == logging.NOTSET:
        root.setLevel(logging.INFO)

    if not root.handlers:
        root.addHandler(logging.StreamHandler(sys.stderr))

    for handler in root.handlers:
        _apply_redacting_formatter(handler)

    for logger_name in _THIRD_PARTY_LOGGER_NAMES:
        _configure_logger_handlers(logging.getLogger(logger_name))

    app_logger = logging.getLogger(_APP_LOGGER_NAME)
    app_logger.propagate = True

    _CONFIGURED = True


def reset_logging_setup_for_tests() -> None:
    """Allow tests to re-run ``configure_logging``."""
    global _CONFIGURED
    _CONFIGURED = False


__all__ = ["configure_logging", "reset_logging_setup_for_tests"]
