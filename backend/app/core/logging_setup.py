"""Application logging bootstrap with secret redaction (ISSUE-223)."""

from __future__ import annotations

import logging
import sys

from app.core.sanitization import RedactingFormatter

_DEFAULT_FORMAT = "%(levelname)s:%(name)s:%(message)s"
_APP_LOGGER_NAME = "app"

_CONFIGURED = False


def _existing_format(formatter: logging.Formatter | None) -> str:
    if formatter is None:
        return _DEFAULT_FORMAT
    return formatter._fmt  # type: ignore[attr-defined]


def _apply_redacting_formatter(handler: logging.Handler) -> None:
    if isinstance(handler.formatter, RedactingFormatter):
        return
    handler.setFormatter(RedactingFormatter(_existing_format(handler.formatter)))


def configure_logging(*, force: bool = False) -> None:
    """Install ``RedactingFormatter`` on root handlers and enable app logger propagation."""
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

    app_logger = logging.getLogger(_APP_LOGGER_NAME)
    app_logger.propagate = True

    _CONFIGURED = True


def reset_logging_setup_for_tests() -> None:
    """Allow tests to re-run ``configure_logging``."""
    global _CONFIGURED
    _CONFIGURED = False


__all__ = ["configure_logging", "reset_logging_setup_for_tests"]
