"""Early process bootstrap side effects (ISSUE-223)."""

from __future__ import annotations

from app.core.logging_setup import configure_logging

configure_logging()

__all__: list[str] = []
