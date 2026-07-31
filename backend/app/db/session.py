"""Async engine and session factory — delegates to ``SessionProvider`` (ISSUE-118)."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.db.session_provider import (
    dispose_session_provider,
    get_session,
    get_session_provider,
)

__all__ = [
    "dispose_session_provider",
    "get_engine",
    "get_session",
    "get_session_factory",
    "get_session_provider",
]


def get_engine() -> AsyncEngine:
    """Return the process-local async engine."""
    return get_session_provider().engine()


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the process-local session factory."""
    return get_session_provider().session_factory()
