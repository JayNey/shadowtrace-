"""Limited retry for transient PostgreSQL contention (ISSUE-355 / FIX-002).

Retries ``serialization_failure`` (40001) and ``deadlock_detected`` (40P01) with
short backoff.  Callers must pass a factory that opens a **fresh** session per
attempt — do not reuse a session after a failed transaction.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import TypeVar

from sqlalchemy.exc import DBAPIError, InternalError, OperationalError

logger = logging.getLogger(__name__)

_TRANSIENT_PG_CODES = frozenset({"40001", "40P01"})

T = TypeVar("T")


def is_transient_db_error(exc: BaseException) -> bool:
    """Return True for deadlock / serialization failures and connection blips."""
    if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        return True
    if isinstance(exc, DBAPIError) and exc.connection_invalidated:
        return True
    if isinstance(exc, (OperationalError, InternalError)):
        orig = getattr(exc, "orig", None)
        if orig is not None:
            code = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
            if code in _TRANSIENT_PG_CODES:
                return True
        lowered = str(exc).lower()
        if "deadlock" in lowered or "serialization" in lowered:
            return True
    return False


async def run_with_db_retry(
    factory: Callable[[], Awaitable[T]],
    *,
    max_attempts: int = 4,
    base_delay_s: float = 0.02,
    operation: str = "db_transaction",
) -> T:
    """Run *factory* until success or non-transient failure."""
    last_exc: BaseException | None = None
    for attempt in range(max_attempts):
        try:
            return await factory()
        except Exception as exc:
            last_exc = exc
            if not is_transient_db_error(exc) or attempt + 1 >= max_attempts:
                raise
            delay = base_delay_s * (attempt + 1)
            logger.warning(
                "%s transient db error attempt=%d/%d — retrying in %.3fs: %s",
                operation,
                attempt + 1,
                max_attempts,
                delay,
                exc,
            )
            await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc


__all__ = ["is_transient_db_error", "run_with_db_retry"]
