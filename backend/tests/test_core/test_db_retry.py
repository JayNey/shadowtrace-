"""Unit tests for transient DB retry helper (ISSUE-355)."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import OperationalError

from app.core.db_retry import is_transient_db_error, run_with_db_retry


def test_is_transient_db_error_deadlock_message() -> None:
    exc = OperationalError("stmt", {}, Exception("deadlock detected"))
    assert is_transient_db_error(exc)


@pytest.mark.asyncio
async def test_run_with_db_retry_recovers_from_transient() -> None:
    attempts = 0

    async def _flaky() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise OperationalError("stmt", {}, Exception("deadlock detected"))
        return "ok"

    result = await run_with_db_retry(_flaky, max_attempts=3, base_delay_s=0)
    assert result == "ok"
    assert attempts == 2


@pytest.mark.asyncio
async def test_run_with_db_retry_non_transient_fails_fast() -> None:
    attempts = 0

    async def _fail() -> None:
        nonlocal attempts
        attempts += 1
        raise ValueError("permanent")

    with pytest.raises(ValueError, match="permanent"):
        await run_with_db_retry(_fail, max_attempts=4, base_delay_s=0)
    assert attempts == 1
