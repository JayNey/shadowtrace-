"""Test doubles aligned with investigation Celery task contracts (ISSUE-264)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.tasks.investigation_task_contract import (
    EXECUTE_INVESTIGATION_KWARG_NAMES,
    RUN_ANALYSIS_ONLY_BODY_KWARG_NAMES,
    RUN_INVESTIGATION_BODY_KWARG_NAMES,
    assert_callable_accepts_kwarg_names,
)


def make_execute_investigation_double(
    captured: dict[str, Any],
    *,
    result_status: str = "completed",
) -> Callable[..., Any]:
    """Return an ``execute_investigation`` double that accepts the production kwargs."""

    async def _fake_execute_investigation(
        event_id: str,
        *,
        include_response_execution: bool = False,
        generate_report: bool = True,
        owner_id: str | None = None,
        lease_acquired: bool = False,
    ) -> dict[str, str]:
        captured.clear()
        captured.update(
            {
                "event_id": event_id,
                "include_response_execution": include_response_execution,
                "generate_report": generate_report,
                "owner_id": owner_id,
                "lease_acquired": lease_acquired,
            }
        )
        return {"status": result_status, "event_id": event_id}

    return _fake_execute_investigation


def make_run_investigation_body_double(
    captured: dict[str, Any],
    *,
    result_status: str = "completed",
) -> Callable[..., Any]:
    """Return a ``_run_investigation_body`` double that accepts the production kwargs."""

    async def _fake_body(
        event_id: str,
        *,
        include_response_execution: bool = False,
        generate_report: bool = True,
        owner_id: str,
        redelivered: bool,
        lease_acquired: bool = False,
    ) -> dict[str, str]:
        captured.clear()
        captured.update(
            {
                "event_id": event_id,
                "include_response_execution": include_response_execution,
                "generate_report": generate_report,
                "owner_id": owner_id,
                "redelivered": redelivered,
                "lease_acquired": lease_acquired,
            }
        )
        return {"status": result_status, "event_id": event_id}

    return _fake_body


def make_run_analysis_only_body_double(
    captured: dict[str, Any],
    *,
    result_status: str = "completed",
) -> Callable[..., Any]:
    """Return a strict ``_run_analysis_only_body`` double."""

    async def _fake_body(
        event_id: str,
        *,
        generate_report: bool,
        owner_id: str,
        redelivered: bool,
        lease_acquired: bool = False,
    ) -> dict[str, str]:
        captured.clear()
        captured.update(
            {
                "event_id": event_id,
                "generate_report": generate_report,
                "owner_id": owner_id,
                "redelivered": redelivered,
                "lease_acquired": lease_acquired,
            }
        )
        return {"status": result_status, "event_id": event_id}

    return _fake_body


def assert_double_covers_execute_contract(double: Callable[..., Any]) -> None:
    assert_callable_accepts_kwarg_names(
        double,
        EXECUTE_INVESTIGATION_KWARG_NAMES,
        label="execute_investigation double",
    )


def assert_double_covers_body_contract(double: Callable[..., Any]) -> None:
    assert_callable_accepts_kwarg_names(
        double,
        RUN_INVESTIGATION_BODY_KWARG_NAMES,
        label="_run_investigation_body double",
    )


def assert_double_covers_analysis_only_body_contract(double: Callable[..., Any]) -> None:
    assert_callable_accepts_kwarg_names(
        double,
        RUN_ANALYSIS_ONLY_BODY_KWARG_NAMES,
        label="_run_analysis_only_body double",
    )
