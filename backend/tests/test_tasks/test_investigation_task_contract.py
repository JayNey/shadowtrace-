"""Callable signature contract tests for investigation Celery tasks (ISSUE-264)."""

from __future__ import annotations

import inspect

import pytest

from app.tasks import investigation_tasks as tasks
from app.tasks.investigation_task_contract import (
    EXECUTE_INVESTIGATION_KWARG_NAMES,
    RUN_ANALYSIS_ONLY_BODY_KWARG_NAMES,
    RUN_ANALYSIS_ONLY_TASK_KWARG_NAMES,
    RUN_INVESTIGATION_BODY_KWARG_NAMES,
    RUN_INVESTIGATION_TASK_KWARG_NAMES,
    assert_callable_accepts_kwarg_names,
    build_analysis_only_dispatch_kwargs,
    build_investigation_dispatch_kwargs,
)
from tests.support.investigation_task_doubles import (
    assert_double_covers_analysis_only_body_contract,
    assert_double_covers_body_contract,
    assert_double_covers_execute_contract,
    make_execute_investigation_double,
    make_run_analysis_only_body_double,
    make_run_investigation_body_double,
)


def test_execute_investigation_signature_contract() -> None:
    sig = inspect.signature(tasks.execute_investigation)
    assert sig.parameters["generate_report"].default is True
    assert_callable_accepts_kwarg_names(
        tasks.execute_investigation,
        EXECUTE_INVESTIGATION_KWARG_NAMES,
        label="execute_investigation",
    )


def test_run_investigation_body_signature_contract() -> None:
    sig = inspect.signature(tasks._run_investigation_body)
    assert sig.parameters["generate_report"].default is True
    assert_callable_accepts_kwarg_names(
        tasks._run_investigation_body,
        RUN_INVESTIGATION_BODY_KWARG_NAMES,
        label="_run_investigation_body",
    )


def test_run_analysis_only_body_signature_contract() -> None:
    assert_callable_accepts_kwarg_names(
        tasks._run_analysis_only_body,
        RUN_ANALYSIS_ONLY_BODY_KWARG_NAMES,
        label="_run_analysis_only_body",
    )


def test_run_investigation_task_signature_contract() -> None:
    sig = inspect.signature(tasks.run_investigation.run)
    assert sig.parameters["generate_report"].default is True
    assert_callable_accepts_kwarg_names(
        tasks.run_investigation.run,
        RUN_INVESTIGATION_TASK_KWARG_NAMES,
        label="run_investigation",
    )


def test_run_analysis_only_task_signature_contract() -> None:
    assert_callable_accepts_kwarg_names(
        tasks.run_analysis_only_investigation.run,
        RUN_ANALYSIS_ONLY_TASK_KWARG_NAMES,
        label="run_analysis_only_investigation",
    )


def test_signature_contract_rejects_loose_or_positional_only_parameters() -> None:
    def _loose_double(**_kwargs: object) -> None:
        return None

    def _positional_only(generate_report: bool, /) -> None:
        return None

    def _explicit_but_loose(generate_report: bool, **extras: object) -> None:
        return None

    with pytest.raises(AssertionError, match="generate_report"):
        assert_callable_accepts_kwarg_names(
            _loose_double,
            frozenset({"generate_report"}),
            label="loose double",
        )
    with pytest.raises(AssertionError, match="generate_report"):
        assert_callable_accepts_kwarg_names(
            _positional_only,
            frozenset({"generate_report"}),
            label="positional-only double",
        )
    with pytest.raises(AssertionError, match=r"\*\*extras"):
        assert_callable_accepts_kwarg_names(
            _explicit_but_loose,
            frozenset({"generate_report"}),
            label="hybrid loose double",
        )


def test_shared_dispatch_builders_include_generate_report() -> None:
    assert build_investigation_dispatch_kwargs()["generate_report"] is True
    assert build_investigation_dispatch_kwargs(generate_report=False)["generate_report"] is False
    assert build_investigation_dispatch_kwargs(
        intent_id="iin-contract",
        include_response_execution=True,
        generate_report=False,
    ) == {
        "include_response_execution": True,
        "generate_report": False,
        "intent_id": "iin-contract",
    }
    assert build_analysis_only_dispatch_kwargs()["generate_report"] is True
    assert build_analysis_only_dispatch_kwargs(
        generate_report=False,
        intent_id="iin-analysis-contract",
    ) == {
        "generate_report": False,
        "intent_id": "iin-analysis-contract",
    }


@pytest.mark.asyncio
async def test_test_doubles_accept_production_execute_kwargs() -> None:
    captured: dict[str, object] = {}
    double = make_execute_investigation_double(captured)
    assert_double_covers_execute_contract(double)
    kwargs = build_investigation_dispatch_kwargs(
        include_response_execution=True,
        generate_report=False,
        owner_id="owner-contract",
        lease_acquired=True,
    )

    await double("evt-contract", **kwargs)

    assert captured == {"event_id": "evt-contract", **kwargs}


@pytest.mark.asyncio
async def test_test_doubles_accept_production_body_kwargs() -> None:
    captured: dict[str, object] = {}
    double = make_run_investigation_body_double(captured)
    assert_double_covers_body_contract(double)

    await double(
        "evt-body-contract",
        include_response_execution=True,
        generate_report=False,
        owner_id="owner-body",
        task_id="task-body",
        redelivered=True,
        lease_acquired=True,
        request_headers={"x-redelivery-lookup-retries": 1},
    )

    assert captured == {
        "event_id": "evt-body-contract",
        "include_response_execution": True,
        "generate_report": False,
        "owner_id": "owner-body",
        "task_id": "task-body",
        "redelivered": True,
        "lease_acquired": True,
        "request_headers": {"x-redelivery-lookup-retries": 1},
    }


@pytest.mark.asyncio
async def test_test_doubles_accept_production_analysis_only_body_kwargs() -> None:
    captured: dict[str, object] = {}
    double = make_run_analysis_only_body_double(captured)
    assert_double_covers_analysis_only_body_contract(double)

    await double(
        "evt-analysis-contract",
        generate_report=False,
        owner_id="owner-analysis",
        task_id="task-analysis",
        redelivered=True,
        lease_acquired=True,
        request_headers=None,
    )

    assert captured == {
        "event_id": "evt-analysis-contract",
        "generate_report": False,
        "owner_id": "owner-analysis",
        "task_id": "task-analysis",
        "redelivered": True,
        "lease_acquired": True,
        "request_headers": None,
    }
