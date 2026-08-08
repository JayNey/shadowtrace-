"""Shared typed contract for investigation Celery task payloads (ISSUE-264).

Production dispatch helpers and test doubles must derive kwargs from the same
builders so ``generate_report`` and lease flags cannot drift silently.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Final

EXECUTE_INVESTIGATION_KWARG_NAMES: Final = frozenset(
    {
        "include_response_execution",
        "generate_report",
        "owner_id",
        "lease_acquired",
    }
)

RUN_INVESTIGATION_BODY_KWARG_NAMES: Final = frozenset(
    {
        "include_response_execution",
        "generate_report",
        "owner_id",
        "redelivered",
        "lease_acquired",
    }
)

RUN_ANALYSIS_ONLY_BODY_KWARG_NAMES: Final = frozenset(
    {
        "generate_report",
        "owner_id",
        "redelivered",
        "lease_acquired",
    }
)

RUN_INVESTIGATION_TASK_KWARG_NAMES: Final = frozenset(
    {
        "include_response_execution",
        "generate_report",
        "intent_id",
        "owner_id",
        "lease_acquired",
    }
)

RUN_ANALYSIS_ONLY_TASK_KWARG_NAMES: Final = frozenset(
    {
        "generate_report",
        "owner_id",
        "lease_acquired",
    }
)


@dataclass(frozen=True, slots=True)
class InvestigationDispatchPayload:
    include_response_execution: bool = False
    generate_report: bool = True
    intent_id: str | None = None
    owner_id: str | None = None
    lease_acquired: bool = False

    def to_apply_async_kwargs(self) -> dict[str, object]:
        kwargs: dict[str, object] = {
            "include_response_execution": self.include_response_execution,
            "generate_report": self.generate_report,
        }
        if self.owner_id is not None:
            kwargs["owner_id"] = self.owner_id
        if self.intent_id is not None:
            kwargs["intent_id"] = self.intent_id
        if self.lease_acquired:
            kwargs["lease_acquired"] = True
        return kwargs


@dataclass(frozen=True, slots=True)
class AnalysisOnlyDispatchPayload:
    generate_report: bool = True
    owner_id: str | None = None
    lease_acquired: bool = False

    def to_apply_async_kwargs(self) -> dict[str, object]:
        kwargs: dict[str, object] = {"generate_report": self.generate_report}
        if self.owner_id is not None:
            kwargs["owner_id"] = self.owner_id
        if self.lease_acquired:
            kwargs["lease_acquired"] = True
        return kwargs


def build_investigation_dispatch_kwargs(
    *,
    include_response_execution: bool = False,
    generate_report: bool = True,
    intent_id: str | None = None,
    owner_id: str | None = None,
    lease_acquired: bool = False,
) -> dict[str, object]:
    return InvestigationDispatchPayload(
        include_response_execution=include_response_execution,
        generate_report=generate_report,
        intent_id=intent_id,
        owner_id=owner_id,
        lease_acquired=lease_acquired,
    ).to_apply_async_kwargs()


def build_analysis_only_dispatch_kwargs(
    *,
    generate_report: bool = True,
    owner_id: str | None = None,
    lease_acquired: bool = False,
) -> dict[str, object]:
    return AnalysisOnlyDispatchPayload(
        generate_report=generate_report,
        owner_id=owner_id,
        lease_acquired=lease_acquired,
    ).to_apply_async_kwargs()


def _callable_accepts_kwarg_names(fn: Any, required: frozenset[str]) -> bool:
    sig = inspect.signature(fn)
    if any(param.kind == inspect.Parameter.VAR_KEYWORD for param in sig.parameters.values()):
        return False
    keyword_kinds = {
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    }
    return all(
        name in sig.parameters and sig.parameters[name].kind in keyword_kinds for name in required
    )


def assert_callable_accepts_kwarg_names(fn: Any, required: frozenset[str], *, label: str) -> None:
    if not _callable_accepts_kwarg_names(fn, required):
        sig = inspect.signature(fn)
        keyword_kinds = {
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        }
        incompatible = sorted(
            name
            for name in required
            if name not in sig.parameters or sig.parameters[name].kind not in keyword_kinds
        )
        incompatible.extend(
            f"**{name}"
            for name, parameter in sig.parameters.items()
            if parameter.kind == inspect.Parameter.VAR_KEYWORD
        )
        raise AssertionError(f"{label} missing or non-keyword parameters: {incompatible}")


__all__ = [
    "AnalysisOnlyDispatchPayload",
    "EXECUTE_INVESTIGATION_KWARG_NAMES",
    "InvestigationDispatchPayload",
    "RUN_ANALYSIS_ONLY_BODY_KWARG_NAMES",
    "RUN_ANALYSIS_ONLY_TASK_KWARG_NAMES",
    "RUN_INVESTIGATION_BODY_KWARG_NAMES",
    "RUN_INVESTIGATION_TASK_KWARG_NAMES",
    "assert_callable_accepts_kwarg_names",
    "build_analysis_only_dispatch_kwargs",
    "build_investigation_dispatch_kwargs",
]
