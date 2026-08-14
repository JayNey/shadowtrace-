"""ISSUE-277 baseline + wired `_maybe_resume` probes."""

from __future__ import annotations

import pytest

from app.models.enums import ExecutionSubstate
from app.services.disposition_sync_service import DispositionSyncService


class _ResumeIntent:
    def __init__(self, intent_id: str) -> None:
        self.intent_id = intent_id


@pytest.mark.asyncio
async def test_baseline_maybe_resume_skips_manual_resolution_when_unwired() -> None:
    """Without ManualResolutionService, MANUAL_RESOLUTION must not direct-resume."""
    calls: list[str] = []

    async def _resume(event_id: str) -> None:
        calls.append(event_id)

    class _Session:
        async def scalar(self, _stmt):  # noqa: ANN001
            return ExecutionSubstate.MANUAL_RESOLUTION.value

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class _Factory:
        def __call__(self):
            return _Session()

    svc = DispositionSyncService(
        _Factory(),  # type: ignore[arg-type]
        context_store=None,
        adapter_registry={},
        resume_investigation=_resume,
    )
    await svc._maybe_resume("evt-manual-hold")
    assert calls == []


@pytest.mark.asyncio
async def test_maybe_resume_manual_resolution_enqueues_durable_intent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wired path must enqueue durable intent instead of calling _resume."""
    resume_calls: list[str] = []
    created: list[str] = []
    scheduled: list[str] = []

    async def _resume(event_id: str) -> None:
        resume_calls.append(event_id)

    class _Manual:
        async def create_or_replay_resume_intent(self, event_id: str, **_kwargs: object):
            created.append(event_id)
            return _ResumeIntent(f"intent-{event_id}")

        def schedule_dispatch(
            self,
            *,
            event_id: str | None = None,
            intent_id: str | None = None,
            trigger: str = "unspecified",
        ) -> None:
            del event_id, intent_id, trigger
            scheduled.append("yes")

    class _Session:
        async def scalar(self, _stmt):  # noqa: ANN001
            return ExecutionSubstate.MANUAL_RESOLUTION.value

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class _Factory:
        def __call__(self):
            return _Session()

    svc = DispositionSyncService(
        _Factory(),  # type: ignore[arg-type]
        context_store=None,
        adapter_registry={},
        resume_investigation=_resume,
        manual_resolution=_Manual(),  # type: ignore[arg-type]
    )
    await svc._maybe_resume("evt-manual-wired")
    assert resume_calls == []
    assert created == ["evt-manual-wired"]
    assert scheduled == ["yes"]


@pytest.mark.asyncio
async def test_maybe_resume_manual_resolution_requires_intent_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing intent_id on resume intent must not silently schedule dispatch."""
    resume_calls: list[str] = []
    scheduled: list[str] = []

    async def _resume(event_id: str) -> None:
        resume_calls.append(event_id)

    class _Manual:
        async def create_or_replay_resume_intent(self, event_id: str, **_kwargs: object):
            del event_id, _kwargs
            return object()

        def schedule_dispatch(
            self,
            *,
            event_id: str | None = None,
            intent_id: str | None = None,
            trigger: str = "unspecified",
        ) -> None:
            del event_id, intent_id, trigger
            scheduled.append("yes")

    class _Session:
        async def scalar(self, _stmt):  # noqa: ANN001
            return ExecutionSubstate.MANUAL_RESOLUTION.value

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class _Factory:
        def __call__(self):
            return _Session()

    svc = DispositionSyncService(
        _Factory(),  # type: ignore[arg-type]
        context_store=None,
        adapter_registry={},
        resume_investigation=_resume,
        manual_resolution=_Manual(),  # type: ignore[arg-type]
    )
    await svc._maybe_resume("evt-manual-missing-intent")
    assert resume_calls == []
    assert scheduled == []
