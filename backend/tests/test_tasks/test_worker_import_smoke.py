"""Celery worker import-graph smoke tests (ISSUE-236)."""

from __future__ import annotations

import sys
from collections.abc import Iterator

import pytest


def test_investigation_intent_tasks_import_without_circular_import() -> None:
    """Worker task modules must import before Celery child processes start."""
    from app.tasks import investigation_intent_tasks

    assert investigation_intent_tasks.dispatch_pending_investigation_intents is not None


def test_agents_public_exports_remain_available() -> None:
    from app.agents import RiskAgent, SuperAgentInput, VerdictResolver

    assert RiskAgent.__name__ == "RiskAgent"
    assert SuperAgentInput.__name__ == "SuperAgentInput"
    assert VerdictResolver.__name__ == "VerdictResolver"


@pytest.fixture
def _fresh_agents_package_exports() -> Iterator[None]:
    """Drop cached lazy exports so prompt submodule loads observe package init."""
    import app.agents

    module = sys.modules["app.agents"]
    saved = {name: module.__dict__.get(name) for name in app.agents.__all__}
    for name in app.agents.__all__:
        module.__dict__.pop(name, None)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                module.__dict__.pop(name, None)
            else:
                module.__dict__[name] = value


def test_agents_prompt_submodule_does_not_eagerly_load_base_agent(
    _fresh_agents_package_exports: None,
) -> None:
    import app.agents

    from app.agents.prompts import event_qa_prompt  # noqa: F401

    assert "BaseAgent" not in app.agents.__dict__
