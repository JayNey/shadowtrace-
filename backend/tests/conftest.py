"""Root pytest hooks for ShadowTrace backend tests.

ISSUE-025 tool-system fixtures are defined in
``tests.test_tools.tool_system_fixtures`` and registered once here so both
``tests/test_tools/`` and ``tests/integration/test_tool_system.py`` can use
them without double-loading ``tests/test_tools/conftest.py`` as a plugin.

ISSUE-055 orchestration fixtures follow the same pattern via
``tests.test_orchestration.orchestration_fixtures``.

ISSUE-016 ingestion fixtures (PostgreSQL/Redis) are registered via
``tests.test_ingestion.ingestion_fixtures`` so intent/auto-investigate tests can
reuse them without nested ``pytest_plugins`` declarations. Ingestion uses
``ingestion_event_service`` / ``ingestion_source_ingester`` (no state machine);
integration/system owners are ``event_service`` and ``source_ingester`` in
``tests.integration.integration_fixtures``.

Plugin order matters: ``ingestion_fixtures`` loads after ``integration_fixtures``,
so shared names like ``session_factory`` and ``redis_client`` resolve to the
ingestion module when both define them. Do **not** reintroduce production-wiring
fixture names (``event_service``, ``source_ingester``) under ingestion plugins.
"""

from __future__ import annotations

import os
import random
from typing import Any

pytest_plugins = [
    "tests.test_tools.tool_system_fixtures",
    "tests.test_orchestration.orchestration_fixtures",
    "tests.test_support.db_isolation",
    "tests.integration.integration_fixtures",
    "tests.test_ingestion.ingestion_fixtures",
]


def pytest_collection_modifyitems(config: Any, items: list[Any]) -> None:
    """Optional deterministic shuffle for ISSUE-267 random-order retests."""
    del config
    seed = os.environ.get("SHADOWTRACE_TEST_SHUFFLE_SEED")
    if seed is None or seed == "":
        return
    rng = random.Random(seed)
    rng.shuffle(items)
