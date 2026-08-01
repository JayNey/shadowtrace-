"""Root pytest hooks for ShadowTrace backend tests.

ISSUE-025 tool-system fixtures are defined in
``tests.test_tools.tool_system_fixtures`` and registered once here so both
``tests/test_tools/`` and ``tests/integration/test_tool_system.py`` can use
them without double-loading ``tests/test_tools/conftest.py`` as a plugin.

ISSUE-055 orchestration fixtures follow the same pattern via
``tests.test_orchestration.orchestration_fixtures``.

ISSUE-016 ingestion fixtures (PostgreSQL/Redis) are registered via
``tests.test_ingestion.conftest`` so intent/auto-investigate tests can reuse
them without nested ``pytest_plugins`` declarations.
"""

pytest_plugins = [
    "tests.test_tools.tool_system_fixtures",
    "tests.test_orchestration.orchestration_fixtures",
    "tests.integration.integration_fixtures",
    "tests.test_ingestion.conftest",
]
