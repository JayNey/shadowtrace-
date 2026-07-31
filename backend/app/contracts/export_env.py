"""Deterministic environment for contract export (ISSUE-112).

OpenAPI route registration reads ``get_settings()`` at import time. Export and
drift-check jobs must pin feature flags so consecutive runs produce identical
artifacts regardless of developer ``.env`` files.
"""

from __future__ import annotations

import os
from typing import Final

# Only variables that change exported contracts belong here.
CONTRACT_EXPORT_ENV: Final[dict[str, str]] = {
    "APP_ENV": "development",
    "EVENT_CHAT_ENABLED": "true",
    "NEO4J_ENABLED": "false",
    "OPENSEARCH_ENABLED": "false",
}


def apply_contract_export_env(*, force: bool = True) -> None:
    """Pin contract-export environment variables before importing ``app.main``."""
    for key, value in CONTRACT_EXPORT_ENV.items():
        if force:
            os.environ[key] = value
        else:
            os.environ.setdefault(key, value)

    from app.core.config import get_settings

    get_settings.cache_clear()
