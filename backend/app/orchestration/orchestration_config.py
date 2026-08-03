"""Orchestration mode startup gates (ISSUE-054)."""

from __future__ import annotations

from app.core.config import Settings, get_settings
from app.core.errors import ConfigurationError
from app.services.analysis_only_pipeline import assert_analysis_only_mode


def assert_graph_orchestration_config(settings: Settings | None = None) -> None:
    """Validate SuperAgent / graph-mode configuration at startup."""
    cfg = settings or get_settings()
    if cfg.react_enabled:
        raise ConfigurationError(
            "REACT_ENABLED=true requires ReadOnlyReActExecutor wiring (ISSUE-053)",
            error_code="configuration_error",
            details={"react_enabled": True},
        )


def assert_shadow_pivot_config(settings: Settings | None = None) -> None:
    """Validate shadow query pivot prerequisites at startup (#641 Phase A)."""
    cfg = settings or get_settings()
    if not cfg.react_shadow_pivot_enabled:
        return
    if not cfg.tool_call_grant_required:
        raise ConfigurationError(
            "REACT_SHADOW_PIVOT_ENABLED=true requires TOOL_CALL_GRANT_REQUIRED=true",
            error_code="configuration_error",
            details={"react_shadow_pivot_enabled": True},
        )


def assert_orchestration_mode(settings: Settings | None = None) -> None:
    """Apply the env gate for the active orchestration mode."""
    cfg = settings or get_settings()
    assert_shadow_pivot_config(cfg)
    mode = (cfg.orchestration_mode or "graph").strip().lower()
    if mode == "analysis_only":
        assert_analysis_only_mode(cfg)
    elif mode == "graph":
        assert_graph_orchestration_config(cfg)
    else:
        raise ConfigurationError(
            f"unsupported ORCHESTRATION_MODE: {cfg.orchestration_mode!r}",
            error_code="configuration_error",
            details={"orchestration_mode": cfg.orchestration_mode},
        )


__all__ = [
    "assert_graph_orchestration_config",
    "assert_orchestration_mode",
    "assert_shadow_pivot_config",
]
