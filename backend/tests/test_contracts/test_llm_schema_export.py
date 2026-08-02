"""LLM contract schema export tests (ISSUE-106 / #609)."""

from __future__ import annotations

from app.models import MODEL_REGISTRY
from app.models.llm_provider import LLMProviderHealth


def test_llm_contract_models_are_registered() -> None:
    expected = {
        "LLMProviderHealth",
        "LLMProbeStatus",
        "LLMCallLogAggregate",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


def test_llm_provider_health_schema_has_sanitized_fields() -> None:
    schema = LLMProviderHealth.model_json_schema(mode="serialization")
    props = schema.get("properties", {})
    assert "base_url_redacted" in props
    assert "api_key" not in props
