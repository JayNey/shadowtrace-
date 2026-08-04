"""Budget/reservation Redis degraded sticky recovery tests (ISSUE-174 / #700)."""

from __future__ import annotations

from typing import Any

import pytest

from app.core.config import Settings
from app.core.metrics import budget_redis_health_snapshot, reset_budget_redis_metrics_for_tests
from app.models.tool_call_grant import ToolCallMode
from app.models.workflow import EVENT_TOKEN_BUDGET, GLOBAL_TOKEN_BUDGET
from app.services.budget_service import (
    EVENT_BUDGET_KEY_PREFIX,
    SYSTEM_BUDGET_KEY,
    BudgetService,
)
from app.services.tool_call_budget_reservation import ToolCallBudgetReservationService


class _FakePipeline:
    def __init__(self, store: _FakeRedisStore) -> None:
        self._store = store
        self._ops: list[tuple[str, ...]] = []

    def incrby(self, key: str, amount: int) -> None:
        self._ops.append(("incrby", key, amount))

    def hincrby(self, key: str, field: str, amount: int) -> None:
        self._ops.append(("hincrby", key, field, amount))

    def hincrbyfloat(self, key: str, field: str, amount: float) -> None:
        self._ops.append(("hincrbyfloat", key, field, amount))

    async def execute(self) -> None:
        if self._store.fail_execute:
            raise ConnectionError("redis pipeline failed")
        for op in self._ops:
            if op[0] == "incrby":
                _, key, amount = op
                self._store.strings[key] = int(self._store.strings.get(key, 0)) + int(amount)
            elif op[0] == "hincrby":
                _, key, field, amount = op
                bucket = self._store.hashes.setdefault(key, {})
                bucket[field] = int(bucket.get(field, 0)) + int(amount)
            elif op[0] == "hincrbyfloat":
                _, key, field, amount = op
                bucket = self._store.hashes.setdefault(key, {})
                bucket[field] = float(bucket.get(field, 0)) + float(amount)


class _FakeRedisStore:
    def __init__(self) -> None:
        self.strings: dict[str, int | str] = {}
        self.hashes: dict[str, dict[str, int | float]] = {}
        self.fail_execute = False
        self.eval_calls = 0

    def pipeline(self) -> _FakePipeline:
        return _FakePipeline(self)

    async def hgetall(self, key: str) -> dict[str, str]:
        raw = self.hashes.get(key, {})
        return {field: str(value) for field, value in raw.items()}

    async def get(self, key: str) -> str | None:
        value = self.strings.get(key)
        return None if value is None else str(value)

    async def delete(self, key: str) -> None:
        self.hashes.pop(key, None)
        self.strings.pop(key, None)

    async def eval(self, _script: str, _num_keys: int, key: str, limit: str) -> int:
        self.eval_calls += 1
        if self.fail_execute:
            raise ConnectionError("redis eval failed")
        current = int(self.strings.get(key, 0))
        max_calls = int(limit)
        if current >= max_calls:
            return -1
        next_value = current + 1
        self.strings[key] = next_value
        return next_value


class _FakeBudgetRedisClient:
    def __init__(self) -> None:
        self.available = True
        self.store = _FakeRedisStore()

    async def ping(self) -> bool:
        return self.available

    def get_client(self) -> _FakeRedisStore:
        return self.store


def _budget_settings(**overrides: Any) -> Settings:
    base = {
        "budget_enabled": True,
        "global_token_budget": GLOBAL_TOKEN_BUDGET,
        "event_token_budget": EVENT_TOKEN_BUDGET,
        "event_cost_budget_usd": 5.0,
        "per_agent_token_cap": 50_000,
        "llm_mode": "mock",
        "app_env": "development",
    }
    base.update(overrides)
    return Settings.model_validate(base)


@pytest.fixture(autouse=True)
def _reset_budget_metrics() -> None:
    reset_budget_redis_metrics_for_tests()
    yield
    reset_budget_redis_metrics_for_tests()


@pytest.mark.asyncio
async def test_budget_redis_failure_degrades_then_recovers_for_new_event() -> None:
    redis = _FakeBudgetRedisClient()
    service = BudgetService(
        redis=redis,  # type: ignore[arg-type]
        settings=_budget_settings(),
        attempt_redis_recovery=True,
        recovery_interval_seconds=0.0,
    )

    redis.store.fail_execute = True
    await service.charge_llm(
        "evt-degraded",
        "TriageAgent",
        "mock-model",
        prompt_tokens=100,
        completion_tokens=0,
    )
    assert service._redis_degraded is True
    degraded_usage = await service.get_usage("evt-degraded")
    assert degraded_usage.event_tokens == 100
    assert budget_redis_health_snapshot()["budget_redis_degraded"] is True

    redis.store.fail_execute = False
    await service.charge_llm(
        "evt-recovered",
        "TriageAgent",
        "mock-model",
        prompt_tokens=50,
        completion_tokens=0,
    )
    assert service._redis_degraded is False
    assert budget_redis_health_snapshot()["budget_redis_degraded"] is False

    recovered_usage = await service.get_usage("evt-recovered")
    assert recovered_usage.event_tokens == 50
    event_key = f"{EVENT_BUDGET_KEY_PREFIX}evt-recovered"
    assert redis.store.hashes[event_key]["tokens"] == 50
    assert redis.store.strings[SYSTEM_BUDGET_KEY] == 50


@pytest.mark.asyncio
async def test_budget_pinned_event_stays_on_memory_after_recovery() -> None:
    redis = _FakeBudgetRedisClient()
    service = BudgetService(
        redis=redis,  # type: ignore[arg-type]
        settings=_budget_settings(),
        attempt_redis_recovery=True,
        recovery_interval_seconds=0.0,
    )

    redis.store.fail_execute = True
    await service.charge_llm(
        "evt-pinned",
        "EvidenceAgent",
        "mock-model",
        prompt_tokens=80,
        completion_tokens=0,
    )
    assert "evt-pinned" in service._memory_pinned_events

    redis.store.fail_execute = False
    await service.charge_llm(
        "evt-new",
        "EvidenceAgent",
        "mock-model",
        prompt_tokens=20,
        completion_tokens=0,
    )
    assert service._redis_degraded is False

    await service.charge_llm(
        "evt-pinned",
        "EvidenceAgent",
        "mock-model",
        prompt_tokens=10,
        completion_tokens=0,
    )
    pinned_usage = await service.get_usage("evt-pinned")
    assert pinned_usage.event_tokens == 90
    pinned_key = f"{EVENT_BUDGET_KEY_PREFIX}evt-pinned"
    assert pinned_key not in redis.store.hashes


@pytest.mark.asyncio
async def test_budget_no_double_charge_on_pinned_event() -> None:
    redis = _FakeBudgetRedisClient()
    service = BudgetService(
        redis=redis,  # type: ignore[arg-type]
        settings=_budget_settings(),
        attempt_redis_recovery=True,
        recovery_interval_seconds=0.0,
    )

    redis.store.fail_execute = True
    await service.charge_llm(
        "evt-no-double",
        "RiskAgent",
        "mock-model",
        prompt_tokens=30,
        completion_tokens=0,
    )
    redis.store.fail_execute = False
    await service._maybe_attempt_redis_recovery()
    assert service._redis_degraded is False

    await service.charge_llm(
        "evt-no-double",
        "RiskAgent",
        "mock-model",
        prompt_tokens=20,
        completion_tokens=0,
    )
    usage = await service.get_usage("evt-no-double")
    assert usage.event_tokens == 50
    event_key = f"{EVENT_BUDGET_KEY_PREFIX}evt-no-double"
    assert event_key not in redis.store.hashes
    assert redis.store.strings.get(SYSTEM_BUDGET_KEY, 0) == 0


@pytest.mark.asyncio
async def test_reservation_redis_failure_degrades_then_recovers_for_new_grant() -> None:
    redis = _FakeBudgetRedisClient()
    service = ToolCallBudgetReservationService(
        redis=redis,
        attempt_redis_recovery=True,
        recovery_interval_seconds=0.0,
    )

    redis.store.fail_execute = True
    seq = await service.reserve(
        mode=ToolCallMode.PRODUCTION,
        namespace_key="production:evt-res",
        grant_id="tcg-degraded",
        max_calls=3,
    )
    assert seq == 1
    assert service._redis_degraded is True
    assert budget_redis_health_snapshot()["reservation_redis_degraded"] is True

    redis.store.fail_execute = False
    redis.store.eval_calls = 0
    seq_new = await service.reserve(
        mode=ToolCallMode.PRODUCTION,
        namespace_key="production:evt-res",
        grant_id="tcg-recovered",
        max_calls=3,
    )
    assert seq_new == 1
    assert service._redis_degraded is False
    assert redis.store.eval_calls == 1


@pytest.mark.asyncio
async def test_reservation_pinned_grant_stays_on_memory_after_recovery() -> None:
    redis = _FakeBudgetRedisClient()
    service = ToolCallBudgetReservationService(
        redis=redis,
        attempt_redis_recovery=True,
        recovery_interval_seconds=0.0,
    )

    redis.store.fail_execute = True
    await service.reserve(
        mode=ToolCallMode.PRODUCTION,
        namespace_key="production:evt-pin",
        grant_id="tcg-pinned",
        max_calls=3,
    )
    redis.store.fail_execute = False
    redis.store.eval_calls = 0
    await service.reserve(
        mode=ToolCallMode.PRODUCTION,
        namespace_key="production:evt-pin",
        grant_id="tcg-new",
        max_calls=3,
    )

    await service.reserve(
        mode=ToolCallMode.PRODUCTION,
        namespace_key="production:evt-pin",
        grant_id="tcg-pinned",
        max_calls=3,
    )
    pinned_count = await service.get_reserved_count(
        mode=ToolCallMode.PRODUCTION,
        namespace_key="production:evt-pin",
        grant_id="tcg-pinned",
    )
    assert pinned_count == 2
    assert redis.store.eval_calls == 1
