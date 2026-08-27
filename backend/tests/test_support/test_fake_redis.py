"""Unit tests for shared in-memory Redis fake (ISSUE-264)."""

from __future__ import annotations

import pytest

from app.orchestration.lease import DEFAULT_LEASE_TTL_S, EventLease, generate_owner_id
from tests.support.fake_redis import InMemoryFakeRedis, InMemoryFakeRedisClient


def _lease_with_fake(fake: InMemoryFakeRedis) -> EventLease:
    return EventLease(InMemoryFakeRedisClient(fake))  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_set_nx_rejects_conflicting_owner() -> None:
    fake = InMemoryFakeRedis()
    lease = _lease_with_fake(fake)
    event_id = "evt-fake-nx-conflict"
    first_owner = generate_owner_id()
    second_owner = generate_owner_id()

    assert await lease.acquire(event_id, first_owner, ttl_s=60) is True
    assert await lease.acquire(event_id, second_owner, ttl_s=60) is False
    assert await lease.get_owner(event_id) == first_owner


@pytest.mark.asyncio
async def test_release_script_owner_mismatch() -> None:
    fake = InMemoryFakeRedis()
    lease = _lease_with_fake(fake)
    event_id = "evt-fake-release-mismatch"
    owner = generate_owner_id()
    other = generate_owner_id()

    assert await lease.acquire(event_id, owner, ttl_s=60) is True
    assert await lease.release(event_id, other) is False
    assert await lease.get_owner(event_id) == owner
    assert await lease.release(event_id, owner) is True


@pytest.mark.asyncio
async def test_set_nx_succeeds_after_ttl_expiry() -> None:
    now = [100.0]
    fake = InMemoryFakeRedis(clock=lambda: now[0])
    lease = _lease_with_fake(fake)
    event_id = "evt-fake-ttl-expiry"
    first_owner = generate_owner_id()
    second_owner = generate_owner_id()

    assert await lease.acquire(event_id, first_owner, ttl_s=10) is True
    now[0] += 9
    assert await lease.acquire(event_id, second_owner, ttl_s=10) is False
    now[0] += 1
    assert await lease.acquire(event_id, second_owner, ttl_s=10) is True
    assert await lease.get_owner(event_id) == second_owner


@pytest.mark.asyncio
async def test_renew_extends_fake_redis_lease_ttl() -> None:
    now = [200.0]
    fake = InMemoryFakeRedis(clock=lambda: now[0])
    lease = _lease_with_fake(fake)
    event_id = "evt-fake-ttl-renew"
    owner = generate_owner_id()

    assert await lease.acquire(event_id, owner, ttl_s=10) is True
    now[0] += 9
    assert await lease.renew(event_id, owner) is True
    now[0] += 2
    assert await lease.get_owner(event_id) == owner
    now[0] += DEFAULT_LEASE_TTL_S - 2
    assert await lease.get_owner(event_id) is None
    assert await lease.release(event_id, owner) is True


@pytest.mark.asyncio
async def test_renew_does_not_extend_foreign_lease_after_expiry() -> None:
    now = [300.0]
    fake = InMemoryFakeRedis(clock=lambda: now[0])
    lease = _lease_with_fake(fake)
    event_id = "evt-fake-ttl-renew-stolen"
    first_owner = generate_owner_id()
    second_owner = generate_owner_id()

    assert await lease.acquire(event_id, first_owner, ttl_s=10) is True
    now[0] += 10
    assert await lease.acquire(event_id, second_owner, ttl_s=10) is True
    assert await lease.renew(event_id, first_owner) is False
    assert await lease.get_owner(event_id) == second_owner
    now[0] += 9
    assert await lease.get_owner(event_id) == second_owner


@pytest.mark.asyncio
async def test_set_rejects_unsupported_options() -> None:
    fake = InMemoryFakeRedis()

    with pytest.raises(TypeError, match="unsupported.*px"):
        await fake.set("key", "value", nx=True, px=1000)


@pytest.mark.asyncio
async def test_lease_rejects_non_positive_ttl() -> None:
    from app.core.errors import ValidationError

    fake = InMemoryFakeRedis()
    lease = _lease_with_fake(fake)
    owner = generate_owner_id()
    with pytest.raises(ValidationError):
        await lease.acquire("evt-ttl", owner, ttl_s=0)
    with pytest.raises(ValidationError):
        await lease.renew("evt-ttl", owner, ttl_s=-1)


@pytest.mark.asyncio
async def test_acquire_writes_ttl_key_with_same_expiry() -> None:
    now = [400.0]
    fake = InMemoryFakeRedis(clock=lambda: now[0])
    lease = _lease_with_fake(fake)
    event_id = "evt-fake-acquire-ttl"
    owner = generate_owner_id()
    assert await lease.acquire(event_id, owner, ttl_s=10) is True
    ttl_key = f"shadowtrace:lease:event:{event_id}:ttl"
    assert await fake.get(ttl_key) == b"10"
    assert await fake.ttl(f"shadowtrace:lease:event:{event_id}") == 10
    now[0] += 10
    assert await fake.get(ttl_key) is None
    assert await lease.get_owner(event_id) is None


@pytest.mark.asyncio
async def test_fake_redis_renew_script_rejects_non_positive_ttl() -> None:
    fake = InMemoryFakeRedis()
    await fake.set("k", "owner-a", nx=True, ex=10)
    renew = fake.register_script('redis.call("EXPIRE", KEYS[1], ARGV[2])')
    assert await renew(keys=["k"], args=["owner-a", "0"]) == 0
    assert await fake.get("k") == b"owner-a"
