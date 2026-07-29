"""Stats API tests (ISSUE-085).

Constructs three orthogonal disposition scenarios and asserts the three rates
stay separate — never fold into a single ``action_success_rate``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import reset_deps
from app.db import models as orm
from app.main import app
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionStatus,
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
    WritebackStatus,
)

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_state")]

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
        "admin-token": {"subject": "admin-1", "roles": ["admin"]},
    }
)


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "false")
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "false")
    monkeypatch.setenv("LLM_MODE", "mock")
    monkeypatch.setenv("TOOL_MODE", "mock")
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("DISPOSITION_MODE", "mock_xdr")
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_services() -> None:
    reset_deps()
    app.dependency_overrides.clear()
    yield
    reset_deps()
    app.dependency_overrides.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _hdr(role: str = "analyst") -> dict[str, str]:
    return {"Authorization": f"Bearer {role}-token"}


def _sfx() -> str:
    return uuid4().hex[:8]


async def _seed_event(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str | None = None,
    status: EventStatus = EventStatus.NEW,
    severity: Severity = Severity.HIGH,
    event_type: EventType = EventType.INSIDER_THREAT,
    disposition_policy: DispositionPolicy = DispositionPolicy.REQUIRED,
    created_at: datetime | None = None,
    closed_at: datetime | None = None,
    title: str = "Stats fixture event",
) -> str:
    eid = event_id or f"evt-{_sfx()}"
    now = created_at or datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=eid,
                    event_type=event_type.value,
                    title=title,
                    description="ISSUE-085 stats fixture",
                    status=status.value,
                    severity=severity.value,
                    final_verdict=FinalVerdict.NONE.value,
                    risk_score=70,
                    entities={},
                    creation_source_ref={
                        "source_kind": "incident",
                        "source_product": "mock_xdr",
                        "source_tenant_id": "t1",
                        "connector_id": f"conn-{_sfx()}",
                        "source_object_id": f"INC-{_sfx()}",
                        "raw_payload_hash": hashlib.sha256(eid.encode()).hexdigest(),
                        "ingested_at": now.isoformat(),
                    },
                    source_reference_snapshots=[],
                    disposition_policy=disposition_policy.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    created_at=now,
                    updated_at=now,
                    closed_at=closed_at,
                    row_version=1,
                )
            )
    return eid


async def _seed_action(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    status: ActionStatus = ActionStatus.SUCCESS,
    effect_verification_status: str | None = None,
    writeback_required: bool = False,
    writeback_status: str | None = None,
    action_id: str | None = None,
) -> str:
    aid = action_id or f"act-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=aid,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{aid}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block_ip",
                    tool_name="block_ip",
                    action_level="l2",
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    target_type="ip",
                    target="203.0.113.10",
                    parameters={"ip": "203.0.113.10"},
                    status=status.value,
                    auto_execute=True,
                    reason="stats fixture",
                    writeback_required=writeback_required,
                    writeback_applicable=writeback_required,
                    writeback_readiness=(
                        WritebackReadiness.READY.value
                        if writeback_required
                        else WritebackReadiness.NOT_REQUIRED.value
                    ),
                    writeback_status=writeback_status,
                    effect_verification_status=effect_verification_status,
                    executed_at=datetime.now(UTC),
                )
            )
    return aid


# --------------------------------------------------------------------------- #
# Three orthogonal scenarios (ISSUE-085 step 4)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_stats_action_success_effect_failed(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Action SUCCESS + effect failed → execution rate 1/1, effect 0/1, wb null."""
    eid = await _seed_event(session_factory, title="action-ok-effect-fail")
    await _seed_action(
        session_factory,
        event_id=eid,
        status=ActionStatus.SUCCESS,
        effect_verification_status="failed",
        writeback_required=False,
        writeback_status=None,
    )

    resp = client.get("/api/v1/stats", headers=_hdr())
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert "action_success_rate" not in body

    aes = body["action_execution_success_rate"]
    assert aes["numerator"] == 1
    assert aes["denominator"] == 1
    assert aes["rate"] == pytest.approx(1.0)

    efr = body["effect_verification_rate"]
    assert efr["numerator"] == 0
    assert efr["denominator"] == 1
    assert efr["rate"] == pytest.approx(0.0)

    wbr = body["writeback_confirmation_rate"]
    assert wbr["numerator"] == 0
    assert wbr["denominator"] == 0
    assert wbr["rate"] is None


@pytest.mark.asyncio
async def test_stats_effect_success_writeback_failed(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Effect verified + writeback failed → rates 1/1, 1/1, 0/1."""
    eid = await _seed_event(session_factory, title="effect-ok-wb-fail")
    await _seed_action(
        session_factory,
        event_id=eid,
        status=ActionStatus.SUCCESS,
        effect_verification_status="verified",
        writeback_required=True,
        writeback_status=WritebackStatus.FAILED.value,
    )

    body = client.get("/api/v1/stats", headers=_hdr()).json()

    assert "action_success_rate" not in body

    aes = body["action_execution_success_rate"]
    assert aes["numerator"] == 1 and aes["denominator"] == 1
    assert aes["rate"] == pytest.approx(1.0)

    efr = body["effect_verification_rate"]
    assert efr["numerator"] == 1 and efr["denominator"] == 1
    assert efr["rate"] == pytest.approx(1.0)

    wbr = body["writeback_confirmation_rate"]
    assert wbr["numerator"] == 0 and wbr["denominator"] == 1
    assert wbr["rate"] == pytest.approx(0.0)


@pytest.mark.asyncio
async def test_stats_all_success(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """All three paths succeed → rates 1/1 each; not_required excluded from wb den."""
    eid = await _seed_event(session_factory, title="all-success")
    await _seed_action(
        session_factory,
        event_id=eid,
        status=ActionStatus.SUCCESS,
        effect_verification_status="verified",
        writeback_required=True,
        writeback_status=WritebackStatus.CONFIRMED.value,
    )
    # not_required writeback must NOT enter the writeback denominator.
    eid2 = await _seed_event(
        session_factory,
        title="not-required-wb",
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )
    await _seed_action(
        session_factory,
        event_id=eid2,
        status=ActionStatus.SUCCESS,
        effect_verification_status="verified",
        writeback_required=False,
        writeback_status=None,
    )

    body = client.get("/api/v1/stats", headers=_hdr()).json()

    assert "action_success_rate" not in body

    aes = body["action_execution_success_rate"]
    assert aes["numerator"] == 2 and aes["denominator"] == 2
    assert aes["rate"] == pytest.approx(1.0)

    efr = body["effect_verification_rate"]
    assert efr["numerator"] == 2 and efr["denominator"] == 2
    assert efr["rate"] == pytest.approx(1.0)

    wbr = body["writeback_confirmation_rate"]
    assert wbr["numerator"] == 1 and wbr["denominator"] == 1
    assert wbr["rate"] == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_stats_event_distributions_match_db(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Demo-like ingest: dashboard counts match seeded rows."""
    now = datetime.now(UTC)
    await _seed_event(
        session_factory,
        status=EventStatus.NEW,
        severity=Severity.CRITICAL,
        event_type=EventType.DATA_EXFILTRATION,
        created_at=now - timedelta(hours=1),
    )
    await _seed_event(
        session_factory,
        status=EventStatus.CLOSED,
        severity=Severity.HIGH,
        event_type=EventType.HOST_COMPROMISE,
        created_at=now - timedelta(hours=2),
        closed_at=now - timedelta(hours=1),
    )
    await _seed_event(
        session_factory,
        status=EventStatus.ANALYZING,
        severity=Severity.LOW,
        event_type=EventType.ACCOUNT_ANOMALY,
        created_at=now - timedelta(hours=3),
    )

    body = client.get("/api/v1/stats", headers=_hdr()).json()

    assert body["total_events"] == 3
    assert body["by_status"]["new"] == 1
    assert body["by_status"]["closed"] == 1
    assert body["by_status"]["analyzing"] == 1
    assert body["by_severity"]["critical"] == 1
    assert body["by_severity"]["high"] == 1
    assert body["by_severity"]["low"] == 1
    assert body["by_event_type"]["data_exfiltration"] == 1
    assert body["by_event_type"]["host_compromise"] == 1
    assert body["by_event_type"]["account_anomaly"] == 1
    assert body["open_events"] == 2
    assert body["closed_events"] == 1
    assert body["avg_investigation_seconds"] == pytest.approx(3600.0, rel=0.05)
    assert isinstance(body["events_last_24h"], list)
    assert sum(bucket["count"] for bucket in body["events_last_24h"]) == 3


@pytest.mark.asyncio
async def test_stats_empty_rates_are_null(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Zero denominator → rate null (not 0)."""
    _ = session_factory  # clean_state ensures empty tables
    body = client.get("/api/v1/stats", headers=_hdr()).json()
    assert body["total_events"] == 0
    for key in (
        "action_execution_success_rate",
        "effect_verification_rate",
        "writeback_confirmation_rate",
    ):
        assert body[key]["rate"] is None
        assert body[key]["numerator"] == 0
        assert body[key]["denominator"] == 0
    assert body["avg_investigation_seconds"] is None
