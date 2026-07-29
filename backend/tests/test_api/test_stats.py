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


@pytest.mark.asyncio
async def test_stats_partial_success_counts_as_execution_failure(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """PARTIAL_SUCCESS enters the execution denominator but not the numerator."""
    eid = await _seed_event(session_factory, title="partial-success")
    await _seed_action(
        session_factory,
        event_id=eid,
        status=ActionStatus.PARTIAL_SUCCESS,
        effect_verification_status=None,
        writeback_required=False,
    )

    body = client.get("/api/v1/stats", headers=_hdr()).json()
    aes = body["action_execution_success_rate"]
    assert aes["numerator"] == 0
    assert aes["denominator"] == 1
    assert aes["rate"] == pytest.approx(0.0)


@pytest.mark.asyncio
async def test_stats_db_unavailable_returns_dependency_error(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DB wiring / aggregation failure → 503 dependency_unavailable (not fake zeros)."""
    import app.api.v1.stats as stats_mod

    monkeypatch.setattr(stats_mod, "_try_get_session_factory", lambda: None)

    resp = client.get("/api/v1/stats", headers=_hdr())
    assert resp.status_code == 503
    body = resp.json()
    assert body["error_code"] == "dependency_unavailable"
    assert body.get("total_events") is None or "total_events" not in body


@pytest.mark.asyncio
async def test_stats_aggregation_error_returns_dependency_error(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """SQLAlchemy failures surface as 503, not an empty successful payload."""
    from sqlalchemy.exc import OperationalError

    import app.api.v1.stats as stats_mod

    async def _boom(_session: object) -> object:
        raise OperationalError("stmt", {}, Exception("db down"))

    monkeypatch.setattr(stats_mod, "_try_get_session_factory", lambda: session_factory)
    monkeypatch.setattr(stats_mod, "_aggregate_stats", _boom)

    resp = client.get("/api/v1/stats", headers=_hdr())
    assert resp.status_code == 503
    assert resp.json()["error_code"] == "dependency_unavailable"


@pytest.mark.asyncio
async def test_stats_effect_rate_after_verify_persist_helper(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """VerifyAgent denormalize helper → effect_verification_rate becomes non-null."""
    from app.agents.verify_agent import VerifyAgent
    from app.models.agent_io import EffectStatus, VerificationActionResult, VerificationPhase

    eid = await _seed_event(session_factory, title="verify-persist")
    aid = await _seed_action(
        session_factory,
        event_id=eid,
        status=ActionStatus.SUCCESS,
        effect_verification_status=None,
        writeback_required=False,
    )

    agent = VerifyAgent(session_factory=session_factory)
    await agent._persist_effect_verification_statuses(
        [
            VerificationActionResult(
                action_id=aid,
                effect_status=EffectStatus.VERIFIED,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                writeback_status=None,
                writeback_ids=[],
                detail="effect_ok",
                verification_phase=VerificationPhase.EFFECT,
            )
        ]
    )

    body = client.get("/api/v1/stats", headers=_hdr()).json()
    efr = body["effect_verification_rate"]
    assert efr["numerator"] == 1
    assert efr["denominator"] == 1
    assert efr["rate"] == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_persist_effect_status_ignores_disposition_phase(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Phase-2 disposition VERIFIED must not overwrite phase-1 effect failure."""
    from app.agents.verify_agent import VerifyAgent
    from app.models.agent_io import EffectStatus, VerificationActionResult, VerificationPhase

    eid = await _seed_event(session_factory, title="phase2-no-overwrite")
    aid = await _seed_action(
        session_factory,
        event_id=eid,
        status=ActionStatus.SUCCESS,
        effect_verification_status=None,
        writeback_required=True,
        writeback_status=WritebackStatus.CONFIRMED.value,
    )

    agent = VerifyAgent(session_factory=session_factory)
    await agent._persist_effect_verification_statuses(
        [
            VerificationActionResult(
                action_id=aid,
                effect_status=EffectStatus.FAILED,
                writeback_required=True,
                writeback_readiness=WritebackReadiness.READY,
                writeback_status=WritebackStatus.CONFIRMED,
                writeback_ids=[],
                detail="effect_failed",
                verification_phase=VerificationPhase.EFFECT,
            ),
            # Mimics phase-2 writeback receipt confirmed — must be ignored.
            VerificationActionResult(
                action_id=aid,
                effect_status=EffectStatus.VERIFIED,
                writeback_required=True,
                writeback_readiness=WritebackReadiness.READY,
                writeback_status=WritebackStatus.CONFIRMED,
                writeback_ids=[f"wbk-{_sfx()}"],
                detail="writeback_confirmed",
                verification_phase=VerificationPhase.DISPOSITION,
            ),
        ]
    )

    body = client.get("/api/v1/stats", headers=_hdr()).json()

    efr = body["effect_verification_rate"]
    assert efr["numerator"] == 0
    assert efr["denominator"] == 1
    assert efr["rate"] == pytest.approx(0.0)

    wbr = body["writeback_confirmation_rate"]
    assert wbr["numerator"] == 1
    assert wbr["denominator"] == 1
    assert wbr["rate"] == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_stats_unverifiable_enters_effect_denominator(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """UNVERIFIABLE stays in the effect denominator so outages do not inflate the rate."""
    eid = await _seed_event(session_factory, title="effect-unverifiable")
    await _seed_action(
        session_factory,
        event_id=eid,
        status=ActionStatus.SUCCESS,
        effect_verification_status="unverifiable",
        writeback_required=False,
    )
    eid2 = await _seed_event(session_factory, title="effect-verified")
    await _seed_action(
        session_factory,
        event_id=eid2,
        status=ActionStatus.SUCCESS,
        effect_verification_status="verified",
        writeback_required=False,
    )

    body = client.get("/api/v1/stats", headers=_hdr()).json()
    efr = body["effect_verification_rate"]
    assert efr["numerator"] == 1
    assert efr["denominator"] == 2
    assert efr["rate"] == pytest.approx(0.5)
