"""AttackPathService tests (ISSUE-083).

``NEO4J_ENABLED=false`` tests run in the normal suite (no Neo4j required).
Neo4j integration tests are gated behind ``@pytest.mark.neo4j``.

Run (disabled path, always safe):
    pytest tests/test_services/test_attack_path.py -v

Run (Neo4j required):
    docker compose --profile optional up -d neo4j
    NEO4J_ENABLED=true \\
        NEO4J_URI=bolt://localhost:7687 \\
        pytest tests/test_services/test_attack_path.py -m neo4j -v
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.neo4j_client import Neo4jClient
from app.db import models as orm
from app.db.orm.graph import GraphEdgeORM, GraphNodeORM
from app.models.agent_io import CrossEventPath
from app.services.attack_path_service import AttackPathService
from app.services.graph_sync_service import GraphSyncService

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace"

# Shared outbound IP used by the two-event Neo4j fixture.
SHARED_EXTERNAL_IP = "198.51.100.77"


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _neo4j_required() -> None:
    if os.environ.get("NEO4J_ENABLED", "").strip().lower() != "true":
        pytest.skip("NEO4J_ENABLED not set to 'true'")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def migrated() -> None:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)

    async def _probe() -> None:
        async with engine.connect() as conn:
            await conn.execute(select(1))

    import asyncio

    try:
        asyncio.run(_probe())
        command.upgrade(_alembic_config(), "head")
        asyncio.run(engine.dispose())
    except Exception as exc:  # noqa: BLE001
        try:
            asyncio.run(engine.dispose())
        except Exception:  # noqa: BLE001
            pass
        pytest.skip(f"PostgreSQL not reachable: {exc}")


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(select(1))
    except Exception as exc:  # noqa: BLE001
        await engine.dispose()
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def cleanup(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    yield
    async with session_factory() as session:
        async with session.begin():
            for table in (
                orm.EventAuditLog,
                orm.ActionTargetResult,
                orm.ActionExecutionJob,
                orm.DispositionReceipt,
                orm.DispositionOutbox,
                orm.Action,
                orm.Evidence,
                orm.Report,
                orm.SourceEventLink,
                orm.SourceObject,
                orm.SourceConnector,
                orm.SecurityEvent,
                GraphEdgeORM,
                GraphNodeORM,
            ):
                await session.execute(delete(table))


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


async def _seed_event(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    title: str = "test-attack-path",
) -> str:
    from app.models.enums import EventStatus, EventType, Severity
    from app.models.ids import new_event_id

    eid = new_event_id(identity=f"test-attack-path:{_sfx()}", occurred_at=_utc_now())
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=eid,
                    title=title,
                    event_type=EventType.INSIDER_THREAT.value,
                    severity=Severity.MEDIUM.value,
                    status=EventStatus.VERIFYING.value,
                    occurred_at=_utc_now(),
                    creation_source_ref={
                        "source_product": "mock_xdr",
                        "source_tenant_id": "tenant-test",
                    },
                )
            )
            await session.flush()
    return eid


async def _seed_event_graph_with_ip(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    host_value: str,
    ip_value: str,
    account_value: str | None = None,
) -> dict[str, str]:
    """Minimal host → IP graph; optional account for lateral-movement tests."""
    host_id = f"node-{_sfx()}"
    ip_id = f"node-{_sfx()}"
    edge_id = f"edge-{_sfx()}"
    account_id = f"node-{_sfx()}" if account_value else ""

    async with session_factory() as session:
        async with session.begin():
            session.add(
                GraphNodeORM(
                    node_id=host_id,
                    event_id=event_id,
                    entity_type="host",
                    entity_value=host_value,
                    properties={},
                )
            )
            session.add(
                GraphNodeORM(
                    node_id=ip_id,
                    event_id=event_id,
                    entity_type="ip",
                    entity_value=ip_value,
                    properties={"direction": "outbound"},
                )
            )
            session.add(
                GraphEdgeORM(
                    edge_id=edge_id,
                    event_id=event_id,
                    source_node_id=host_id,
                    target_node_id=ip_id,
                    relation_type="connected_to",
                    evidence_id=f"ev-{_sfx()}",
                    occurred_at=_utc_now(),
                )
            )
            if account_value:
                session.add(
                    GraphNodeORM(
                        node_id=account_id,
                        event_id=event_id,
                        entity_type="account",
                        entity_value=account_value,
                        properties={},
                    )
                )
                session.add(
                    GraphEdgeORM(
                        edge_id=f"edge-{_sfx()}",
                        event_id=event_id,
                        source_node_id=account_id,
                        target_node_id=host_id,
                        relation_type="logged_in_from",
                        evidence_id=f"ev-{_sfx()}",
                        occurred_at=_utc_now(),
                    )
                )
            await session.flush()
    return {"host": host_id, "ip": ip_id, "account": account_id, "edge": edge_id}


# ---------------------------------------------------------------------------
# Disabled-path tests (always run)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cross_event_paths_empty_when_neo4j_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NEO4J_ENABLED=false → find_cross_event_paths always returns []."""
    monkeypatch.setenv("NEO4J_ENABLED", "false")
    from app.core.config import get_settings

    get_settings.cache_clear()

    svc = AttackPathService(client=None)
    paths = await svc.find_cross_event_paths("evt-any")
    assert paths == []

    hops = await svc.find_lateral_movement("svc@example.test")
    assert hops == []

    get_settings.cache_clear()


def test_cross_event_path_model_fields() -> None:
    path = CrossEventPath(
        path_id="cep-abc",
        related_event_ids=["evt-b"],
        shared_entities=[SHARED_EXTERNAL_IP],
        path_nodes=["node-a", "node-b"],
        risk_hint="shared_external_ip",
    )
    assert path.shared_entities == [SHARED_EXTERNAL_IP]
    assert path.related_event_ids == ["evt-b"]


class _FakeNeo4jClient:
    """Minimal Neo4jClient stand-in for disabled-path / failure-path unit tests."""

    def __init__(
        self,
        *,
        ping_ok: bool = True,
        records: list[dict[str, object]] | None = None,
        raise_on_cypher: Exception | None = None,
    ) -> None:
        self.ping_ok = ping_ok
        self.records = records or []
        self.raise_on_cypher = raise_on_cypher
        self.cypher_calls: list[tuple[str, dict[str, object]]] = []

    async def ping(self) -> bool:
        return self.ping_ok

    async def run_cypher(
        self,
        query: str,
        params: dict[str, object] | None = None,
    ) -> list[dict[str, object]]:
        self.cypher_calls.append((query, params or {}))
        if self.raise_on_cypher is not None:
            raise self.raise_on_cypher
        return list(self.records)

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_cross_event_paths_empty_when_ping_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEO4J_ENABLED", "true")
    from app.core.config import get_settings

    get_settings.cache_clear()
    client = _FakeNeo4jClient(ping_ok=False)
    svc = AttackPathService(client=cast(Neo4jClient, client))
    assert await svc.find_cross_event_paths("evt-any") == []
    assert client.cypher_calls == []
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_cross_event_paths_empty_when_cypher_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEO4J_ENABLED", "true")
    from app.core.config import get_settings

    get_settings.cache_clear()
    client = _FakeNeo4jClient(raise_on_cypher=RuntimeError("bolt down"))
    svc = AttackPathService(client=cast(Neo4jClient, client))
    assert await svc.find_cross_event_paths("evt-any") == []
    assert len(client.cypher_calls) == 1
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_cross_event_paths_cypher_failure_skips_pg_fallback(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neo4j query errors must not fall back to PostgreSQL (partial outage)."""
    monkeypatch.setenv("NEO4J_ENABLED", "true")
    from app.core.config import get_settings

    get_settings.cache_clear()

    event_a = await _seed_event(session_factory, title="cypher-fail-a")
    event_b = await _seed_event(session_factory, title="cypher-fail-b")
    await _seed_event_graph_with_ip(
        session_factory,
        event_a,
        host_value="host-cf-a.example.test",
        ip_value=SHARED_EXTERNAL_IP,
    )
    await _seed_event_graph_with_ip(
        session_factory,
        event_b,
        host_value="host-cf-b.example.test",
        ip_value=SHARED_EXTERNAL_IP,
    )

    client = _FakeNeo4jClient(raise_on_cypher=RuntimeError("bolt down"))
    svc = AttackPathService(
        client=cast(Neo4jClient, client),
        session_factory=session_factory,
    )
    assert await svc.find_cross_event_paths(event_a) == []
    assert len(client.cypher_calls) == 1
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_cross_event_paths_requires_matching_entity_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same entity_value with different entity_type must not form a path."""
    monkeypatch.setenv("NEO4J_ENABLED", "true")
    from app.core.config import get_settings

    get_settings.cache_clear()
    # Simulate Neo4j returning only type-matched rows (service query filters).
    # Empty records ⇒ no path; also assert query text requires entity_type equality.
    client = _FakeNeo4jClient(records=[])
    svc = AttackPathService(client=cast(Neo4jClient, client))
    assert await svc.find_cross_event_paths("evt-a") == []
    assert client.cypher_calls
    query, _params = client.cypher_calls[0]
    assert "entity_type: local.entity_type" in query
    assert "entity_value: local.entity_value" in query
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_cross_event_paths_pg_fallback_when_neo4j_empty(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PostgreSQL probe fills paths while Neo4j sync is still catching up."""
    monkeypatch.setenv("NEO4J_ENABLED", "true")
    from app.core.config import get_settings

    get_settings.cache_clear()

    event_a = await _seed_event(session_factory, title="pg-fallback-a")
    event_b = await _seed_event(session_factory, title="pg-fallback-b")
    await _seed_event_graph_with_ip(
        session_factory,
        event_a,
        host_value="host-pg-a.example.test",
        ip_value=SHARED_EXTERNAL_IP,
    )
    await _seed_event_graph_with_ip(
        session_factory,
        event_b,
        host_value="host-pg-b.example.test",
        ip_value=SHARED_EXTERNAL_IP,
    )

    client = _FakeNeo4jClient(records=[])
    svc = AttackPathService(
        client=cast(Neo4jClient, client),
        session_factory=session_factory,
    )
    paths = await svc.find_cross_event_paths(event_a)
    assert len(paths) >= 1
    matched = next((p for p in paths if event_b in p.related_event_ids), None)
    assert matched is not None
    assert SHARED_EXTERNAL_IP in matched.shared_entities
    assert matched.risk_hint == "shared_external_ip"
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Neo4j integration
# ---------------------------------------------------------------------------


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_shared_external_ip_discovers_cross_event_paths(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two events sharing an outbound IP discover each other via Neo4j."""
    _neo4j_required()
    monkeypatch.setenv("NEO4J_ENABLED", "true")
    from app.core.config import get_settings
    from app.core.neo4j_client import Neo4jClient

    get_settings.cache_clear()

    event_a = await _seed_event(session_factory, title="attack-path-a")
    event_b = await _seed_event(session_factory, title="attack-path-b")
    await _seed_event_graph_with_ip(
        session_factory,
        event_a,
        host_value="host-a.example.test",
        ip_value=SHARED_EXTERNAL_IP,
    )
    await _seed_event_graph_with_ip(
        session_factory,
        event_b,
        host_value="host-b.example.test",
        ip_value=SHARED_EXTERNAL_IP,
    )

    client = Neo4jClient()
    sync = GraphSyncService(session_factory, client=client)
    assert (await sync.sync_event_graph(event_a)).skipped is False
    assert (await sync.sync_event_graph(event_b)).skipped is False

    svc = AttackPathService(client=client)

    paths_a = await svc.find_cross_event_paths(event_a)
    assert len(paths_a) >= 1
    matched_a = next(
        (p for p in paths_a if event_b in p.related_event_ids),
        None,
    )
    assert matched_a is not None
    assert SHARED_EXTERNAL_IP in matched_a.shared_entities
    assert matched_a.related_event_ids == [event_b]
    assert matched_a.risk_hint == "shared_external_ip"
    assert matched_a.path_id.startswith("cep-")
    assert len(matched_a.path_nodes) >= 2

    paths_b = await svc.find_cross_event_paths(event_b)
    matched_b = next(
        (p for p in paths_b if event_a in p.related_event_ids),
        None,
    )
    assert matched_b is not None
    assert SHARED_EXTERNAL_IP in matched_b.shared_entities
    assert event_a in matched_b.related_event_ids

    await client.aclose()
    get_settings.cache_clear()


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_lateral_movement_across_hosts(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same account on two hosts yields a time-ordered lateral-movement trail."""
    _neo4j_required()
    monkeypatch.setenv("NEO4J_ENABLED", "true")
    from app.core.config import get_settings
    from app.core.neo4j_client import Neo4jClient

    get_settings.cache_clear()

    account = f"svc-lateral-{_sfx()}@example.test"
    event_a = await _seed_event(session_factory, title="lateral-a")
    event_b = await _seed_event(session_factory, title="lateral-b")
    await _seed_event_graph_with_ip(
        session_factory,
        event_a,
        host_value="workstation-a.example.test",
        ip_value="203.0.113.10",
        account_value=account,
    )
    await _seed_event_graph_with_ip(
        session_factory,
        event_b,
        host_value="workstation-b.example.test",
        ip_value="203.0.113.11",
        account_value=account,
    )

    client = Neo4jClient()
    sync = GraphSyncService(session_factory, client=client)
    await sync.sync_event_graph(event_a)
    await sync.sync_event_graph(event_b)

    svc = AttackPathService(client=client)
    hops = await svc.find_lateral_movement(account)
    assert len(hops) >= 2
    hosts = {h.host_value for h in hops}
    assert "workstation-a.example.test" in hosts
    assert "workstation-b.example.test" in hosts

    await client.aclose()
    get_settings.cache_clear()
