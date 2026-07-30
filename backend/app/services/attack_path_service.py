"""AttackPathService: Neo4j cross-event path discovery (ISSUE-083).

When ``NEO4J_ENABLED=false`` every method returns an empty list — no Neo4j
connection is attempted. Single-event PostgreSQL graphs are unaffected.

When Neo4j is enabled but async sync has not finished, results fall back to a
PostgreSQL shared-entity probe so ``GET /graph`` is not briefly empty. That
fallback applies only when Neo4j returns **zero rows** — never when the Cypher
query itself fails (partial Neo4j outage must not masquerade as cross-event data).

Community detection (Issue goal) is intentionally deferred; this service covers
cross-event shared-entity paths and lateral-movement hops only.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import cast

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import aliased

from app.core.config import get_settings
from app.core.neo4j_client import Neo4jClient
from app.db.orm.graph import GraphNodeORM
from app.models.agent_io import CrossEventPath

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cypher templates
# ---------------------------------------------------------------------------

# Shared entity across events. ``remote`` match uses indexed properties first.
_CROSS_EVENT_SHARED = """
MATCH (local {event_id: $event_id})
WHERE local.entity_value IS NOT NULL
WITH local
MATCH (remote {entity_type: local.entity_type, entity_value: local.entity_value})
WHERE remote.event_id <> $event_id
RETURN local.entity_value AS shared_value,
       local.entity_type AS entity_type,
       local.node_id AS local_node_id,
       remote.node_id AS remote_node_id,
       remote.event_id AS related_event_id
ORDER BY shared_value, related_event_id
"""

# Optional: expand from a local shared entity along intra-event edges up to
# max_depth to enrich path_nodes (best-effort; empty when isolated).
_LOCAL_NEIGHBORHOOD = """
MATCH (shared {{node_id: $node_id, event_id: $event_id}})
OPTIONAL MATCH p = (shared)-[*1..{max_depth}]-(neighbor {{event_id: $event_id}})
WITH shared, neighbor
WHERE neighbor IS NOT NULL AND neighbor.node_id <> shared.node_id
RETURN collect(DISTINCT neighbor.node_id)[0..8] AS neighbor_ids
"""

# Lateral movement: same account/process touching multiple hosts, time-ordered.
_LATERAL_MOVEMENT = """
MATCH (actor)
WHERE actor.entity_value = $entity_value
  AND actor.entity_type IN ['account', 'process']
MATCH (actor)-[r]-(host)
WHERE host.entity_type = 'host'
RETURN actor.node_id AS actor_node_id,
       actor.entity_type AS actor_type,
       actor.event_id AS event_id,
       host.node_id AS host_node_id,
       host.entity_value AS host_value,
       r.occurred_at AS occurred_at
ORDER BY coalesce(r.occurred_at, datetime('1970-01-01T00:00:00Z'))
"""


def _path_id(event_id: str, related_event_id: str, shared_value: str) -> str:
    digest = hashlib.sha256(f"{event_id}|{related_event_id}|{shared_value}".encode()).hexdigest()[
        :12
    ]
    return f"cep-{digest}"


def _risk_hint(entity_type: str | None) -> str:
    mapping = {
        "ip": "shared_external_ip",
        "domain": "shared_domain",
        "account": "shared_account",
        "host": "shared_host",
        "process": "shared_process",
        "file": "shared_file",
    }
    if entity_type is None:
        return "shared_entity"
    return mapping.get(entity_type, "shared_entity")


@dataclass(frozen=True)
class LateralMovementHop:
    """One hop of a lateral-movement trail (account/process × host)."""

    actor_node_id: str
    actor_type: str
    event_id: str
    host_node_id: str
    host_value: str
    occurred_at: object | None


class AttackPathService:
    """Discover cross-event associations and lateral-movement trails via Neo4j."""

    def __init__(
        self,
        *,
        client: Neo4jClient | None = None,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        self._client = client
        self._session_factory = session_factory
        self._enabled = get_settings().neo4j_enabled and client is not None

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def find_cross_event_paths(
        self,
        event_id: str,
        max_depth: int = 4,
    ) -> list[CrossEventPath]:
        """Find shared-entity associations between *event_id* and other events.

        Returns ``[]`` when Neo4j is disabled or unreachable. When Neo4j is
        enabled but has not yet mirrored graph rows, falls back to PostgreSQL.
        """
        if not self._enabled:
            return []

        assert self._client is not None
        if not await self._client.ping():
            logger.warning(
                "Neo4j unreachable — cross_event_paths empty for event %s",
                event_id,
            )
            return []

        records: list[dict[str, object]] = []
        try:
            records = await self._client.run_cypher(
                _CROSS_EVENT_SHARED,
                {"event_id": event_id},
            )
        except Exception:
            logger.exception(
                "Neo4j cross-event query failed for event %s — skipping PG fallback",
                event_id,
            )
            return []

        paths = await self._build_paths_from_records(
            event_id,
            records,
            max_depth=max_depth,
            expand_neighborhood=True,
        )
        if paths:
            return paths

        pg_paths = await self._find_cross_event_paths_pg(event_id)
        if pg_paths:
            logger.debug(
                "cross_event_paths PG fallback for event %s (%d path(s))",
                event_id,
                len(pg_paths),
            )
        return pg_paths

    async def _build_paths_from_records(
        self,
        event_id: str,
        records: list[dict[str, object]],
        *,
        max_depth: int,
        expand_neighborhood: bool,
    ) -> list[CrossEventPath]:
        by_related: dict[str, dict[str, object]] = {}
        for rec in records:
            shared_value = str(rec.get("shared_value") or "")
            related_event_id = str(rec.get("related_event_id") or "")
            local_node_id = str(rec.get("local_node_id") or "")
            remote_node_id = str(rec.get("remote_node_id") or "")
            entity_type = cast(str | None, rec.get("entity_type"))
            if not shared_value or not related_event_id:
                continue

            bucket = by_related.get(related_event_id)
            if bucket is None:
                bucket = {
                    "shared": [],
                    "nodes": [],
                    "types": [],
                }
                by_related[related_event_id] = bucket

            shared_list = cast(list[str], bucket["shared"])
            nodes_list = cast(list[str], bucket["nodes"])
            types_list = cast(list[str], bucket["types"])
            if shared_value not in shared_list:
                shared_list.append(shared_value)
            for nid in (local_node_id, remote_node_id):
                if nid and nid not in nodes_list:
                    nodes_list.append(nid)
            if entity_type:
                types_list.append(entity_type)

        depth = max(1, min(int(max_depth), 8))
        paths: list[CrossEventPath] = []
        for related_event_id, bucket in sorted(by_related.items()):
            shared_entities = cast(list[str], bucket["shared"])
            path_nodes = cast(list[str], bucket["nodes"])
            types_list = cast(list[str], bucket["types"])

            if expand_neighborhood and path_nodes and self._client is not None:
                local_nid = path_nodes[0]
                try:
                    neigh = await self._client.run_cypher(
                        _LOCAL_NEIGHBORHOOD.format(max_depth=depth),
                        {"node_id": local_nid, "event_id": event_id},
                    )
                    if neigh:
                        extra = cast(list[str], neigh[0].get("neighbor_ids") or [])
                        for nid in extra:
                            if nid and nid not in path_nodes:
                                path_nodes.append(nid)
                except Exception:
                    logger.debug(
                        "Neighborhood expansion skipped for %s",
                        local_nid,
                        exc_info=True,
                    )

            primary_type = types_list[0] if types_list else None
            primary_shared = shared_entities[0] if shared_entities else ""
            paths.append(
                CrossEventPath(
                    path_id=_path_id(event_id, related_event_id, primary_shared),
                    related_event_ids=[related_event_id],
                    shared_entities=shared_entities,
                    path_nodes=path_nodes,
                    risk_hint=_risk_hint(primary_type),
                )
            )

        return paths

    async def _find_cross_event_paths_pg(self, event_id: str) -> list[CrossEventPath]:
        """PostgreSQL shared-entity probe used while Neo4j sync is catching up."""
        if self._session_factory is None:
            return []

        local_node = aliased(GraphNodeORM)
        remote_node = aliased(GraphNodeORM)

        try:
            async with self._session_factory() as session:
                rows = (
                    await session.execute(
                        select(
                            local_node.entity_value,
                            local_node.entity_type,
                            local_node.node_id,
                            remote_node.node_id,
                            remote_node.event_id,
                        )
                        .select_from(local_node)
                        .join(
                            remote_node,
                            and_(
                                local_node.entity_type == remote_node.entity_type,
                                local_node.entity_value == remote_node.entity_value,
                                local_node.event_id == event_id,
                                remote_node.event_id != event_id,
                            ),
                        )
                        .where(local_node.entity_value.isnot(None))
                        .where(local_node.entity_value != "")
                        .order_by(local_node.entity_value, remote_node.event_id)
                    )
                ).all()
        except Exception:
            logger.exception(
                "PostgreSQL cross-event fallback failed for event %s",
                event_id,
            )
            return []

        records: list[dict[str, object]] = [
            {
                "shared_value": row[0],
                "entity_type": row[1],
                "local_node_id": row[2],
                "remote_node_id": row[3],
                "related_event_id": row[4],
            }
            for row in rows
        ]
        return await self._build_paths_from_records(
            event_id,
            records,
            max_depth=4,
            expand_neighborhood=False,
        )

    async def find_lateral_movement(self, entity_value: str) -> list[LateralMovementHop]:
        """Return time-ordered host hops for an account/process entity value.

        Empty when Neo4j is disabled/unreachable or the entity spans fewer
        than two distinct hosts (not lateral).
        """
        if not self._enabled:
            return []

        assert self._client is not None
        if not await self._client.ping():
            logger.warning(
                "Neo4j unreachable — lateral movement empty for %s",
                entity_value,
            )
            return []

        try:
            records = await self._client.run_cypher(
                _LATERAL_MOVEMENT,
                {"entity_value": entity_value},
            )
        except Exception:
            logger.exception(
                "Neo4j lateral-movement query failed for %s",
                entity_value,
            )
            return []

        hops: list[LateralMovementHop] = []
        seen_hosts: set[str] = set()
        for rec in records:
            host_value = str(rec.get("host_value") or "")
            hop = LateralMovementHop(
                actor_node_id=str(rec.get("actor_node_id") or ""),
                actor_type=str(rec.get("actor_type") or ""),
                event_id=str(rec.get("event_id") or ""),
                host_node_id=str(rec.get("host_node_id") or ""),
                host_value=host_value,
                occurred_at=rec.get("occurred_at"),
            )
            if hop.actor_node_id and hop.host_node_id:
                hops.append(hop)
                if host_value:
                    seen_hosts.add(host_value)

        if len(seen_hosts) < 2:
            return []
        return hops
