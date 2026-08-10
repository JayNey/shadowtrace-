"""Seed the standalone Mock XDR service and ingest via SourceAdapter (ISSUE-088).

Used by ``scripts/bootstrap.sh`` so demo events exist in **both** PostgreSQL and
the mock-xdr container (read + disposition writeback stay consistent).

Usage (inside backend container)::

    python3 scripts/seed_mock_xdr_and_ingest.py \\
        --scenario insider_data_exfiltration \\
        --mock-xdr-url http://mock-xdr:8100 \\
        --seed 42
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

import httpx

_ROOT = Path(__file__).resolve().parents[1]
_BACKEND = _ROOT / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.adapters.mock_xdr import MockXDRSourceAdapter
from app.core.redis_client import RedisClient
from app.data_generators.scenarios import (
    SCENARIO_BUILDERS,
    build_scenario,
)
from app.db.session import dispose_session_provider, get_session_factory
from app.ingestion.source_ingester import SourceIngester
from app.models.enums import SourceObjectKind
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_service import EventService
from sqlalchemy import select

from app.db import models as orm

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("seed_mock_xdr_and_ingest")

_ALL_SOURCE_KINDS = [
    SourceObjectKind.INCIDENT,
    SourceObjectKind.ALERT,
    SourceObjectKind.ASSET,
    SourceObjectKind.LOG,
]

from app.mock_xdr.state import MOCK_XDR_DEFAULT_READ_TOKEN, MOCK_XDR_DEFAULT_WRITE_TOKEN


async def _seed_mock_xdr(*, mock_xdr_url: str, scenario_id: str, seed: int) -> dict:
    scenario = build_scenario(scenario_id, seed=seed)
    seed_url = f"{mock_xdr_url.rstrip('/')}/mock-xdr/v1/control/seed"
    payload = scenario.model_dump(mode="json")
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(seed_url, json=payload)
        response.raise_for_status()
        return response.json()


async def _snapshot_event_ids() -> set[str]:
    factory = get_session_factory()
    async with factory() as session:
        rows = await session.scalars(select(orm.SecurityEvent.event_id))
        return {str(event_id) for event_id in rows.all()}


async def _poll_ingest(*, mock_xdr_url: str) -> dict:
    factory = get_session_factory()
    redis = RedisClient()
    try:
        store = EventContextStore(redis, factory)
        degraded = DegradedFlagService(store, factory)
        events = EventService(factory, store, degraded_flags=degraded)
        ingester = SourceIngester(events, factory, source_mode="mock_xdr")
        adapter = MockXDRSourceAdapter(
            base_url=mock_xdr_url.rstrip("/"),
            read_token=MOCK_XDR_DEFAULT_READ_TOKEN,
            write_token=MOCK_XDR_DEFAULT_WRITE_TOKEN,
            max_retries=0,
        )
        summary = await ingester.poll(adapter, _ALL_SOURCE_KINDS, batch_size=50)
        return summary.model_dump(mode="json")
    finally:
        await redis.aclose()
        await dispose_session_provider()


async def _run(*, scenario_id: str, mock_xdr_url: str, seed: int, seed_only: bool) -> int:
    if scenario_id not in SCENARIO_BUILDERS:
        raise SystemExit(f"unknown scenario: {scenario_id!r}")

    seed_result = await _seed_mock_xdr(
        mock_xdr_url=mock_xdr_url,
        scenario_id=scenario_id,
        seed=seed,
    )
    logger.info(
        "mock-xdr seeded scenario=%s counts=%s",
        seed_result.get("scenario_id"),
        seed_result.get("object_counts"),
    )

    if seed_only:
        print(json.dumps(seed_result, ensure_ascii=False, indent=2))
        return 0

    before_event_ids = await _snapshot_event_ids()
    ingest_summary = await _poll_ingest(mock_xdr_url=mock_xdr_url)
    after_event_ids = await _snapshot_event_ids()
    new_event_ids = sorted(after_event_ids - before_event_ids)
    output = dict(ingest_summary)
    output["event_ids"] = new_event_ids
    print(json.dumps(output, ensure_ascii=False, indent=2))
    if output.get("degraded") or output.get("rejected", 0) > 0:
        logger.error("ingestion degraded or rejected rows present")
        return 1
    if output.get("accepted", 0) < 1:
        logger.error("no events accepted for scenario=%s", scenario_id)
        return 1
    if not new_event_ids:
        logger.error(
            "ingest accepted rows but produced no new event_ids for scenario=%s",
            scenario_id,
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Seed mock-xdr control plane and ingest via SourceAdapter poll"
    )
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIO_BUILDERS))
    parser.add_argument(
        "--mock-xdr-url",
        default="http://mock-xdr:8100",
        help="Mock XDR base URL (default: docker service)",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--seed-only",
        action="store_true",
        help="Only seed mock-xdr control plane; skip SourceAdapter poll (ISSUE-107 scheduler smoke)",
    )
    args = parser.parse_args(argv)
    return asyncio.run(
        _run(
            scenario_id=args.scenario,
            mock_xdr_url=args.mock_xdr_url,
            seed=args.seed,
            seed_only=args.seed_only,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
