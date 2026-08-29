"""Dump EventContext rag_output + graph_output for EventType-8 persist gates.

Runs inside the backend container (compose exec). Does not change the
ISSUE-254 API snapshot whitelist.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

def _prepare_sys_path() -> None:
    """Container WORKDIR is /app (app package); host eval uses backend/app."""
    candidates: list[Path] = [Path("/app"), Path("/app/backend")]
    file_name = globals().get("__file__")
    if isinstance(file_name, str) and not file_name.startswith("<"):
        here = Path(file_name).resolve()
        if here.is_file():
            repo = here.parents[1]
            if (repo / "backend" / "app").is_dir():
                candidates.extend([repo, repo / "backend"])
    for path in candidates:
        text = str(path)
        if path.is_dir() and text not in sys.path:
            sys.path.insert(0, text)


_prepare_sys_path()

from app.core.redis_client import RedisClient
from app.db.session import dispose_session_provider, get_session_factory
from app.services.context_service import EventContextStore


def _as_json(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


async def dump_persist(event_id: str) -> dict[str, Any]:
    redis = RedisClient()
    factory = get_session_factory()
    try:
        store = EventContextStore(redis, factory)
        ctx = await store.get_full_context(event_id)
        return {
            "event_id": event_id,
            "rag_output": _as_json(ctx.rag_output),
            "graph_output": _as_json(ctx.graph_output),
        }
    finally:
        await redis.aclose()
        await dispose_session_provider()


def dump_persist_sync(event_id: str) -> dict[str, Any]:
    return asyncio.run(dump_persist(event_id))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dump EventContext persist fields")
    parser.add_argument("--event-id", required=True)
    args = parser.parse_args(argv)
    payload = dump_persist_sync(str(args.event_id))
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[dump-eventtype8-persist] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
