"""Load ATT&CK STIX release into the knowledge registry (ISSUE-128 / #634).

Usage::

    cd backend && python -m scripts.load_attack_stix_release

The script stages + activates an offline STIX bundle derived from
``data/knowledge/attack_techniques.json``. Repeated runs are idempotent.

This is a **development bootstrap** path only — the curated JSON fixture is not
a signed production ATT&CK release. Use validated offline bundles with explicit
provenance for production imports.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.core.config import Settings  # noqa: E402
from app.core.embedding.service import EmbeddingService  # noqa: E402
from app.models.knowledge_release import ATTACK_CORPUS_ID  # noqa: E402
from app.services.knowledge_release_resolver import default_attack_provenance  # noqa: E402
from app.services.knowledge_release_service import KnowledgeReleaseService  # noqa: E402
from app.services.knowledge_store import KnowledgeStore  # noqa: E402
from app.services.stix_bundle_builder import build_bundle_from_techniques_json  # noqa: E402

REPO_ROOT = _BACKEND.parent
DATA_FILE = REPO_ROOT / "data" / "knowledge" / "attack_techniques.json"
STIX_DIR = REPO_ROOT / "data" / "knowledge" / "stix"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


async def _main() -> None:
    if not DATA_FILE.exists():
        print(f"Data file not found: {DATA_FILE}")
        sys.exit(1)

    bundle = build_bundle_from_techniques_json(DATA_FILE)
    attack_version = str(bundle.get("x_shadowtrace_attack_version") or "unknown")

    STIX_DIR.mkdir(parents=True, exist_ok=True)
    bundle_path = STIX_DIR / f"attack_enterprise_{attack_version.replace('.', '_')}.bundle.json"
    bundle_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    settings = Settings()
    engine = create_async_engine(DATABASE_URL)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    embed_service = EmbeddingService(settings)
    store = KnowledgeStore(session_factory, embed_service)
    service = KnowledgeReleaseService(session_factory, store=store, settings=settings)

    try:
        staged = await service.stage_stix_bundle(
            bundle,
            release_version=attack_version,
            provenance=default_attack_provenance(str(bundle_path)),
        )
        activated = await service.activate_release(staged.release_id, vector_ready=False)
        active = await service.get_active_release(ATTACK_CORPUS_ID)
        print(
            f"Activated release {activated.release_id} "
            f"(objects={activated.object_count}, corpus={ATTACK_CORPUS_ID})"
        )
        if active is None or active.release_id != activated.release_id:
            print("Active release verification failed")
            sys.exit(1)
    finally:
        await embed_service.close()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_main())
