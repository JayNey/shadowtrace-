"""Load policy/control corpus into KnowledgeRelease registry (ISSUE-129 / #635).

Usage::

    cd backend && python -m scripts.load_policy_release

Repeated runs are idempotent via release idempotency keys.
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
from app.models.knowledge_release import KnowledgeReleaseProvenance  # noqa: E402
from app.services.policy_release_resolver import default_policy_provenance  # noqa: E402
from app.services.policy_release_service import PolicyReleaseService  # noqa: E402

REPO_ROOT = _BACKEND.parent
DATA_FILE = REPO_ROOT / "data" / "knowledge" / "policy_controls.json"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


async def _main() -> None:
    if not DATA_FILE.exists():
        print(f"Data file not found: {DATA_FILE}")
        sys.exit(1)

    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    settings = Settings()
    engine = create_async_engine(DATABASE_URL)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    service = PolicyReleaseService(session_factory, settings=settings)

    try:
        provenance = KnowledgeReleaseProvenance.model_validate(
            default_policy_provenance(str(DATA_FILE))
        )
        staged = await service.stage_policy_bundle(
            bundle,
            release_version="v1",
            provenance=provenance,
        )
        active = await service.activate_release(staged.release_id)
        print(
            f"Policy release {active.release_id} activated "
            f"(objects={active.object_count}, mappings={active.relationship_count})"
        )
    except Exception as exc:
        print(f"Policy release load failed: {exc}")
        sys.exit(1)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_main())
