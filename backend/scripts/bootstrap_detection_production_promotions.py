"""Bootstrap completed promotions before post-promotion comparison (ISSUE-126 Phase B)."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
DEFAULT_DATASET = REPO_ROOT / "data" / "evaluation" / "detection_production_v1"
DEFAULT_THRESHOLD = (
    REPO_ROOT / "data" / "evaluation" / "detection_shadow_v1" / "threshold_manifest.json"
)


async def _run(args: argparse.Namespace) -> int:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.core.redis_client import RedisClient
    from app.evaluation.detection.production_bootstrap import bootstrap_production_promotions
    from app.evaluation.detection.production_fixture_loader import load_production_binding_manifest
    from app.models.detection_evaluation import DetectionEvaluationArtifact

    phase_a_payload = json.loads(args.phase_a_artifact.read_text(encoding="utf-8"))
    phase_a = DetectionEvaluationArtifact.model_validate(phase_a_payload)
    binding_manifest = load_production_binding_manifest(Path(args.dataset_dir))

    engine = create_async_engine(args.database_url)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    redis_client = RedisClient(args.redis_url)
    try:
        result = await bootstrap_production_promotions(
            session_factory,
            redis_client,
            phase_a_artifact=phase_a,
            binding_manifest=binding_manifest,
            threshold_manifest_path=args.threshold_manifest,
        )
    finally:
        await engine.dispose()
        await redis_client.aclose()

    print(
        json.dumps(
            {
                "promoted_case_ids": list(result.promoted_case_ids),
                "skipped_case_ids": list(result.skipped_case_ids),
            },
            indent=2,
        )
    )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Approve and promote Phase A candidates for production comparison.",
    )
    parser.add_argument(
        "--phase-a-artifact",
        type=Path,
        required=True,
        help="Pinned Phase A DetectionEvaluationArtifact JSON",
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DEFAULT_DATASET,
        help="Production comparison dataset directory",
    )
    parser.add_argument(
        "--threshold-manifest",
        type=Path,
        default=DEFAULT_THRESHOLD,
        help="Governance threshold manifest for approval",
    )
    parser.add_argument(
        "--database-url",
        default=os.environ.get(
            "DATABASE_URL",
            "postgresql+asyncpg://shadowtrace:shadowtrace@127.0.0.1:5432/shadowtrace",
        ),
    )
    parser.add_argument(
        "--redis-url",
        default=os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"),
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
