"""CLI entry for mock-only evaluation runs (ISSUE-105 / #608)."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
DEFAULT_DATASET = REPO_ROOT / "data" / "evaluation" / "shadowtrace_demo_v1"


def resolve_code_sha(explicit: str | None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "0000000"


def _apply_migrations(database_url: str) -> None:
    import os

    from alembic import command
    from alembic.config import Config

    os.environ["DATABASE_URL"] = database_url
    alembic_cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    command.upgrade(alembic_cfg, "head")


async def _run(args: argparse.Namespace) -> int:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.evaluation.fixture_loader import load_fixture_dataset
    from app.evaluation.runner import run_fixture_evaluation
    from app.models.evaluation_run import EvaluationReleaseRefs
    from app.services.evaluation_truth_service import EvaluationTruthService

    dataset_dir = Path(args.dataset_dir)
    threshold_path: Path | None
    if args.threshold_manifest:
        threshold_path = Path(args.threshold_manifest)
    else:
        candidate = dataset_dir / "threshold_manifest.json"
        threshold_path = candidate if candidate.is_file() else None

    engine = create_async_engine(args.database_url)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    truth_service = EvaluationTruthService(session_factory)

    async with session_factory() as session:
        async with session.begin():
            truths, manifest = await load_fixture_dataset(
                truth_service,
                dataset_dir,
                tenant_id=args.tenant_id,
            )

    artifact = await run_fixture_evaluation(
        truth_service,
        manifest,
        seed=args.seed,
        code_sha=resolve_code_sha(args.code_sha),
        release_refs=EvaluationReleaseRefs(config_profile=args.config_profile),
        threshold_manifest_path=threshold_path,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(artifact.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "run_id": artifact.run_id,
                "status": artifact.status.value,
                "artifact_hash": artifact.artifact_hash,
                "case_count": artifact.aggregates.case_count,
                "pass_rate": artifact.aggregates.pass_rate,
                "gate_verdict": artifact.gate.verdict.value if artifact.gate else None,
                "output": str(output_path),
                "loaded_cases": len(truths),
            },
            indent=2,
        )
    )

    await engine.dispose()
    if artifact.status.value != "completed":
        return 1
    if artifact.gate and artifact.gate.verdict.value in {"fail", "fail_closed"}:
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run mock-only evaluation pipeline.")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DEFAULT_DATASET,
        help="Fixture dataset directory containing manifest.json and cases/",
    )
    parser.add_argument("--tenant-id", default=None, help="Override tenant id from manifest")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic replay seed")
    parser.add_argument("--code-sha", default=None, help="Pinned code SHA (defaults to git HEAD)")
    parser.add_argument(
        "--config-profile",
        default="mock_p0",
        help="Release config profile label stored in artifact",
    )
    parser.add_argument(
        "--threshold-manifest",
        type=Path,
        default=None,
        help="Threshold manifest path (defaults to dataset threshold_manifest.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "artifacts" / "evaluation" / "latest_run.json",
        help="Artifact JSON output path",
    )
    parser.add_argument(
        "--database-url",
        default="postgresql+asyncpg://shadowtrace:shadowtrace@127.0.0.1:5432/shadowtrace",
        help="PostgreSQL URL for canonical truth persistence",
    )
    args = parser.parse_args()

    _apply_migrations(args.database_url)

    import asyncio

    raise SystemExit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
