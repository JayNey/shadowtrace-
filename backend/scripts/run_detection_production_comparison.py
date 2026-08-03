"""CLI entry for post-promotion detection comparison (ISSUE-126 / #631 Phase B)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
DEFAULT_DATASET = REPO_ROOT / "data" / "evaluation" / "detection_production_v1"


def resolve_code_sha(explicit: str | None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    env_sha = os.environ.get("EVAL_CODE_SHA", "").strip()
    if env_sha:
        return env_sha
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


async def _run(args: argparse.Namespace) -> int:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.evaluation.detection.production_comparison_diff import (
        diff_production_comparison_against_baseline,
    )
    from app.evaluation.detection.production_fixture_loader import load_production_binding_manifest
    from app.evaluation.detection.production_runner import run_production_comparison
    from app.models.detection_evaluation import DetectionEvaluationArtifact
    from app.models.detection_production_comparison import DetectionProductionComparisonArtifact

    phase_a_payload = json.loads(args.phase_a_artifact.read_text(encoding="utf-8"))
    phase_a = DetectionEvaluationArtifact.model_validate(phase_a_payload)
    binding_manifest = load_production_binding_manifest(Path(args.dataset_dir))

    engine = create_async_engine(args.database_url)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    try:
        artifact = await run_production_comparison(
            session_factory,
            phase_a_artifact=phase_a,
            binding_manifest=binding_manifest,
            code_sha=resolve_code_sha(args.code_sha),
            seed=args.seed,
        )
    finally:
        await engine.dispose()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(artifact.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "comparison_id": artifact.comparison_id,
                "status": artifact.status.value,
                "recommendation": artifact.recommendation.value,
                "artifact_hash": artifact.artifact_hash,
                "phase_a_artifact_hash": artifact.config.phase_a_artifact_hash,
                "compared_cases": len(artifact.case_comparisons),
                "coverage_drift_detected": artifact.coverage_drift.drift_detected,
                "output": str(output_path),
                "advisory_note": artifact.advisory_note,
            },
            indent=2,
        )
    )

    if args.compare_baseline is not None:
        baseline_payload = json.loads(args.compare_baseline.read_text(encoding="utf-8"))
        baseline = DetectionProductionComparisonArtifact.model_validate(baseline_payload)
        drift = diff_production_comparison_against_baseline(baseline, artifact)
        if drift:
            print(
                json.dumps(
                    {
                        "baseline_compare": "failed",
                        "baseline_path": str(args.compare_baseline),
                        "diffs": [item.model_dump(mode="json") for item in drift],
                    },
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1
        print(
            json.dumps(
                {
                    "baseline_compare": "passed",
                    "baseline_path": str(args.compare_baseline),
                },
                indent=2,
            )
        )

    if artifact.recommendation.value == "rollback_recommended":
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run post-promotion detection comparison.")
    parser.add_argument(
        "--phase-a-artifact",
        type=Path,
        required=True,
        help="Pinned Phase A DetectionEvaluationArtifact JSON (read-only input)",
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DEFAULT_DATASET,
        help="Production comparison dataset directory with case_bindings.json",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--code-sha", default=None)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "artifacts" / "evaluation" / "detection_production_latest.json",
    )
    parser.add_argument(
        "--database-url",
        default="postgresql+asyncpg://shadowtrace:shadowtrace@127.0.0.1:5432/shadowtrace",
    )
    parser.add_argument(
        "--compare-baseline",
        type=Path,
        default=None,
        help="Pinned baseline comparison artifact JSON",
    )
    args = parser.parse_args()

    import asyncio

    raise SystemExit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
