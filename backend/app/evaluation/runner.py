"""Evaluation runner orchestration (ISSUE-105 / #608).

Consumes canonical ``EvaluationCaseTruth`` rows (#618 Phase A), performs mock-only
deterministic replay, runs registered scorers, and emits a versioned artifact.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from app.core.errors import ValidationError
from app.evaluation.artifact import finalize_artifact
from app.evaluation.paths import repo_relative_manifest_path
from app.evaluation.replayer import MockDeterministicReplayer
from app.evaluation.scorers.base import ScorerContext
from app.evaluation.scorers.registry import ScorerRegistry, default_scorer_registry
from app.evaluation.threshold import (
    evaluate_gate,
    load_threshold_manifest,
    validate_threshold_manifest_for_run,
)
from app.models.evaluation_run import (
    EvaluationAggregateMetrics,
    EvaluationCaseResult,
    EvaluationReleaseRefs,
    EvaluationRunArtifact,
    EvaluationRunConfig,
    EvaluationRunStatus,
    EvaluationScorerResult,
    EvaluationThresholdManifest,
    GateVerdict,
    ScorerOutcome,
)
from app.models.evaluation_truth import (
    EvaluationCaseTruth,
    EvaluationDatasetManifest,
    EvaluationTruthQuery,
    SliceType,
    UnevaluableSliceExpectation,
)
from app.services.evaluation_truth_service import EvaluationTruthService


def _slice_type(truth: EvaluationCaseTruth) -> SliceType:
    return SliceType(truth.slice_expectation.slice_type)


def _scorer_failure_status(
    scorer_results: list[EvaluationScorerResult],
) -> EvaluationRunStatus | None:
    if not scorer_results:
        return None
    if any(r.outcome == ScorerOutcome.ERROR for r in scorer_results):
        return EvaluationRunStatus.FAILED
    if any(r.outcome == ScorerOutcome.FAIL for r in scorer_results):
        return EvaluationRunStatus.FAILED
    if any(r.outcome == ScorerOutcome.SKIPPED for r in scorer_results):
        return EvaluationRunStatus.FAILED
    return None


def _case_status(
    slice_type: SliceType,
    scorer_results: list[EvaluationScorerResult],
) -> EvaluationRunStatus:
    failure = _scorer_failure_status(scorer_results)
    if failure is not None:
        return failure
    if slice_type == SliceType.UNEVALUABLE:
        if not scorer_results:
            return EvaluationRunStatus.UNEVALUABLE
        if all(r.outcome == ScorerOutcome.UNEVALUABLE for r in scorer_results):
            return EvaluationRunStatus.UNEVALUABLE
        return EvaluationRunStatus.FAILED
    if not scorer_results:
        return EvaluationRunStatus.FAILED
    if all(r.outcome == ScorerOutcome.PASS for r in scorer_results):
        return EvaluationRunStatus.COMPLETED
    return EvaluationRunStatus.FAILED


def _aggregate(
    case_results: list[EvaluationCaseResult],
    *,
    required_scorer_ids: frozenset[str],
) -> EvaluationAggregateMetrics:
    pass_count = fail_count = unevaluable_count = error_count = 0
    required_scorer_error_count = 0

    for case in case_results:
        outcomes = {r.outcome for r in case.scorer_results}
        if ScorerOutcome.ERROR in outcomes:
            error_count += 1
            required_scorer_error_count += sum(
                1
                for r in case.scorer_results
                if r.outcome == ScorerOutcome.ERROR and r.scorer_id in required_scorer_ids
            )
        elif case.case_status == EvaluationRunStatus.UNEVALUABLE:
            unevaluable_count += 1
        elif ScorerOutcome.FAIL in outcomes or case.case_status == EvaluationRunStatus.FAILED:
            fail_count += 1
        elif (
            case.scorer_results
            and all(r.outcome == ScorerOutcome.PASS for r in case.scorer_results)
        ):
            pass_count += 1
        else:
            fail_count += 1

    evaluable = pass_count + fail_count + error_count
    pass_rate = (pass_count / evaluable) if evaluable else 1.0

    return EvaluationAggregateMetrics(
        case_count=len(case_results),
        pass_count=pass_count,
        fail_count=fail_count,
        unevaluable_count=unevaluable_count,
        error_count=error_count,
        pass_rate=pass_rate,
        required_scorer_error_count=required_scorer_error_count,
    )


def _required_scorer_ids(
    manifest: EvaluationThresholdManifest | None,
    registry: ScorerRegistry,
) -> frozenset[str]:
    if manifest is not None and manifest.required_scorers:
        return frozenset(manifest.required_scorers)
    return frozenset(registry.all_required_ids())


def _run_status(
    aggregates: EvaluationAggregateMetrics,
    gate_verdict: GateVerdict | None,
    errors: list[str],
) -> EvaluationRunStatus:
    if errors:
        return EvaluationRunStatus.FAILED
    if gate_verdict in {GateVerdict.FAIL, GateVerdict.FAIL_CLOSED}:
        return EvaluationRunStatus.FAILED
    if aggregates.error_count > 0 or aggregates.fail_count > 0:
        return EvaluationRunStatus.FAILED
    if aggregates.case_count == aggregates.unevaluable_count:
        return EvaluationRunStatus.UNEVALUABLE
    return EvaluationRunStatus.COMPLETED


@dataclass(frozen=True, slots=True)
class EvaluationRunRequest:
    tenant_id: str
    dataset_id: str
    dataset_version: str
    dataset_content_hash: str
    seed: int
    code_sha: str
    release_refs: EvaluationReleaseRefs = field(default_factory=EvaluationReleaseRefs)
    scorer_ids: list[str] | None = None
    threshold_manifest: EvaluationThresholdManifest | None = None
    threshold_manifest_path: str | None = None


class EvaluationRunner:
    """Mock-only evaluation runner consuming canonical truth."""

    def __init__(
        self,
        truth_service: EvaluationTruthService,
        *,
        replayer: MockDeterministicReplayer | None = None,
        registry: ScorerRegistry | None = None,
    ) -> None:
        self._truth_service = truth_service
        self._replayer = replayer or MockDeterministicReplayer()
        self._registry = registry or default_scorer_registry()

    async def _load_truths(self, request: EvaluationRunRequest) -> list[EvaluationCaseTruth]:
        truths: list[EvaluationCaseTruth] = []
        page = 1
        while True:
            result = await self._truth_service.query_truths(
                EvaluationTruthQuery(
                    tenant_id=request.tenant_id,
                    dataset_id=request.dataset_id,
                    dataset_version=request.dataset_version,
                    latest_revision_only=True,
                    page=page,
                    page_size=200,
                )
            )
            truths.extend(result.items)
            if len(truths) >= result.total:
                break
            page += 1
        if not truths:
            raise ValidationError(
                "no canonical truth rows for dataset",
                details={
                    "tenant_id": request.tenant_id,
                    "dataset_id": request.dataset_id,
                    "dataset_version": request.dataset_version,
                },
            )
        return sorted(truths, key=lambda t: t.case_id)

    async def _validate_dataset_content_hash(self, request: EvaluationRunRequest) -> None:
        manifest = await self._truth_service.get_dataset_manifest(
            tenant_id=request.tenant_id,
            dataset_id=request.dataset_id,
            dataset_version=request.dataset_version,
        )
        if manifest.content_hash != request.dataset_content_hash:
            raise ValidationError(
                "dataset content hash mismatch",
                details={
                    "expected": manifest.content_hash,
                    "actual": request.dataset_content_hash,
                    "dataset_id": request.dataset_id,
                    "dataset_version": request.dataset_version,
                },
            )

    def _resolve_scorers(self, request: EvaluationRunRequest) -> list[str]:
        if request.scorer_ids:
            for scorer_id in request.scorer_ids:
                self._registry.get(scorer_id)
            return list(request.scorer_ids)
        return self._registry.scorer_ids

    async def run(self, request: EvaluationRunRequest) -> EvaluationRunArtifact:
        started_at = datetime.now(tz=UTC)
        await self._validate_dataset_content_hash(request)
        truths = await self._load_truths(request)
        scorer_ids = self._resolve_scorers(request)
        ctx = ScorerContext(
            seed=request.seed,
            dataset_id=request.dataset_id,
            dataset_version=request.dataset_version,
            replay_mode=self._replayer.replay_mode,
        )
        config = EvaluationRunConfig(
            seed=request.seed,
            replay_mode=self._replayer.replay_mode,
            replay_fidelity=getattr(self._replayer, "replay_fidelity", "echo_truth_stub"),
            release_refs=request.release_refs,
            scorer_ids=scorer_ids,
        )

        case_results: list[EvaluationCaseResult] = []
        errors: list[str] = []

        for truth in truths:
            slice_type = _slice_type(truth)
            observation = self._replayer.replay(truth, seed=request.seed)
            registrations = self._registry.list_for_slice(slice_type)
            active_registrations = [r for r in registrations if r.scorer_id in scorer_ids]
            if slice_type != SliceType.UNEVALUABLE and not active_registrations:
                if registrations:
                    errors.append(
                        "no active scorers for slice "
                        f"{slice_type.value} case {truth.case_id} "
                        f"(configured scorer_ids={scorer_ids})"
                    )
                else:
                    errors.append(
                        f"no scorers registered for slice {slice_type.value}: {truth.case_id}"
                    )
            scorer_results: list[EvaluationScorerResult] = []
            for registration in active_registrations:
                try:
                    scorer_results.append(registration.scorer.score(truth, observation, ctx))
                except Exception as exc:  # noqa: BLE001 — scorer boundary fail-closed
                    scorer_results.append(
                        EvaluationScorerResult(
                            scorer_id=registration.scorer_id,
                            outcome=ScorerOutcome.ERROR,
                            reason_code="scorer_exception",
                            message=str(exc)[:512],
                        )
                    )
            case_results.append(
                EvaluationCaseResult(
                    case_id=truth.case_id,
                    truth_id=truth.truth_id,
                    truth_revision=truth.revision,
                    truth_content_hash=truth.content_hash,
                    slice_type=slice_type,
                    observation=observation,
                    scorer_results=scorer_results,
                    case_status=_case_status(slice_type, scorer_results),
                    unevaluable_reason=(
                        truth.slice_expectation.reason_code
                        if isinstance(truth.slice_expectation, UnevaluableSliceExpectation)
                        else None
                    ),
                )
            )

        if request.threshold_manifest is not None:
            validate_threshold_manifest_for_run(
                request.threshold_manifest,
                dataset_id=request.dataset_id,
                dataset_version=request.dataset_version,
            )

        aggregates = _aggregate(
            case_results,
            required_scorer_ids=_required_scorer_ids(request.threshold_manifest, self._registry),
        )
        gate = evaluate_gate(
            request.threshold_manifest,
            aggregates=aggregates,
            case_results=case_results,
            registry=self._registry,
            manifest_path=request.threshold_manifest_path,
        )
        status = _run_status(aggregates, gate.verdict if gate else None, errors)
        completed_at = datetime.now(tz=UTC)

        artifact = EvaluationRunArtifact(
            run_id=f"eval-{uuid.uuid4()}",
            tenant_id=request.tenant_id,
            dataset_id=request.dataset_id,
            dataset_version=request.dataset_version,
            dataset_content_hash=request.dataset_content_hash,
            code_sha=request.code_sha,
            config=config,
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            case_results=case_results,
            aggregates=aggregates,
            gate=gate,
            errors=errors,
        )
        return finalize_artifact(artifact)


async def run_fixture_evaluation(
    truth_service: EvaluationTruthService,
    manifest: EvaluationDatasetManifest,
    *,
    seed: int,
    code_sha: str,
    release_refs: EvaluationReleaseRefs | None = None,
    threshold_manifest_path: Path | None = None,
    registry: ScorerRegistry | None = None,
) -> EvaluationRunArtifact:
    """Convenience entry for fixture-backed datasets."""
    threshold: EvaluationThresholdManifest | None = None
    threshold_path_str: str | None = None
    if threshold_manifest_path is not None:
        threshold_path_str = repo_relative_manifest_path(threshold_manifest_path)
        threshold = load_threshold_manifest(threshold_manifest_path)

    runner = EvaluationRunner(truth_service, registry=registry)
    return await runner.run(
        EvaluationRunRequest(
            tenant_id=manifest.tenant_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            dataset_content_hash=manifest.content_hash,
            seed=seed,
            code_sha=code_sha,
            release_refs=release_refs or EvaluationReleaseRefs(),
            threshold_manifest=threshold,
            threshold_manifest_path=threshold_path_str,
        )
    )


__all__ = [
    "EvaluationRunRequest",
    "EvaluationRunner",
    "run_fixture_evaluation",
]
