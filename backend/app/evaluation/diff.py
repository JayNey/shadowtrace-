"""Artifact comparison helpers (ISSUE-105 / #608)."""

from __future__ import annotations

from typing import Any

from app.evaluation.artifact import finalize_artifact
from app.models.evaluation_run import EvaluationGateDiff, EvaluationRunArtifact


def _scalar_diff(field: str, left: Any, right: Any, *, reason: str) -> EvaluationGateDiff | None:
    if left == right:
        return None
    return EvaluationGateDiff(
        field=field,
        expected=left,
        actual=right,
        reason=reason,
    )


def diff_artifacts(
    baseline: EvaluationRunArtifact,
    candidate: EvaluationRunArtifact,
) -> list[EvaluationGateDiff]:
    """Return machine-readable deltas between two evaluation artifacts."""
    diffs: list[EvaluationGateDiff] = []

    for field, reason in (
        ("dataset_content_hash", "dataset content hash changed"),
        ("code_sha", "code SHA changed"),
        ("schema_version", "artifact schema version changed"),
    ):
        delta = _scalar_diff(
            field,
            getattr(baseline, field),
            getattr(candidate, field),
            reason=reason,
        )
        if delta is not None:
            diffs.append(delta)

    if baseline.config.seed != candidate.config.seed:
        diffs.append(
            EvaluationGateDiff(
                field="config.seed",
                expected=baseline.config.seed,
                actual=candidate.config.seed,
                reason="replay seed changed",
            )
        )

    if baseline.config.replay_fidelity != candidate.config.replay_fidelity:
        diffs.append(
            EvaluationGateDiff(
                field="config.replay_fidelity",
                expected=baseline.config.replay_fidelity,
                actual=candidate.config.replay_fidelity,
                reason="replay fidelity changed",
            )
        )

    baseline_refs = baseline.config.release_refs.model_dump()
    candidate_refs = candidate.config.release_refs.model_dump()
    if baseline_refs != candidate_refs:
        diffs.append(
            EvaluationGateDiff(
                field="config.release_refs",
                expected=baseline_refs,
                actual=candidate_refs,
                reason="release refs changed",
            )
        )

    if baseline.artifact_hash != candidate.artifact_hash:
        diffs.append(
            EvaluationGateDiff(
                field="artifact_hash",
                expected=baseline.artifact_hash,
                actual=candidate.artifact_hash,
                reason="reproducible artifact hash changed",
            )
        )

    baseline_cases = {case.case_id: case for case in baseline.case_results}
    candidate_cases = {case.case_id: case for case in candidate.case_results}

    for case_id in sorted(set(baseline_cases) | set(candidate_cases)):
        left = baseline_cases.get(case_id)
        right = candidate_cases.get(case_id)
        if left is None:
            diffs.append(
                EvaluationGateDiff(
                    field=f"case:{case_id}",
                    expected="present",
                    actual="missing",
                    reason=f"case {case_id} missing from baseline artifact",
                )
            )
            continue
        if right is None:
            diffs.append(
                EvaluationGateDiff(
                    field=f"case:{case_id}",
                    expected="present",
                    actual="missing",
                    reason=f"case {case_id} missing from candidate artifact",
                )
            )
            continue
        if left.truth_revision != right.truth_revision:
            diffs.append(
                EvaluationGateDiff(
                    field=f"case:{case_id}.truth_revision",
                    expected=left.truth_revision,
                    actual=right.truth_revision,
                    reason=f"truth revision changed for case {case_id}",
                )
            )
        if left.case_status != right.case_status:
            diffs.append(
                EvaluationGateDiff(
                    field=f"case:{case_id}.case_status",
                    expected=left.case_status.value,
                    actual=right.case_status.value,
                    reason=f"case status changed for case {case_id}",
                )
            )

    return diffs


def diff_against_baseline(
    baseline: EvaluationRunArtifact,
    candidate: EvaluationRunArtifact,
) -> list[EvaluationGateDiff]:
    """Compare candidate output to a pinned baseline artifact.

    Aligns ``code_sha`` to the baseline pin so CI can use ``GITHUB_SHA`` for
    provenance while still detecting evaluation-output drift.
    """
    aligned = candidate.model_copy(update={"code_sha": baseline.code_sha})
    aligned = finalize_artifact(aligned)
    return diff_artifacts(baseline, aligned)


__all__ = ["diff_against_baseline", "diff_artifacts"]
