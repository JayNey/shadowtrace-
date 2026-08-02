"""Detection shadow replayer (ISSUE-126 / #631 Phase A).

Replays canonical truth cases through the shadow detection runtime (#626–#628).
Never reads post-promotion Event severity, agent conclusions, or response outcomes.
"""

from __future__ import annotations

import hashlib

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.evaluation.detection.fixture_loader import DetectionReplayFixture
from app.evaluation.detection.fixture_seeder import SeededDetectionContext, seed_detection_replay_fixture
from app.models.detection_evaluation import DetectionCaseObservation, DetectionResourceMetrics
from app.models.detection_rule import DetectionRuleRuntimeError
from app.models.evaluation_truth import EvaluationCaseTruth, SliceType, UnevaluableSliceExpectation
from app.services.detection_rule_runtime import DetectionRuleRuntimeService


def _derive_case_nonce(case_id: str, seed: int) -> int:
    digest = hashlib.sha256(f"{seed}:{case_id}".encode()).hexdigest()
    return int(digest[:8], 16)


class DetectionShadowReplayer:
    """Deterministic shadow runtime replay for detection evaluation cases."""

    replay_mode = "detection_shadow"
    replay_fidelity = "shadow_runtime_v1"

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._runtime = DetectionRuleRuntimeService(session_factory)
        self._seed_cache: dict[str, SeededDetectionContext] = {}

    async def seed_case(self, replay: DetectionReplayFixture) -> SeededDetectionContext:
        cache_key = f"{replay.source_tenant_id}:{replay.package_id}"
        if cache_key not in self._seed_cache:
            self._seed_cache[cache_key] = await seed_detection_replay_fixture(
                self._session_factory,
                replay,
            )
        return self._seed_cache[cache_key]

    async def replay(
        self,
        truth: EvaluationCaseTruth,
        replay: DetectionReplayFixture,
        *,
        seed: int,
    ) -> DetectionCaseObservation:
        slice_type = SliceType(truth.slice_expectation.slice_type)
        nonce = _derive_case_nonce(truth.case_id, seed)

        if isinstance(truth.slice_expectation, UnevaluableSliceExpectation):
            seeded = await self.seed_case(replay)
            if replay.skip_shadow_execute:
                return DetectionCaseObservation(
                    case_id=truth.case_id,
                    slice_type=slice_type,
                    observation_available=False,
                    replay_notes=(
                        f"unevaluable:{truth.slice_expectation.reason_code};seed={seed};n={nonce:x}"
                    ),
                )

        seeded = await self.seed_case(replay)

        if replay.force_runtime_error:
            runtime_error = DetectionRuleRuntimeError(
                error_id=f"err-{truth.case_id}",
                source_tenant_id=replay.source_tenant_id,
                package_id=seeded.package_id,
                rule_id=replay.rules[0].rule_id if replay.rules else None,
                error_category="fixture_forced_error",
                error_message="fixture forced runtime error",
                detail={"case_id": truth.case_id},
            )
            return DetectionCaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                runtime_errors=[runtime_error],
                resource_metrics=DetectionResourceMetrics(runtime_error_count=1),
                observation_available=False,
                replay_notes=f"forced_error;seed={seed};n={nonce:x}",
            )

        if replay.skip_shadow_execute:
            return DetectionCaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observation_available=False,
                replay_notes=f"skip_shadow_execute;seed={seed};n={nonce:x}",
            )

        result = await self._runtime.execute_shadow(
            source_tenant_id=replay.source_tenant_id,
            cutoff_at=replay.cutoff_at,
            package_id=seeded.package_id,
        )

        return DetectionCaseObservation(
            case_id=truth.case_id,
            slice_type=slice_type,
            candidates=list(result.candidates),
            runtime_errors=list(result.errors),
            resource_metrics=DetectionResourceMetrics(
                rules_evaluated=result.rules_evaluated,
                observations_scanned=result.observations_scanned,
                runtime_error_count=len(result.errors),
                candidate_count=len(result.candidates),
            ),
            observation_available=True,
            replay_notes=f"shadow_runtime_v1;seed={seed};n={nonce:x}",
        )

    async def probe_tenant_isolation(
        self,
        replay: DetectionReplayFixture,
        *,
        probe_tenant_id: str,
    ) -> list:
        await self.seed_case(replay)
        result = await self._runtime.execute_shadow(
            source_tenant_id=probe_tenant_id,
            cutoff_at=replay.cutoff_at,
            package_id=None,
        )
        return list(result.candidates)


__all__ = ["DetectionShadowReplayer"]
