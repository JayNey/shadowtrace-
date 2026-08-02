"""Seed detection replay fixtures into PostgreSQL (ISSUE-126 / #631 Phase A)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.evaluation.detection.fixture_loader import (
    DetectionObservationFixture,
    DetectionReplayFixture,
)
from app.models.behavior_observation import (
    BehaviorEntityRef,
    BehaviorObservation,
    BehaviorObservationProvenance,
    BehaviorObservationSourceRef,
)
from app.models.detection_rule import DetectionRuleRuntimeState
from app.models.detection_scope import DetectionScopeIdentity, UpstreamConnectorMember
from app.services.detection_rule_resolver import compile_rule_package
from app.services.detection_rule_service import DetectionRuleService
from app.services.detection_scope_service import DetectionScopeService
from app.models.detection_rule import DetectionRulePackageProvenance


@dataclass(frozen=True, slots=True)
class SeededDetectionContext:
    source_tenant_id: str
    detection_scope_id: str
    scope_revision_id: str
    package_id: str
    package_content_hash: str
    feature_contract_version: str


async def _insert_observation_row(
    session: AsyncSession,
    fixture: DetectionObservationFixture,
) -> None:
    existing = await session.get(orm.BehaviorObservation, fixture.observation_id)
    if existing is not None:
        return
    observation = BehaviorObservation(
        observation_id=fixture.observation_id,
        source_tenant_id=fixture.source_tenant_id,
        detection_scope_id=fixture.detection_scope_id,
        source_ref=BehaviorObservationSourceRef(
            source_product="mock_xdr",
            connector_id=fixture.connector_id,
            source_kind="log",
            source_object_id=fixture.source_object_id,
            source_object_type="edr",
            source_revision=1,
        ),
        observed_at=fixture.observed_at,
        ingested_at=fixture.observed_at,
        entity_refs=[
            BehaviorEntityRef(
                entity_type=fixture.entity_type,
                entity_id=fixture.entity_id,
                role="src",
            )
        ],
        action=fixture.action,
        category=fixture.category,
        detection_score=fixture.detection_score,
        content_hash=fixture.content_hash,
        observation_hash=fixture.observation_hash,
        idempotency_key=f"idem-{fixture.observation_id}",
        provenance=BehaviorObservationProvenance(source_record_id=f"src-{fixture.observation_id}"),
    )
    session.add(
        orm.BehaviorObservation(
            observation_id=observation.observation_id,
            source_tenant_id=observation.source_tenant_id,
            detection_scope_id=observation.detection_scope_id,
            source_product=observation.source_ref.source_product,
            connector_id=observation.source_ref.connector_id,
            source_kind=observation.source_ref.source_kind,
            source_object_id=observation.source_ref.source_object_id,
            source_object_type=observation.source_ref.source_object_type,
            source_revision=observation.source_ref.source_revision,
            source_ref=observation.source_ref.model_dump(mode="json"),
            observed_at=observation.observed_at,
            ingested_at=observation.ingested_at,
            entity_refs=[item.model_dump(mode="json") for item in observation.entity_refs],
            action=observation.action,
            category=observation.category,
            normalized_attributes=observation.normalized_attributes,
            detection_score=observation.detection_score,
            schema_version=observation.schema_version,
            projection_schema_version=observation.projection_schema_version,
            content_hash=observation.content_hash,
            observation_hash=observation.observation_hash,
            idempotency_key=observation.idempotency_key,
            provenance=observation.provenance.model_dump(mode="json"),
        )
    )


async def seed_detection_replay_fixture(
    session_factory: async_sessionmaker[AsyncSession],
    replay: DetectionReplayFixture,
) -> SeededDetectionContext:
    """Idempotently seed scope, observations, and shadow package for one case."""
    scope_service = DetectionScopeService(session_factory)
    rule_service = DetectionRuleService(session_factory)

    identity = DetectionScopeIdentity(
        source_tenant_id=replay.source_tenant_id,
        source_product=replay.scope_seed.source_product,
        integration_instance_id=replay.scope_seed.integration_instance_id,
    )
    existing_scope = await scope_service.get_active_revision_for_instance(
        source_tenant_id=replay.source_tenant_id,
        source_product=replay.scope_seed.source_product,
        integration_instance_id=replay.scope_seed.integration_instance_id,
    )
    if existing_scope is not None:
        activated = existing_scope
        scope_id = activated.detection_scope_id
    else:
        revision = await scope_service.register_revision(
            identity=identity,
            connector_set_version=1,
            upstream_connectors=[
                UpstreamConnectorMember(
                    connector_id=replay.scope_seed.connector_id,
                    source_product=replay.scope_seed.source_product,
                ),
            ],
        )
        activated = await scope_service.activate_revision(revision.scope_revision_id)
        scope_id = activated.detection_scope_id

    rules = []
    for rule in replay.rules:
        rules.append(
            rule.model_copy(update={"detection_scope_id": scope_id}),
        )

    async with session_factory() as session:
        async with session.begin():
            for obs in replay.observations:
                obs_fixture = DetectionObservationFixture(
                    observation_id=obs.observation_id,
                    source_tenant_id=obs.source_tenant_id,
                    detection_scope_id=scope_id,
                    observed_at=obs.observed_at,
                    action=obs.action,
                    category=obs.category,
                    entity_type=obs.entity_type,
                    entity_id=obs.entity_id,
                    connector_id=obs.connector_id,
                    source_object_id=obs.source_object_id,
                    detection_score=obs.detection_score,
                    content_hash=obs.content_hash,
                    observation_hash=obs.observation_hash,
                )
                await _insert_observation_row(session, obs_fixture)

    existing = await rule_service.get_package(
        source_tenant_id=replay.source_tenant_id,
        package_id=replay.package_id,
    )
    if existing is None:
        package = compile_rule_package(
            source_tenant_id=replay.source_tenant_id,
            package_id=replay.package_id,
            package_version=replay.package_version,
            runtime_state=DetectionRuleRuntimeState.DRAFT,
            rules=list(rules),
            provenance=DetectionRulePackageProvenance(
                author="detection-evaluation-fixture",
                compiled_at=datetime.now(UTC),
            ),
        )
        async with session_factory() as session:
            async with session.begin():
                package = await rule_service.persist_in_session(session, package)
    else:
        package = existing

    if package.runtime_state is not DetectionRuleRuntimeState.SHADOW_ACTIVE:
        if package.runtime_state is DetectionRuleRuntimeState.DRAFT:
            await rule_service.validate_package(
                source_tenant_id=replay.source_tenant_id,
                package_id=package.package_id,
            )
        await rule_service.activate_shadow(
            source_tenant_id=replay.source_tenant_id,
            package_id=package.package_id,
        )
        package = await rule_service.get_package(
            source_tenant_id=replay.source_tenant_id,
            package_id=package.package_id,
        )
        assert package is not None

    feature_contract_version = rules[0].feature_contract_version if rules else "unknown"
    return SeededDetectionContext(
        source_tenant_id=replay.source_tenant_id,
        detection_scope_id=scope_id,
        scope_revision_id=activated.scope_revision_id,
        package_id=package.package_id,
        package_content_hash=package.content_hash,
        feature_contract_version=feature_contract_version,
    )


async def clear_detection_tables(session_factory: async_sessionmaker[AsyncSession]) -> None:
    from sqlalchemy import delete

    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.DetectionRuleRuntimeError))
            await session.execute(delete(orm.CandidateDetection))
            await session.execute(delete(orm.DetectionRulePackage))
            await session.execute(delete(orm.DetectionFeatureBaseline))
            await session.execute(delete(orm.FeatureSnapshot))
            await session.execute(delete(orm.BehaviorObservation))
            await session.execute(delete(orm.DetectionScopeRevision))


async def derive_candidate_refs(
    session_factory: async_sessionmaker[AsyncSession],
    replay: DetectionReplayFixture,
) -> DetectionCandidateRefs:
    from app.models.detection_evaluation import DetectionCandidateRefs

    seeded = await seed_detection_replay_fixture(session_factory, replay)
    rule_ids = [rule.rule_id for rule in replay.rules]
    return DetectionCandidateRefs(
        package_id=seeded.package_id,
        package_version=replay.package_version,
        package_content_hash=seeded.package_content_hash,
        rule_ids=rule_ids,
        feature_contract_version=seeded.feature_contract_version,
        detection_scope_id=seeded.detection_scope_id,
        scope_revision_id=seeded.scope_revision_id,
    )


__all__ = [
    "SeededDetectionContext",
    "clear_detection_tables",
    "derive_candidate_refs",
    "seed_detection_replay_fixture",
]
