"""Tests for PlaybookReleaseService and approval binding (ISSUE-139 / #645)."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.core.errors import ValidationError
from app.models.knowledge_release import KnowledgeReleaseProvenance
from app.models.playbook_release import PlaybookRef
from app.services.knowledge_store import KnowledgeStore
from app.services.playbook_approval_binding import (
    build_approval_binding_detail,
    compute_playbook_binding_hash,
    validate_approval_binding,
)
from app.services.playbook_kb_service import PlaybookKBService
from app.services.playbook_release_resolver import compute_playbook_object_hash
from app.services.playbook_release_service import PlaybookReleaseService

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
DATA_FILE = REPO_ROOT / "data" / "knowledge" / "playbooks.json"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
def settings() -> Settings:
    return Settings(embedding_mode="mock")


@pytest_asyncio.fixture
def embed_service(settings: Settings) -> EmbeddingService:
    return EmbeddingService(settings)


@pytest_asyncio.fixture
def store(
    session_factory: async_sessionmaker[AsyncSession],
    embed_service: EmbeddingService,
) -> KnowledgeStore:
    return KnowledgeStore(session_factory, embed_service)


@pytest_asyncio.fixture
def playbook_kb(
    store: KnowledgeStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> PlaybookKBService:
    return PlaybookKBService(store, session_factory)


@pytest_asyncio.fixture
def release_service(
    session_factory: async_sessionmaker[AsyncSession],
    playbook_kb: PlaybookKBService,
    settings: Settings,
) -> PlaybookReleaseService:
    return PlaybookReleaseService(session_factory, playbook_kb=playbook_kb, settings=settings)


async def _clean(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        await session.execute(text("DELETE FROM knowledge_chunk"))
        await session.execute(text("DELETE FROM playbook_release_object"))
        await session.execute(text("DELETE FROM knowledge_release"))
        await session.commit()


@pytest.mark.asyncio
async def test_stage_and_activate_playbook_release(
    session_factory: async_sessionmaker[AsyncSession],
    release_service: PlaybookReleaseService,
    playbook_kb: PlaybookKBService,
) -> None:
    await _clean(session_factory)
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance(
        source_path=str(DATA_FILE),
        imported_by="test",
        import_kind="playbook_bundle",
    )
    staged = await release_service.stage_playbook_bundle(
        bundle,
        release_version="v1-test",
        provenance=provenance,
    )
    assert staged.object_count >= 1

    active = await release_service.activate_release(staged.release_id)
    assert active.lifecycle_state.value == "active"

    active_lookup = await release_service.get_active_release()
    assert active_lookup is not None
    assert active_lookup.release_id == staged.release_id

    count = await playbook_kb.store.count("playbook_kb")
    assert count >= 1


@pytest.mark.asyncio
async def test_resolve_playbook_ref_rejects_hash_mismatch(
    session_factory: async_sessionmaker[AsyncSession],
    release_service: PlaybookReleaseService,
) -> None:
    await _clean(session_factory)
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance(
        source_path=str(DATA_FILE),
        imported_by="test",
        import_kind="playbook_bundle",
    )
    staged = await release_service.stage_playbook_bundle(
        bundle,
        release_version="v1-test",
        provenance=provenance,
    )
    playbook = bundle["playbooks"][0]
    bad_ref = PlaybookRef(
        playbook_id=playbook["playbook_id"],
        release_id=staged.release_id,
        release_version=staged.release_version,
        content_hash="0" * 64,
        bundle_content_hash=staged.content_hash,
        revision=staged.revision,
    )
    with pytest.raises(ValidationError, match="content hash mismatch"):
        await release_service.resolve_playbook_ref(bad_ref)


@pytest.mark.asyncio
async def test_retired_release_still_resolves_historically(
    session_factory: async_sessionmaker[AsyncSession],
    release_service: PlaybookReleaseService,
) -> None:
    await _clean(session_factory)
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance(
        source_path=str(DATA_FILE),
        imported_by="test",
        import_kind="playbook_bundle",
    )
    v1 = await release_service.stage_playbook_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    await release_service.activate_release(v1.release_id)
    playbook = bundle["playbooks"][0]
    ref = PlaybookRef(
        playbook_id=playbook["playbook_id"],
        release_id=v1.release_id,
        release_version=v1.release_version,
        content_hash=compute_playbook_object_hash(playbook),
        bundle_content_hash=v1.content_hash,
        revision=v1.revision,
    )

    v2 = await release_service.stage_playbook_bundle(
        bundle,
        release_version="v2",
        provenance=provenance,
        revision=2,
        supersedes_release_id=v1.release_id,
    )
    await release_service.activate_release(v2.release_id)

    resolved, release = await release_service.resolve_playbook_ref(ref, allow_retired=True)
    assert resolved.playbook_id == playbook["playbook_id"]
    assert release.lifecycle_state.value == "retired"


def test_approval_binding_invalidates_on_fingerprint_change() -> None:
    from app.models.action import Action
    from app.models.enums import ActionCategory, ActionLevel, ExecutionOwner
    from app.models.playbook_release import PlaybookActionTemplateSnapshot, PlaybookRef

    ref = PlaybookRef(
        playbook_id="pb-a1b2c3d4",
        release_id="krel-abc",
        release_version="v1",
        content_hash="a" * 64,
        bundle_content_hash="b" * 64,
    )
    snapshot = PlaybookActionTemplateSnapshot(
        step_order=1,
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        action_name="Block IP",
        template_hash="c" * 64,
    )
    action = Action(
        action_id="act-001",
        event_id="evt-001",
        plan_revision=1,
        action_fingerprint="fp-original",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        playbook_ref=ref,
        action_template_snapshot=snapshot,
    )
    detail = build_approval_binding_detail(action)
    mutated = action.model_copy(update={"action_fingerprint": "fp-changed"})
    with pytest.raises(ValidationError, match="fingerprint changed"):
        validate_approval_binding(mutated, detail)


def test_approval_binding_invalidates_on_plan_revision_change() -> None:
    from app.models.action import Action
    from app.models.enums import ActionCategory, ActionLevel, ExecutionOwner
    from app.models.playbook_release import PlaybookActionTemplateSnapshot, PlaybookRef

    ref = PlaybookRef(
        playbook_id="pb-a1b2c3d4",
        release_id="krel-abc",
        release_version="v1",
        content_hash="a" * 64,
        bundle_content_hash="b" * 64,
    )
    snapshot = PlaybookActionTemplateSnapshot(
        step_order=1,
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        action_name="Block IP",
        template_hash="c" * 64,
    )
    action = Action(
        action_id="act-001",
        event_id="evt-001",
        plan_revision=1,
        action_fingerprint="fp-original",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        playbook_ref=ref,
        action_template_snapshot=snapshot,
    )
    detail = build_approval_binding_detail(action)
    mutated = action.model_copy(update={"plan_revision": 2})
    with pytest.raises(ValidationError, match="plan revision changed"):
        validate_approval_binding(mutated, detail)


def test_approval_binding_invalidates_on_playbook_hash_change() -> None:
    from app.models.action import Action
    from app.models.enums import ActionCategory, ActionLevel, ExecutionOwner
    from app.models.playbook_release import PlaybookActionTemplateSnapshot, PlaybookRef

    ref = PlaybookRef(
        playbook_id="pb-a1b2c3d4",
        release_id="krel-abc",
        release_version="v1",
        content_hash="a" * 64,
        bundle_content_hash="b" * 64,
    )
    snapshot = PlaybookActionTemplateSnapshot(
        step_order=1,
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        action_name="Block IP",
        template_hash="c" * 64,
    )
    action = Action(
        action_id="act-001",
        event_id="evt-001",
        plan_revision=1,
        action_fingerprint="fp-original",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        playbook_ref=ref,
        action_template_snapshot=snapshot,
    )
    detail = build_approval_binding_detail(action)
    mutated_ref = ref.model_copy(update={"content_hash": "d" * 64})
    mutated = action.model_copy(update={"playbook_ref": mutated_ref})
    with pytest.raises(ValidationError, match="playbook binding changed"):
        validate_approval_binding(mutated, detail)


def test_approval_binding_requires_detail_for_playbook_pinned_action() -> None:
    from app.models.action import Action
    from app.models.enums import ActionCategory, ActionLevel, ExecutionOwner
    from app.models.playbook_release import PlaybookRef

    action = Action(
        action_id="act-001",
        event_id="evt-001",
        plan_revision=1,
        action_fingerprint="fp-original",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        playbook_ref=PlaybookRef(
            playbook_id="pb-a1b2c3d4",
            release_id="krel-abc",
            release_version="v1",
            content_hash="a" * 64,
            bundle_content_hash="b" * 64,
        ),
    )
    with pytest.raises(ValidationError, match="binding missing"):
        validate_approval_binding(action, None)


def test_approval_binding_invalidates_on_policy_version_change() -> None:
    from app.models.action import Action
    from app.models.enums import ActionCategory, ActionLevel, ExecutionOwner
    from app.models.playbook_release import PlaybookActionTemplateSnapshot, PlaybookRef

    ref = PlaybookRef(
        playbook_id="pb-a1b2c3d4",
        release_id="krel-abc",
        release_version="v1",
        content_hash="a" * 64,
        bundle_content_hash="b" * 64,
    )
    snapshot = PlaybookActionTemplateSnapshot(
        step_order=1,
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        action_name="Block IP",
        template_hash="c" * 64,
    )
    action = Action(
        action_id="act-001",
        event_id="evt-001",
        plan_revision=1,
        action_fingerprint="fp-original",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        playbook_ref=ref,
        action_template_snapshot=snapshot,
    )
    detail = build_approval_binding_detail(action)
    detail["policy_version"] = "stale-policy-v0"
    with pytest.raises(ValidationError, match="policy version changed"):
        validate_approval_binding(action, detail)


@pytest.mark.asyncio
async def test_resolve_playbook_ref_rejects_retired_when_not_allowed(
    session_factory: async_sessionmaker[AsyncSession],
    release_service: PlaybookReleaseService,
) -> None:
    await _clean(session_factory)
    bundle = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    provenance = KnowledgeReleaseProvenance(
        source_path=str(DATA_FILE),
        imported_by="test",
        import_kind="playbook_bundle",
    )
    v1 = await release_service.stage_playbook_bundle(
        bundle,
        release_version="v1",
        provenance=provenance,
    )
    await release_service.activate_release(v1.release_id)
    playbook = bundle["playbooks"][0]
    ref = PlaybookRef(
        playbook_id=playbook["playbook_id"],
        release_id=v1.release_id,
        release_version=v1.release_version,
        content_hash=compute_playbook_object_hash(playbook),
        bundle_content_hash=v1.content_hash,
        revision=v1.revision,
    )

    v2 = await release_service.stage_playbook_bundle(
        bundle,
        release_version="v2",
        provenance=provenance,
        revision=2,
        supersedes_release_id=v1.release_id,
    )
    await release_service.activate_release(v2.release_id)

    with pytest.raises(ValidationError, match="release retired"):
        await release_service.resolve_playbook_ref(ref, allow_retired=False)


def test_build_action_template_snapshot_enforces_byte_budget() -> None:
    from app.models.enums import ActionLevel
    from app.models.playbook import PlaybookStep
    from app.services.playbook_release_resolver import build_action_template_snapshot

    step = PlaybookStep(
        step_order=1,
        action_name="x" * 3000,
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        precondition="",
        expected_outcome="",
        required_capabilities=["entity_response"],
    )
    with pytest.raises(ValueError, match="byte budget"):
        build_action_template_snapshot(step)


def test_compute_playbook_binding_hash_stable() -> None:
    from app.models.enums import ActionLevel
    from app.models.playbook_release import PlaybookActionTemplateSnapshot, PlaybookRef

    ref = PlaybookRef(
        playbook_id="pb-a1b2c3d4",
        release_id="krel-abc",
        release_version="v1",
        content_hash="a" * 64,
        bundle_content_hash="b" * 64,
    )
    snapshot = PlaybookActionTemplateSnapshot(
        step_order=1,
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        action_name="Block IP",
        template_hash="c" * 64,
    )
    h1 = compute_playbook_binding_hash(playbook_ref=ref, template_snapshot=snapshot)
    h2 = compute_playbook_binding_hash(playbook_ref=ref, template_snapshot=snapshot)
    assert h1 == h2
    assert h1 != compute_playbook_binding_hash(playbook_ref=ref, template_snapshot=None)
