"""Deterministic id/hash builders for KnowledgeRelease (ISSUE-128 / #634)."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from app.models.knowledge_release import (
    ATTACK_CORPUS_ID,
    ATTACK_SOURCE_ID,
    KNOWLEDGE_RELEASE_SCHEMA_VERSION,
    KnowledgeImportStatus,
    KnowledgeRelease,
    KnowledgeReleaseLifecycleState,
    KnowledgeReleaseProvenance,
)


def canonical_json_bytes(value: Any) -> bytes:
    """Stable UTF-8 JSON bytes for content hashing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_bundle_content_hash(bundle: dict[str, Any]) -> str:
    """SHA-256 hex digest of canonical bundle JSON."""
    return hashlib.sha256(canonical_json_bytes(bundle)).hexdigest()


def compute_object_hash(stix_object: dict[str, Any]) -> str:
    """SHA-256 hex digest of one STIX object."""
    return hashlib.sha256(canonical_json_bytes(stix_object)).hexdigest()


def build_release_id(content_hash: str) -> str:
    return f"krel-{content_hash[:16]}"


def build_idempotency_key(*, corpus_id: str, content_hash: str) -> str:
    return f"{corpus_id}:{content_hash}"


def build_stix_object_id(technique_id: str) -> str:
    """Deterministic STIX id for an ATT&CK technique external id."""
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    return f"attack-pattern--{uuid.uuid5(namespace, technique_id)}"


def build_knowledge_release(
    *,
    corpus_id: str,
    source_id: str,
    release_version: str,
    content_hash: str,
    provenance: KnowledgeReleaseProvenance,
    object_count: int,
    relationship_count: int,
    revision: int = 1,
    supersedes_release_id: str | None = None,
    lifecycle_state: KnowledgeReleaseLifecycleState = KnowledgeReleaseLifecycleState.STAGED,
    import_status: KnowledgeImportStatus = KnowledgeImportStatus.VALIDATED,
    vector_ready: bool = False,
    embedding_release_id: str | None = None,
) -> KnowledgeRelease:
    release_id = build_release_id(content_hash)
    return KnowledgeRelease(
        release_id=release_id,
        corpus_id=corpus_id,
        source_id=source_id,
        release_version=release_version,
        content_hash=content_hash,
        provenance=provenance,
        schema_version=KNOWLEDGE_RELEASE_SCHEMA_VERSION,
        import_status=import_status,
        lifecycle_state=lifecycle_state,
        revision=revision,
        supersedes_release_id=supersedes_release_id,
        object_count=object_count,
        relationship_count=relationship_count,
        vector_ready=vector_ready,
        embedding_release_id=embedding_release_id,
        idempotency_key=build_idempotency_key(corpus_id=corpus_id, content_hash=content_hash),
    )


def default_attack_provenance(source_path: str) -> KnowledgeReleaseProvenance:
    return KnowledgeReleaseProvenance(
        source_path=source_path,
        imported_by="attack_stix_importer",
        import_kind="stix_bundle",
    )


def corpus_to_kb_name(corpus_id: str) -> str | None:
    if corpus_id == ATTACK_CORPUS_ID:
        return "attack_kb"
    return None


def kb_name_to_corpus(kb_name: str) -> str | None:
    if kb_name == "attack_kb":
        return ATTACK_CORPUS_ID
    return None


__all__ = [
    "build_idempotency_key",
    "build_knowledge_release",
    "build_release_id",
    "build_stix_object_id",
    "canonical_json_bytes",
    "compute_bundle_content_hash",
    "compute_object_hash",
    "corpus_to_kb_name",
    "default_attack_provenance",
    "kb_name_to_corpus",
]
