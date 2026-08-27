"""Scoped knowledge_chunk cleanup for tests that share demo Postgres.

Gold / demo seeds live in ``org_context_kb`` (hashed ``chk-{8hex}`` ids) and
``attack_kb`` (``atk-*``). Tests that default ``DATABASE_URL`` to
``localhost:5432/shadowtrace`` must not ``DELETE FROM knowledge_chunk``.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.sql.elements import TextClause

# Prefixes used by unit fixtures. Org-context seed ids are chk-{8 hex} hashes
# that do not start with these tokens.
TEST_OWNED_CHUNK_DELETE: TextClause = text(
    """
    DELETE FROM knowledge_chunk
    WHERE chunk_id LIKE 'chk-0000%'
       OR chunk_id LIKE 'chk-tenant%'
       OR chunk_id LIKE 'chk-playbook%'
       OR chunk_id LIKE 'chk-global%'
       OR chunk_id LIKE 'chk-alpha%'
       OR chunk_id LIKE 'chk-beta%'
       OR chunk_id LIKE 'chk-fp-%'
       OR chunk_id LIKE 'chk-hist%'
       OR chunk_id LIKE 'chk-delegated%'
       OR chunk_id LIKE 'chk-org%'
    """
)

PRESERVE_ORG_CONTEXT_DELETE: TextClause = text(
    "DELETE FROM knowledge_chunk WHERE kb_name <> 'org_context_kb'"
)
