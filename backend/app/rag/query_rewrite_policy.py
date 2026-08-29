"""Decide when RAG query rewriting is skipped.

Structured investigator queries already carry event type and labeled entities.
Calling an LLM rewriter on those strings adds latency without improving FTS.
"""

from __future__ import annotations

import re

from app.services.org_context_matcher import OrgContextFacts

_STRUCTURED_MARKERS = re.compile(
    r"(?i)(?:event\s+type\s*:?|(?:host|ip|domain|account)\s*:)",
)


def should_skip_query_rewrite(
    query: str,
    *,
    facts: OrgContextFacts | None = None,
    force: bool = False,
) -> bool:
    """True when the query text is already structured enough for hybrid search.

    Ambient ``OrgContextFacts`` on the retrieval context do not skip rewrite;
    only the query string (or an explicit force) does.
    """
    if force:
        return True
    _ = facts
    return bool(_STRUCTURED_MARKERS.search(query or ""))
