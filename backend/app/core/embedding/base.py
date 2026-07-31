"""Embedding provider errors and protocols (ISSUE-140)."""

from __future__ import annotations

from typing import Protocol

from app.core.errors import ShadowTraceError
from app.models.embedding import EmbeddingRelease


class EmbeddingError(ShadowTraceError):
    default_error_code = "embedding_provider_error"


class EmbeddingCompatibilityError(EmbeddingError):
    default_error_code = "embedding_compatibility_error"


class EmbeddingUnavailableError(EmbeddingError):
    default_error_code = "embedding_provider_unavailable"


class EmbeddingPrefilterError(EmbeddingError):
    default_error_code = "embedding_prefilter_required"


class BaseEmbeddingProvider(Protocol):
    """Process-local embedding backend bound to one ``EmbeddingRelease``."""

    @property
    def release(self) -> EmbeddingRelease: ...

    async def embed_texts(self, texts: list[str]) -> list[list[float]]: ...

    async def health_check(self) -> tuple[str, str | None]:
        """Return (status, error_code) where status is ok|degraded|error."""
        ...
