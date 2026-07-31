"""MockEmbedder: deterministic pseudo-random unit vectors from SHA-256 (ISSUE-140)."""

from __future__ import annotations

import hashlib
import math

from app.core.embedding.compat import validate_vector_dimension
from app.models.embedding import EmbeddingRelease, VectorNormalization

DEFAULT_EMBEDDING_DIM = 1024
EMBEDDING_DIM = DEFAULT_EMBEDDING_DIM

# Large primes for the pseudo-random projection
_PRIME_A = 2654435761
_PRIME_B = 2246822519
_PRIME_C = 3266489917
_PRIME_D = 668265263


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _pseudo_random_float(seed: int, index: int) -> float:
    """Deterministic pseudo-random float in [-1, 1) driven by seed + component index."""
    x = (seed + index * _PRIME_A) & 0xFFFFFFFF
    x = (x ^ (x >> 13)) * _PRIME_B
    x = (x ^ (x >> 16)) * _PRIME_C
    x = (x ^ (x >> 17)) * _PRIME_D
    return ((x & 0xFFFFFFFF) / 2147483648.0) - 1.0


class MockEmbedder:
    """Deterministic embedder: SHA-256(text) → seeded pseudo-random unit vector."""

    def __init__(self, *, release: EmbeddingRelease | None = None, dim: int | None = None) -> None:
        self._release = release
        self.dim = release.dimension if release is not None else (dim or DEFAULT_EMBEDDING_DIM)

    @property
    def release(self) -> EmbeddingRelease | None:
        return self._release

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Produce deterministic unit vectors for *texts*."""
        vectors: list[list[float]] = []
        for text in texts:
            digest = _sha256_hex(text)
            seed = int(digest[:8], 16)
            raw = [_pseudo_random_float(seed, i) for i in range(self.dim)]
            norm = math.sqrt(sum(v * v for v in raw))
            if norm == 0.0:
                vector = [0.0] * self.dim
            else:
                vector = [v / norm for v in raw]
            if (
                self._release is not None
                and self._release.normalization == VectorNormalization.UNIT_L2
            ):
                validate_vector_dimension(
                    vector,
                    expected_dimension=self._release.dimension,
                    context="mock_embed",
                )
            vectors.append(vector)
        return vectors
