"""OpenAI-compatible remote embedding provider (ISSUE-140)."""

from __future__ import annotations

import time

import httpx

from app.core.config import Settings
from app.core.embedding.base import EmbeddingCompatibilityError, EmbeddingUnavailableError
from app.core.embedding.compat import validate_vector_dimension
from app.core.embedding.release import build_embedding_release
from app.models.embedding import EmbeddingRelease


class RemoteEmbedder:
    """Production/local embedding via OpenAI-compatible ``/v1/embeddings``."""

    def __init__(self, settings: Settings, *, release: EmbeddingRelease | None = None) -> None:
        self._settings = settings
        self._release = release or build_embedding_release(settings)
        self._http: httpx.AsyncClient | None = None
        self._base_url = settings.embedding_api_base_url.rstrip("/")
        self._api_key = settings.embedding_api_key
        self._timeout = settings.embedding_timeout_seconds

    @property
    def release(self) -> EmbeddingRelease:
        return self._release

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None:
            if not self._base_url:
                raise EmbeddingUnavailableError(
                    message="embedding API base URL is not configured",
                    error_code="embedding_provider_unavailable",
                    details={"mode": self._release.provider_mode.value},
                )
            headers: dict[str, str] = {}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
            self._http = httpx.AsyncClient(base_url=self._base_url, headers=headers)
        return self._http

    async def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        http = await self._get_http()
        started = time.perf_counter()
        try:
            resp = await http.post(
                "/v1/embeddings",
                json={"input": texts, "model": self._settings.embedding_model_id.strip()},
                timeout=self._timeout,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise EmbeddingUnavailableError(
                message="embedding provider request failed",
                error_code="embedding_provider_unavailable",
                details={
                    "mode": self._release.provider_mode.value,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                },
            ) from exc
        data = resp.json()
        vectors: list[list[float]] = []
        for item in data.get("data", []):
            vec = item.get("embedding")
            if not isinstance(vec, list):
                raise EmbeddingCompatibilityError(
                    message="embedding provider returned invalid vector payload",
                    error_code="embedding_provider_error",
                )
            validate_vector_dimension(
                vec,
                expected_dimension=self._release.dimension,
                context="remote_embedding",
            )
            vectors.append(vec)
        if len(vectors) != len(texts):
            raise EmbeddingCompatibilityError(
                message="embedding provider returned unexpected batch size",
                error_code="embedding_provider_error",
                details={"expected": len(texts), "actual": len(vectors)},
            )
        return vectors

    async def health_check(self) -> tuple[str, str | None]:
        if not self._base_url:
            return "error", "embedding_provider_unavailable"
        if self._release.provider_mode.value != "mock" and not self._api_key:
            return "degraded", "embedding_provider_unavailable"
        try:
            await self.embed(["health probe"])
            return "ok", None
        except EmbeddingUnavailableError:
            return "error", "embedding_provider_unavailable"
        except EmbeddingCompatibilityError:
            return "error", "embedding_compatibility_error"

    async def close(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None
