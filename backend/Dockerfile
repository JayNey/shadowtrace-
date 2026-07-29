# ---------------------------------------------------------------------------
# ShadowTrace backend — multi-stage production image (ISSUE-088)
#
# Build context: project root (scripts/, data/, contracts/ accessible).
#   docker build -f backend/Dockerfile .
#
# Runtime layout matches main (/app flat app tree + /contracts) so Socket.IO
# schema resolution and alembic entrypoint stay compatible with ISSUE-077.
# Nested /app/backend/ is also present for bootstrap CLI scripts.
# ---------------------------------------------------------------------------

ARG PYTHON_VERSION=3.11

FROM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml backend/alembic.ini ./
COPY backend/app ./app
COPY backend/migrations ./migrations
COPY backend/docker-entrypoint.sh /docker-entrypoint.sh
COPY contracts /contracts
# Nested tree for scripts/generate_mock_data.py path resolution.
COPY backend/ ./backend/
COPY scripts/ ./scripts/
COPY data/ ./data/

RUN chmod +x /docker-entrypoint.sh \
    && pip install --no-cache-dir -e .

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------

FROM python:${PYTHON_VERSION}-slim

ARG PYTHON_VERSION

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python${PYTHON_VERSION}/site-packages \
    /usr/local/lib/python${PYTHON_VERSION}/site-packages
COPY --from=builder /app /app
COPY --from=builder /docker-entrypoint.sh /docker-entrypoint.sh

RUN groupadd -r shadowtrace && useradd -r -g shadowtrace shadowtrace \
    && chown -R shadowtrace:shadowtrace /app
USER shadowtrace

EXPOSE 8000

ENTRYPOINT ["/docker-entrypoint.sh"]
# Multi-worker uvicorn; python -m because site-packages only (no /usr/local/bin).
CMD ["python", "-m", "uvicorn", "app.main:socket_app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--log-level", "info"]
