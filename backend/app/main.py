"""ShadowTrace FastAPI application entrypoint."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.v1 import api_router
from app.api.v1.errors import register_exception_handlers
from app.api.v1.health import shutdown_health_clients
from app.core.config import get_settings
from app.core.redis_client import RedisClient
from app.core.socketio_manager import SocketIOManager

# ---------------------------------------------------------------------------
# Lazy infrastructure singletons (connections established on first use)
# ---------------------------------------------------------------------------

_redis = RedisClient()
_socketio_manager = SocketIOManager(_redis)


# ---------------------------------------------------------------------------
# Application factory + lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(application: FastAPI) -> AsyncIterator[None]:
    # Fail-closed (ISSUE-093 §5): validate runtime settings BEFORE serving any
    # traffic. Settings construction raises ConfigurationError if app_env is
    # production and any mock/simulation mode is active.
    get_settings()

    # Start the Redis→Socket.IO bridge background task.
    await _socketio_manager.start()

    yield

    # Graceful shutdown.
    await _socketio_manager.stop()
    await shutdown_health_clients()


app = FastAPI(title="ShadowTrace", version="0.1.0", lifespan=_lifespan)
register_exception_handlers(app)
app.include_router(api_router, prefix="/api/v1")

# ---------------------------------------------------------------------------
# Socket.IO wrapper — uvicorn / Docker must target ``socket_app``, not ``app``.
# ``app`` is kept as the inner FastAPI instance so that ``app.openapi()``,
# TestClient, and scripts that import ``from app.main import app`` continue to
# work unchanged.
# ---------------------------------------------------------------------------

socket_app = _socketio_manager.mount(app)
