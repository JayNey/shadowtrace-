"""Socket.IO event handlers and room management (ISSUE-040).

Connect/disconnect/subscribe handlers registered on ``socketio.AsyncServer``
for the ``/events`` namespace.

Naming
------
* Namespace: ``/events``
* Rooms: ``global`` (every connected client), ``event:{event_id}`` (per-event)
"""

from __future__ import annotations

import logging
from typing import Any

import socketio

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SOCKETIO_NAMESPACE = "/events"
GLOBAL_ROOM = "global"
EVENT_ROOM_PREFIX = "event:"


def _event_room(event_id: str) -> str:
    """Return the per-event room name for *event_id*."""
    return f"{EVENT_ROOM_PREFIX}{event_id}"


# ---------------------------------------------------------------------------
# Handler registration
# ---------------------------------------------------------------------------


def register_handlers(sio: socketio.AsyncServer) -> None:
    """Register connect, disconnect, and subscribe handlers on *sio*.

    Call once during application startup, before any client connections.
    """

    @sio.event(namespace=SOCKETIO_NAMESPACE)  # type: ignore[untyped-decorator]
    async def connect(  # noqa: ARG001
        sid: str,
        environ: dict[str, Any],
        auth: dict[str, Any] | None = None,
    ) -> None:
        """Auto-join every connected client to the global room."""
        await sio.enter_room(sid, GLOBAL_ROOM, namespace=SOCKETIO_NAMESPACE)
        logger.debug("socketio connect sid=%s → room=%s", sid, GLOBAL_ROOM)

    @sio.event(namespace=SOCKETIO_NAMESPACE)  # type: ignore[untyped-decorator]
    async def disconnect(sid: str, reason: str | None = None) -> None:  # noqa: ARG001
        """Log client disconnection.

        Room membership is cleaned up automatically by the python-socketio
        engine on disconnect — no explicit ``leave_room`` calls needed here.
        """
        logger.debug("socketio disconnect sid=%s reason=%s", sid, reason)

    @sio.event(namespace=SOCKETIO_NAMESPACE)  # type: ignore[untyped-decorator]
    async def subscribe(sid: str, data: dict[str, Any]) -> None:
        """Client requests to follow a specific event.

        Expected payload: ``{"event_id": "evt-..."}``
        """
        event_id = data.get("event_id") if isinstance(data, dict) else None
        if not event_id or not isinstance(event_id, str):
            logger.warning(
                "socketio subscribe rejected sid=%s — missing or invalid event_id",
                sid,
            )
            await sio.emit(
                "error",
                {"message": "subscribe requires a valid event_id string"},
                to=sid,
                namespace=SOCKETIO_NAMESPACE,
            )
            return

        room = _event_room(event_id)
        # Detail subscribers leave the global room so they receive each event
        # once via the per-event room (dashboard clients remain global-only).
        await sio.leave_room(sid, GLOBAL_ROOM, namespace=SOCKETIO_NAMESPACE)
        await sio.enter_room(sid, room, namespace=SOCKETIO_NAMESPACE)
        logger.debug("socketio subscribe sid=%s → room=%s (left %s)", sid, room, GLOBAL_ROOM)


__all__ = [
    "GLOBAL_ROOM",
    "SOCKETIO_NAMESPACE",
    "_event_room",
    "register_handlers",
]
