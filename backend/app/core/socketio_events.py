"""Socket.IO event handlers and room management (ISSUE-040 / ISSUE-258).

Connect/disconnect/subscribe handlers registered on ``socketio.AsyncServer``
for the ``/events`` namespace.  Handshake authentication reuses REST
``Principal`` resolution; room membership is granted only after auth and
resource checks succeed (fail-closed).

Naming
------
* Namespace: ``/events``
* Rooms: ``global`` (SOC/dashboard clients), ``event:{event_id}`` (per-event)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import socketio

from app.core.auth import (
    AuthenticationError,
    Principal,
    authorization_fingerprint,
    can_join_global_broadcast,
    headers_from_socketio_environ,
    resolve_principal,
    resolve_principal_from_socketio_handshake,
)

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
# Session registry (SID → Principal / rooms)
# ---------------------------------------------------------------------------


@dataclass
class _SocketSession:
    principal: Principal
    auth_fingerprint: str | None
    rooms: set[str] = field(default_factory=set)


class SocketIOSessionRegistry:
    """Track authenticated Socket.IO sessions for authz and cleanup (ISSUE-258)."""

    def __init__(self) -> None:
        self._sessions: dict[str, _SocketSession] = {}

    def register(
        self,
        sid: str,
        principal: Principal,
        auth_fingerprint: str | None,
    ) -> None:
        self._sessions[sid] = _SocketSession(
            principal=principal,
            auth_fingerprint=auth_fingerprint,
        )

    def remove(self, sid: str) -> None:
        self._sessions.pop(sid, None)

    def get(self, sid: str) -> _SocketSession | None:
        return self._sessions.get(sid)

    def track_room(self, sid: str, room: str) -> None:
        session = self._sessions.get(sid)
        if session is not None:
            session.rooms.add(room)

    def untrack_room(self, sid: str, room: str) -> None:
        session = self._sessions.get(sid)
        if session is not None:
            session.rooms.discard(room)

    def clear_rooms(self, sid: str) -> None:
        session = self._sessions.get(sid)
        if session is not None:
            session.rooms.clear()


def _session_still_valid(session: _SocketSession) -> bool:
    """Re-check bearer credentials; trusted-proxy sessions stay valid until disconnect."""
    if not session.auth_fingerprint:
        return True
    try:
        resolve_principal(
            headers={"Authorization": session.auth_fingerprint},
            client_host="",
        )
    except AuthenticationError:
        return False
    else:
        return True


async def _event_readable(event_id: str) -> bool:
    """Return whether the event exists (mirrors REST ``GET /events/{id}`` gate)."""
    try:
        from app.api.v1.deps import get_event_service

        event_service = await get_event_service()
        event = await event_service.get_event(event_id)
    except Exception:
        logger.warning(
            "socketio event lookup failed event_id=%s",
            event_id,
            exc_info=True,
        )
        return False
    return event is not None


async def _emit_auth_error(
    sio: socketio.AsyncServer,
    sid: str,
    message: str,
    *,
    disconnect: bool = False,
) -> None:
    await sio.emit(
        "error",
        {"message": message},
        to=sid,
        namespace=SOCKETIO_NAMESPACE,
    )
    if disconnect:
        await sio.disconnect(sid, namespace=SOCKETIO_NAMESPACE)


async def _require_session(
    sio: socketio.AsyncServer,
    sid: str,
    sessions: SocketIOSessionRegistry,
) -> _SocketSession | None:
    session = sessions.get(sid)
    if session is None:
        await _emit_auth_error(sio, sid, "session not authenticated", disconnect=True)
        return None
    if not _session_still_valid(session):
        sessions.remove(sid)
        await _emit_auth_error(sio, sid, "session expired or revoked", disconnect=True)
        return None
    return session


# ---------------------------------------------------------------------------
# Handler registration
# ---------------------------------------------------------------------------


def register_handlers(
    sio: socketio.AsyncServer,
    *,
    sessions: SocketIOSessionRegistry,
) -> None:
    """Register connect, disconnect, and subscribe handlers on *sio*.

    Call once during application startup, before any client connections.
    """

    @sio.event(namespace=SOCKETIO_NAMESPACE)  # type: ignore[untyped-decorator]
    async def connect(
        sid: str,
        environ: dict[str, Any],
        auth: dict[str, Any] | None = None,
    ) -> bool:
        """Authenticate at handshake; join ``global`` only for authorized roles."""
        try:
            principal = resolve_principal_from_socketio_handshake(environ, auth)
        except AuthenticationError:
            logger.info("socketio connect rejected sid=%s — unauthenticated", sid)
            return False

        fingerprint = authorization_fingerprint(headers_from_socketio_environ(environ, auth))
        sessions.register(sid, principal, fingerprint)

        if can_join_global_broadcast(principal):
            await sio.enter_room(sid, GLOBAL_ROOM, namespace=SOCKETIO_NAMESPACE)
            sessions.track_room(sid, GLOBAL_ROOM)
            logger.debug(
                "socketio connect sid=%s subject=%s → room=%s",
                sid,
                principal.subject,
                GLOBAL_ROOM,
            )
        else:
            logger.debug(
                "socketio connect sid=%s subject=%s — no global room (missing role)",
                sid,
                principal.subject,
            )
        return True

    @sio.event(namespace=SOCKETIO_NAMESPACE)  # type: ignore[untyped-decorator]
    async def disconnect(sid: str, reason: str | None = None) -> None:  # noqa: ARG001
        """Drop session state; Engine.IO removes room membership on disconnect."""
        sessions.remove(sid)
        logger.debug("socketio disconnect sid=%s reason=%s", sid, reason)

    @sio.event(namespace=SOCKETIO_NAMESPACE)  # type: ignore[untyped-decorator]
    async def subscribe(sid: str, data: dict[str, Any]) -> None:
        """Client requests to follow a specific event after resource authorization."""
        session = await _require_session(sio, sid, sessions)
        if session is None:
            return

        event_id = data.get("event_id") if isinstance(data, dict) else None
        if not event_id or not isinstance(event_id, str):
            logger.warning(
                "socketio subscribe rejected sid=%s — missing or invalid event_id",
                sid,
            )
            await _emit_auth_error(sio, sid, "subscribe requires a valid event_id string")
            return

        if not await _event_readable(event_id):
            logger.info(
                "socketio subscribe rejected sid=%s subject=%s event_id=%s — not found",
                sid,
                session.principal.subject,
                event_id,
            )
            await _emit_auth_error(sio, sid, "event not found or not accessible")
            return

        room = _event_room(event_id)
        await sio.leave_room(sid, GLOBAL_ROOM, namespace=SOCKETIO_NAMESPACE)
        sessions.untrack_room(sid, GLOBAL_ROOM)
        await sio.enter_room(sid, room, namespace=SOCKETIO_NAMESPACE)
        sessions.track_room(sid, room)
        logger.debug(
            "socketio subscribe sid=%s subject=%s → room=%s (left %s)",
            sid,
            session.principal.subject,
            room,
            GLOBAL_ROOM,
        )

    @sio.event(namespace=SOCKETIO_NAMESPACE)  # type: ignore[untyped-decorator]
    async def join_global(sid: str, data: dict[str, Any] | None = None) -> None:  # noqa: ARG001
        """Re-enter the global room when the principal has dashboard broadcast access."""
        session = await _require_session(sio, sid, sessions)
        if session is None:
            return

        if not can_join_global_broadcast(session.principal):
            logger.info(
                "socketio join_global rejected sid=%s subject=%s — missing role",
                sid,
                session.principal.subject,
            )
            await _emit_auth_error(sio, sid, "not authorized for global broadcasts")
            return

        try:
            rooms = sio.rooms(sid, namespace=SOCKETIO_NAMESPACE)
        except KeyError:
            rooms = []
        for room in list(rooms):
            if isinstance(room, str) and room.startswith(EVENT_ROOM_PREFIX):
                await sio.leave_room(sid, room, namespace=SOCKETIO_NAMESPACE)
                sessions.untrack_room(sid, room)
        await sio.enter_room(sid, GLOBAL_ROOM, namespace=SOCKETIO_NAMESPACE)
        sessions.track_room(sid, GLOBAL_ROOM)
        logger.debug(
            "socketio join_global sid=%s subject=%s → room=%s",
            sid,
            session.principal.subject,
            GLOBAL_ROOM,
        )


__all__ = [
    "GLOBAL_ROOM",
    "SOCKETIO_NAMESPACE",
    "SocketIOSessionRegistry",
    "_event_room",
    "register_handlers",
]
