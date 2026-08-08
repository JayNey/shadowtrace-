"""Authentication principal and RBAC dependencies (ISSUE-004).

Identity is always established server-side. Two mechanisms are supported:

1. A trusted reverse proxy: only when ``TRUSTED_AUTH_PROXY_ENABLED`` is on AND the
   direct client address is in ``TRUSTED_PROXY_ALLOWLIST`` are the identity headers
   (``X-Auth-Subject`` / ``X-Auth-Roles``) honored. Unknown role names are dropped
   (ISSUE-180); production rejects empty or wildcard allowlists at startup.
2. Development tokens: ``DEV_AUTH_TOKENS`` maps a bearer token to a fixed
   Principal, and is rejected outright in production (``APP_ENV=production``).

The client request body can NEVER specify the operator/principal — services must
audit using ``Principal.subject`` derived here.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from typing import Annotated, Any

from fastapi import Depends, Request
from pydantic import BaseModel, Field

from app.core.config import get_settings

ROLE_ANALYST = "analyst"
ROLE_APPROVER = "approver"
ROLE_DISPOSITION_OPERATOR = "disposition_operator"
ROLE_ADMIN = "admin"

ALL_ROLES = frozenset({ROLE_ANALYST, ROLE_APPROVER, ROLE_DISPOSITION_OPERATOR, ROLE_ADMIN})

# Roles permitted to receive SOC / dashboard global Socket.IO broadcasts (ISSUE-258).
GLOBAL_BROADCAST_ROLES = (
    ROLE_ANALYST,
    ROLE_APPROVER,
    ROLE_DISPOSITION_OPERATOR,
    ROLE_ADMIN,
)


class Principal(BaseModel):
    """Authenticated caller identity."""

    subject: str
    display_name: str = ""
    roles: list[str] = Field(default_factory=list)
    tenant_id: str | None = None

    def has_any_role(self, roles: Iterable[str]) -> bool:
        wanted = set(roles)
        return bool(wanted & set(self.roles)) or ROLE_ADMIN in self.roles


class AuthenticationError(Exception):
    """Raised when no valid principal can be established (maps to 401)."""


class AuthorizationError(Exception):
    """Raised when the principal lacks a required role (maps to 403)."""

    def __init__(self, required: Iterable[str]) -> None:
        self.required = sorted(set(required))
        super().__init__(f"requires one of roles: {', '.join(self.required)}")


def _is_production() -> bool:
    return get_settings().is_production()


def _dev_token_registry() -> dict[str, Principal]:
    """Parse ``DEV_AUTH_TOKENS`` JSON into token -> Principal (dev only)."""
    raw = os.environ.get("DEV_AUTH_TOKENS", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    registry: dict[str, Principal] = {}
    for token, spec in data.items():
        registry[token] = Principal(
            subject=spec.get("subject", token),
            display_name=spec.get("display_name", ""),
            roles=list(spec.get("roles", [])),
            tenant_id=spec.get("tenant_id"),
        )
    return registry


def _filter_known_roles(roles: list[str]) -> list[str]:
    """Drop unknown role names from trusted-proxy headers (ISSUE-180).

    Role names are normalized to lowercase before matching ``ALL_ROLES``.
    """
    known: list[str] = []
    for role in roles:
        normalized = role.lower()
        if normalized in ALL_ROLES:
            known.append(normalized)
    return known


def _proxy_allowlist() -> set[str]:
    return set(get_settings().trusted_proxy_allowlist_hosts())


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return a lowercase-key header map for shared REST / Socket.IO resolution."""
    return {key.lower(): value for key, value in headers.items()}


def _header(headers: Mapping[str, str], name: str, default: str = "") -> str:
    value = headers.get(name.lower(), default)
    return value if isinstance(value, str) else default


def _principal_from_trusted_proxy_headers(
    headers: Mapping[str, str],
    client_host: str,
) -> Principal | None:
    settings = get_settings()
    if not settings.trusted_auth_proxy_enabled:
        return None
    if client_host not in _proxy_allowlist():
        return None
    subject = _header(headers, "X-Auth-Subject")
    if not subject:
        return None
    roles_header = _header(headers, "X-Auth-Roles")
    roles = _filter_known_roles([r.strip() for r in roles_header.split(",") if r.strip()])
    tenant_raw = _header(headers, "X-Auth-Tenant-Id")
    tenant_id = tenant_raw.strip() if tenant_raw.strip() else None
    return Principal(
        subject=subject,
        display_name=_header(headers, "X-Auth-Display-Name"),
        roles=roles,
        tenant_id=tenant_id,
    )


def _principal_from_dev_token_headers(headers: Mapping[str, str]) -> Principal | None:
    if _is_production():
        return None  # dev identities are rejected in production
    auth = _header(headers, "Authorization")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth[len("bearer ") :].strip()
    return _dev_token_registry().get(token)


def resolve_principal(
    *,
    headers: Mapping[str, str],
    client_host: str = "",
) -> Principal:
    """Resolve an authenticated principal or raise ``AuthenticationError``.

    Shared by REST dependencies and the Socket.IO handshake (ISSUE-258).
    """
    normalized = _normalize_headers(headers)
    principal = _principal_from_trusted_proxy_headers(
        normalized,
        client_host,
    ) or _principal_from_dev_token_headers(normalized)
    if principal is None:
        raise AuthenticationError("no valid credentials")
    return principal


def can_join_global_broadcast(principal: Principal) -> bool:
    """Return whether *principal* may enter the Socket.IO ``global`` room."""
    return principal.has_any_role(GLOBAL_BROADCAST_ROLES)


def headers_from_socketio_environ(
    environ: Mapping[str, Any],
    auth: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Build HTTP-style headers from an Engine.IO environ + optional auth payload."""
    headers: dict[str, str] = {}
    for key, value in environ.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        if key.startswith("HTTP_"):
            header_name = "-".join(part.capitalize() for part in key[5:].split("_"))
            headers[header_name] = value

    scope = environ.get("asgi.scope") or environ.get("scope")
    if isinstance(scope, dict):
        raw_headers = scope.get("headers")
        if isinstance(raw_headers, list):
            for item in raw_headers:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    continue
                name_raw, value_raw = item
                name = name_raw.decode("latin-1") if isinstance(name_raw, bytes) else str(name_raw)
                value = (
                    value_raw.decode("latin-1") if isinstance(value_raw, bytes) else str(value_raw)
                )
                headers[name] = value

    if isinstance(auth, dict):
        token = auth.get("token")
        if isinstance(token, str) and token.strip():
            headers.setdefault("Authorization", f"Bearer {token.strip()}")

    return headers


def client_host_from_socketio_environ(environ: Mapping[str, Any]) -> str:
    """Best-effort client address for trusted-proxy auth at the Socket.IO handshake."""
    forwarded = environ.get("HTTP_X_FORWARDED_FOR")
    if isinstance(forwarded, str) and forwarded.strip():
        return forwarded.split(",")[0].strip()
    remote = environ.get("REMOTE_ADDR")
    return remote if isinstance(remote, str) else ""


def resolve_principal_from_socketio_handshake(
    environ: Mapping[str, Any],
    auth: dict[str, Any] | None = None,
) -> Principal:
    """Resolve principal from a Socket.IO connect handshake."""
    headers = headers_from_socketio_environ(environ, auth)
    client_host = client_host_from_socketio_environ(environ)
    return resolve_principal(headers=headers, client_host=client_host)


def authorization_fingerprint(headers: Mapping[str, str]) -> str | None:
    """Stable fingerprint for re-validating bearer-token sessions."""
    auth = _header(_normalize_headers(headers), "Authorization")
    return auth.strip() if auth.strip() else None


async def get_principal(request: Request) -> Principal:
    """Resolve the authenticated principal or raise ``AuthenticationError``."""
    client_host = request.client.host if request.client else ""
    return resolve_principal(headers=request.headers, client_host=client_host)


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def require_roles(*roles: str) -> object:
    """Return a dependency enforcing that the principal has one of ``roles``.

    ``admin`` always satisfies the check (see ``Principal.has_any_role``).
    """

    async def _dep(principal: CurrentPrincipal) -> Principal:
        if not principal.has_any_role(roles):
            raise AuthorizationError(roles)
        return principal

    return Depends(_dep)
