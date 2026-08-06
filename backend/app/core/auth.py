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
from collections.abc import Iterable
from typing import Annotated

from fastapi import Depends, Request
from pydantic import BaseModel, Field

from app.core.config import get_settings

ROLE_ANALYST = "analyst"
ROLE_APPROVER = "approver"
ROLE_DISPOSITION_OPERATOR = "disposition_operator"
ROLE_ADMIN = "admin"

ALL_ROLES = frozenset({ROLE_ANALYST, ROLE_APPROVER, ROLE_DISPOSITION_OPERATOR, ROLE_ADMIN})


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
    # Strip surrounding whitespace exactly like config.Settings.production_fail_closed_violations
    # (ISSUE-217): APP_ENV=" production " must be treated as production so the dev-token
    # path stays closed instead of diverging from the fail-closed configuration gate.
    return get_settings().app_env.strip().lower() == "production"


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


def _principal_from_trusted_proxy(request: Request) -> Principal | None:
    settings = get_settings()
    if not settings.trusted_auth_proxy_enabled:
        return None
    client_host = request.client.host if request.client else ""
    if client_host not in _proxy_allowlist():
        return None
    subject = request.headers.get("X-Auth-Subject")
    if not subject:
        return None
    roles_header = request.headers.get("X-Auth-Roles", "")
    roles = _filter_known_roles([r.strip() for r in roles_header.split(",") if r.strip()])
    tenant_id = request.headers.get("X-Auth-Tenant-Id")
    tenant_id = tenant_id.strip() if isinstance(tenant_id, str) and tenant_id.strip() else None
    return Principal(
        subject=subject,
        display_name=request.headers.get("X-Auth-Display-Name", ""),
        roles=roles,
        tenant_id=tenant_id,
    )


def _principal_from_dev_token(request: Request) -> Principal | None:
    if _is_production():
        return None  # dev identities are rejected in production
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth[len("bearer ") :].strip()
    return _dev_token_registry().get(token)


async def get_principal(request: Request) -> Principal:
    """Resolve the authenticated principal or raise ``AuthenticationError``."""
    principal = _principal_from_trusted_proxy(request) or _principal_from_dev_token(request)
    if principal is None:
        raise AuthenticationError("no valid credentials")
    return principal


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
