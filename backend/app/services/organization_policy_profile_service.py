"""Organization policy profile persistence (ISSUE-129 / #635 Phase A)."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import and_, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.organization_policy_profile import (
    ORGANIZATION_POLICY_PROFILE_SCHEMA_VERSION,
    OrganizationPolicyProfile,
    OrganizationPolicyProfileUpsertRequest,
)


def new_profile_id() -> str:
    return f"opp-{secrets.token_hex(4)}"


def tenant_policy_profile_lock_key(tenant_id: str) -> int:
    material = f"organization_policy_profile|{tenant_id.strip()}".encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], byteorder="big", signed=True)


def _assert_authorized_tenant(
    *,
    tenant_id: str,
    authorized_tenant_id: str | None,
) -> None:
    if authorized_tenant_id is None:
        return
    normalized = tenant_id.strip()
    authorized = authorized_tenant_id.strip()
    if normalized != authorized:
        raise ValidationError(
            "cross-tenant policy profile access denied",
            details={
                "tenant_id": normalized,
                "authorized_tenant_id": authorized,
                "reason": "cross_tenant_denied",
            },
        )


def _row_to_profile(row: orm.OrganizationPolicyProfileORM) -> OrganizationPolicyProfile:
    return OrganizationPolicyProfile(
        schema_version=row.schema_version,
        profile_id=row.profile_id,
        tenant_id=row.tenant_id,
        revision=int(row.revision),
        owner_principal=row.owner_principal,
        framework_allowlist=tuple(row.framework_allowlist or ()),
        jurisdiction_codes=tuple(row.jurisdiction_codes or ()),
        industry_codes=tuple(row.industry_codes or ()),
        effective_at=row.effective_at,
        approved_by=row.approved_by,
        audit_note=row.audit_note,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class OrganizationPolicyProfileService:
    """Server-owned tenant applicability profiles with revision pinning."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_effective_profile(
        self,
        *,
        tenant_id: str,
        principal: str,
        authorized_tenant_id: str | None = None,
    ) -> OrganizationPolicyProfile | None:
        """Return the newest effective profile for a tenant."""
        normalized_tenant = tenant_id.strip()
        normalized_principal = principal.strip()
        _assert_authorized_tenant(
            tenant_id=normalized_tenant,
            authorized_tenant_id=authorized_tenant_id,
        )
        if not normalized_tenant:
            return None
        if not normalized_principal:
            raise ValidationError(
                "authenticated principal required for policy profile resolution",
                details={"tenant_id": normalized_tenant},
            )
        async with self._session_factory() as session:
            row = await session.scalar(
                select(orm.OrganizationPolicyProfileORM)
                .where(orm.OrganizationPolicyProfileORM.tenant_id == normalized_tenant)
                .order_by(
                    orm.OrganizationPolicyProfileORM.revision.desc(),
                    orm.OrganizationPolicyProfileORM.updated_at.desc(),
                )
                .limit(1)
            )
            if row is None:
                return None
            return _row_to_profile(row)

    async def upsert_profile(
        self,
        request: OrganizationPolicyProfileUpsertRequest,
        *,
        actor_principal: str,
        authorized_tenant_id: str | None = None,
    ) -> OrganizationPolicyProfile:
        if not actor_principal.strip():
            raise ValidationError(
                "actor principal required for policy profile upsert",
                details={"tenant_id": request.tenant_id},
            )
        _assert_authorized_tenant(
            tenant_id=request.tenant_id,
            authorized_tenant_id=authorized_tenant_id,
        )
        now = datetime.now(tz=UTC)
        async with self._session_factory() as session:
            async with session.begin():
                await session.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_key)"),
                    {"lock_key": tenant_policy_profile_lock_key(request.tenant_id)},
                )
                existing = await session.scalar(
                    select(orm.OrganizationPolicyProfileORM)
                    .where(orm.OrganizationPolicyProfileORM.tenant_id == request.tenant_id)
                    .order_by(orm.OrganizationPolicyProfileORM.revision.desc())
                    .limit(1)
                    .with_for_update()
                )
                next_revision = 1 if existing is None else int(existing.revision) + 1
                profile_id = existing.profile_id if existing is not None else new_profile_id()
                row = orm.OrganizationPolicyProfileORM(
                    profile_row_id=f"opprow-{uuid.uuid4().hex[:16]}",
                    profile_id=profile_id,
                    tenant_id=request.tenant_id,
                    revision=next_revision,
                    owner_principal=request.owner_principal,
                    framework_allowlist=list(request.framework_allowlist),
                    jurisdiction_codes=list(request.jurisdiction_codes),
                    industry_codes=list(request.industry_codes),
                    effective_at=now,
                    approved_by=request.approved_by or actor_principal,
                    audit_note=request.audit_note,
                    schema_version=ORGANIZATION_POLICY_PROFILE_SCHEMA_VERSION,
                    created_at=existing.created_at if existing is not None else now,
                    updated_at=now,
                )
                session.add(row)
                await session.flush()
                await session.refresh(row)
                return _row_to_profile(row)

    async def get_profile_by_revision(
        self,
        *,
        tenant_id: str,
        profile_id: str,
        revision: int,
        authorized_tenant_id: str | None = None,
    ) -> OrganizationPolicyProfile | None:
        _assert_authorized_tenant(
            tenant_id=tenant_id,
            authorized_tenant_id=authorized_tenant_id,
        )
        async with self._session_factory() as session:
            row = await session.scalar(
                select(orm.OrganizationPolicyProfileORM).where(
                    and_(
                        orm.OrganizationPolicyProfileORM.tenant_id == tenant_id,
                        orm.OrganizationPolicyProfileORM.profile_id == profile_id,
                        orm.OrganizationPolicyProfileORM.revision == revision,
                    )
                )
            )
            if row is None:
                return None
            return _row_to_profile(row)

    async def validate_profile_revision(
        self,
        *,
        tenant_id: str,
        profile_id: str,
        profile_revision: int,
        authorized_tenant_id: str | None = None,
    ) -> OrganizationPolicyProfile:
        profile = await self.get_profile_by_revision(
            tenant_id=tenant_id,
            profile_id=profile_id,
            revision=profile_revision,
            authorized_tenant_id=authorized_tenant_id,
        )
        if profile is None:
            raise ValidationError(
                "organization policy profile revision not found",
                details={
                    "tenant_id": tenant_id,
                    "profile_id": profile_id,
                    "profile_revision": profile_revision,
                    "reason": "profile_revision_stale",
                },
            )
        return profile


__all__ = [
    "OrganizationPolicyProfileService",
    "new_profile_id",
    "tenant_policy_profile_lock_key",
]
