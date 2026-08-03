"""enforce one profile revision per tenant (ISSUE-129 / #635)

Revision ID: 0029_policy_profile_uq
Revises: 0028_policy_control
Create Date: 2026-08-03 15:30:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0029_policy_profile_uq"
down_revision: str | None = "0028_policy_control"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_organization_policy_profile_tenant_revision",
        "organization_policy_profile",
        ["tenant_id", "revision"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_organization_policy_profile_tenant_revision",
        "organization_policy_profile",
        type_="unique",
    )
