"""add AI summary columns

Revision ID: a1b2c3d4e5f6
Revises: cf6ede218e77
Create Date: 2026-11-26 06:50:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "cf6ede218e77"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("vulnerabilities", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ai_summary", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("ai_summary_model", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("ai_summary_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("vulnerabilities", schema=None) as batch_op:
        batch_op.drop_column("ai_summary_at")
        batch_op.drop_column("ai_summary_model")
        batch_op.drop_column("ai_summary")
