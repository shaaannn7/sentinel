"""add score version to investigations

Revision ID: 20261004_score_version
Revises: 38907ae8a829
Create Date: 2026-10-04 12:00:00+00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20261004_score_version"
down_revision = "38907ae8a829"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("score_version", sa.String(length=32), nullable=False, server_default="2026.10"),
    )
    op.alter_column("investigations", "score_version", server_default=None)


def downgrade() -> None:
    op.drop_column("investigations", "score_version")
