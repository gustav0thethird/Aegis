"""Add diff column to change_log

Revision ID: 004
Revises: 003
Create Date: 2026-03-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade():
    # diff stores structured before/after per-field change data
    op.add_column("change_log", sa.Column("diff", JSONB, nullable=True))


def downgrade():
    op.drop_column("change_log", "diff")
