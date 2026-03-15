"""Add change_log table

Revision ID: 002
Revises: 001
Create Date: 2026-03-15
"""
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "change_log",
        sa.Column("id",           sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("timestamp",    sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("action",       sa.Text, nullable=False),   # created|updated|deleted|key_rotated|object_added|object_removed|registry_assigned|registry_unassigned
        sa.Column("entity_type",  sa.Text, nullable=False),   # object|registry|team
        sa.Column("entity_id",    sa.Text, nullable=False),   # name or UUID string
        sa.Column("entity_name",  sa.Text, nullable=False),   # snapshotted at time of change
        sa.Column("detail",       sa.Text),                   # human-readable description
        sa.Column("performed_by", sa.Text, nullable=False, server_default="admin"),
    )
    op.create_index("ix_change_log_timestamp",   "change_log", ["timestamp"])
    op.create_index("ix_change_log_entity",      "change_log", ["entity_type", "entity_id"])


def downgrade():
    op.drop_table("change_log")
