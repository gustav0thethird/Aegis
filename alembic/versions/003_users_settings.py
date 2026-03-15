"""Add users and settings tables

Revision ID: 003
Revises: 002
Create Date: 2026-03-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
import uuid

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id",            UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("username",      sa.Text, nullable=False, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role",          sa.Text, nullable=False, server_default="user"),
        sa.Column("team_id",       UUID(as_uuid=True), nullable=True),
        sa.Column("theme",         sa.Text, nullable=False, server_default="default"),
        sa.Column("created_at",    sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by",    sa.Text, nullable=False, server_default="admin"),
    )
    op.create_index("ix_users_username", "users", ["username"])

    op.create_table(
        "settings",
        sa.Column("key",        sa.Text, primary_key=True),
        sa.Column("value",      sa.Text),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_by", sa.Text, nullable=False, server_default="admin"),
    )

    # Seed default settings
    op.execute("""
        INSERT INTO settings (key, value) VALUES
        ('siem_destinations',  'stdout'),
        ('splunk_hec_url',     ''),
        ('splunk_hec_token',   ''),
        ('s3_log_bucket',      ''),
        ('dd_api_key',         ''),
        ('rate_limit_rpm',     '60'),
        ('change_number_required', 'true'),
        ('session_ttl_hours',  '8'),
        ('log_retention_days', '90')
        ON CONFLICT DO NOTHING
    """)


def downgrade():
    op.drop_table("users")
    op.drop_table("settings")
