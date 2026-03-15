"""Initial schema

Revision ID: 001
Revises:
Create Date: 2026-03-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    op.create_table(
        "objects",
        sa.Column("name",       sa.Text, primary_key=True),
        sa.Column("vendor",     sa.Text, nullable=False),
        sa.Column("auth_ref",   sa.Text, nullable=False),
        sa.Column("path",       sa.Text, nullable=False),
        sa.Column("platform",   sa.Text),
        sa.Column("safe",       sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.Text, nullable=False, server_default="admin"),
    )

    op.create_table(
        "registries",
        sa.Column("id",         postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name",       sa.Text, nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.Text, nullable=False, server_default="admin"),
    )

    op.create_table(
        "registry_objects",
        sa.Column("registry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("registries.id", ondelete="CASCADE"),  primary_key=True),
        sa.Column("object_name", sa.Text,                        sa.ForeignKey("objects.name",   ondelete="RESTRICT"), primary_key=True),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "registry_keys",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("registry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("registries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key_hash",    sa.Text, nullable=False, unique=True),
        sa.Column("key_preview", sa.Text, nullable=False),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at",  sa.DateTime(timezone=True)),
    )
    op.create_index("ix_registry_keys_registry_id", "registry_keys", ["registry_id"])

    op.create_table(
        "teams",
        sa.Column("id",         postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name",       sa.Text, nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.Text, nullable=False, server_default="admin"),
    )

    op.create_table(
        "team_registries",
        sa.Column("team_id",     postgresql.UUID(as_uuid=True), sa.ForeignKey("teams.id",      ondelete="CASCADE"),  primary_key=True),
        sa.Column("registry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("registries.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("assigned_by", sa.Text, nullable=False, server_default="admin"),
    )

    op.create_table(
        "audit_log",
        sa.Column("id",            sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("timestamp",     sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("event",         sa.Text, nullable=False),
        sa.Column("outcome",       sa.Text, nullable=False),
        sa.Column("change_number", sa.Text),
        sa.Column("registry_id",   postgresql.UUID(as_uuid=True)),
        sa.Column("registry_name", sa.Text),
        sa.Column("objects",       postgresql.ARRAY(sa.Text)),
        sa.Column("key_preview",   sa.Text),
        sa.Column("source_ip",     sa.Text),
        sa.Column("user_agent",    sa.Text),
        sa.Column("error_detail",  sa.Text),
    )
    op.create_index("ix_audit_log_timestamp",     "audit_log", ["timestamp"])
    op.create_index("ix_audit_log_registry_id",   "audit_log", ["registry_id"])
    op.create_index("ix_audit_log_change_number", "audit_log", ["change_number"])


def downgrade():
    op.drop_table("audit_log")
    op.drop_table("team_registries")
    op.drop_table("teams")
    op.drop_table("registry_keys")
    op.drop_table("registry_objects")
    op.drop_table("registries")
    op.drop_table("objects")
