"""Move API keys from registries to team-registry assignments

Each team's access to a registry now carries its own API key, giving
full traceability: key → team + registry rather than just registry.

Revision ID: 005
Revises: 004
Create Date: 2026-03-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "team_registry_keys",
        sa.Column("id",          UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("team_id",     UUID(as_uuid=True),
                  sa.ForeignKey("teams.id",      ondelete="CASCADE"), nullable=False),
        sa.Column("registry_id", UUID(as_uuid=True),
                  sa.ForeignKey("registries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key_hash",    sa.Text, nullable=False, unique=True),
        sa.Column("key_preview", sa.Text, nullable=False),
        sa.Column("created_at",  sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at",  sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_trk_team_registry", "team_registry_keys", ["team_id", "registry_id"])
    op.create_index("ix_trk_key_hash",      "team_registry_keys", ["key_hash"])

    # Add team tracking columns to audit_log
    op.add_column("audit_log", sa.Column("team_id",   UUID(as_uuid=True), nullable=True))
    op.add_column("audit_log", sa.Column("team_name", sa.Text, nullable=True))

    # Drop the old registry-level keys table
    op.drop_table("registry_keys")


def downgrade():
    op.drop_table("team_registry_keys")
    op.drop_column("audit_log", "team_id")
    op.drop_column("audit_log", "team_name")
    op.create_table(
        "registry_keys",
        sa.Column("id",          UUID(as_uuid=True), primary_key=True),
        sa.Column("registry_id", UUID(as_uuid=True), nullable=False),
        sa.Column("key_hash",    sa.Text, nullable=False, unique=True),
        sa.Column("key_preview", sa.Text, nullable=False),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at",  sa.DateTime(timezone=True), nullable=True),
    )
