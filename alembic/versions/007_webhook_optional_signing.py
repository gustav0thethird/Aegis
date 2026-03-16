"""Make webhook signing optional — add signing_enabled flag, make secret nullable

Revision ID: 007
Revises: 006
Create Date: 2026-03-15
"""
from alembic import op
import sqlalchemy as sa

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade():
    # Add signing_enabled flag (default False = no signing by default)
    op.add_column("webhooks",
        sa.Column("signing_enabled", sa.Boolean, nullable=False, server_default="false"))

    # Make secret nullable (only set when signing_enabled=True)
    op.alter_column("webhooks", "secret", nullable=True)

    # Clear any placeholder secrets on existing webhooks that have no real secret yet
    # (Existing webhooks already have a real auto-generated secret, so no action needed)


def downgrade():
    op.alter_column("webhooks", "secret", nullable=False)
    op.drop_column("webhooks", "signing_enabled")
