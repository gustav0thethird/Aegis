"""009 — Add suspended column to team_registry_keys

Allows admins to temporarily disable a key without revoking it.
A suspended key is rejected at the secrets endpoint with 401 (indistinguishable
from a revoked key to the caller) but can be re-enabled without rotation.

Revision ID: 009
Revises: 008
"""

from alembic import op
import sqlalchemy as sa

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "team_registry_keys",
        sa.Column("suspended", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade():
    op.drop_column("team_registry_keys", "suspended")
