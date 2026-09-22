"""012 — Add identity_bindings

Workload identity: a caller may authenticate with the OIDC token its platform
already issued it (a Kubernetes projected ServiceAccount token, a GitHub
Actions token) instead of a long-lived Aegis API key.

A row here is not a credential. Issuer, audience, subject and claim rules are
public facts about a workload; possession of them grants nothing without a
token the issuer actually signed.

Revision ID: 012
Revises: 011
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "identity_bindings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("audience", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("claim_rules", JSONB(), nullable=True),
        sa.Column("team_id", UUID(as_uuid=True),
                  sa.ForeignKey("teams.id", ondelete="CASCADE"), nullable=False),
        sa.Column("registry_id", UUID(as_uuid=True),
                  sa.ForeignKey("registries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("created_by", sa.Text(), nullable=False, server_default="admin"),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("issuer", "audience", "subject", "team_id", "registry_id",
                            name="uq_identity_binding"),
    )
    # Authentication looks bindings up by issuer on every request.
    op.create_index("ix_identity_bindings_issuer", "identity_bindings", ["issuer"])


def downgrade():
    op.drop_index("ix_identity_bindings_issuer", table_name="identity_bindings")
    op.drop_table("identity_bindings")
