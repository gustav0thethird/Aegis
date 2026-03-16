"""Add policies, webhooks, webhook_log; expires_at on team_registry_keys

Revision ID: 006
Revises: 005
Create Date: 2026-03-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ARRAY

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade():
    # --- policies -----------------------------------------------------------
    op.create_table(
        "policies",
        sa.Column("id",           UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("entity_type",  sa.Text, nullable=False),   # registry | team
        sa.Column("entity_id",    UUID(as_uuid=True), nullable=False),
        # Registry-level controls
        sa.Column("ip_allowlist",  ARRAY(sa.Text), nullable=True),   # CIDRs; null = unrestricted
        sa.Column("allowed_from",  sa.Time(timezone=False), nullable=True),  # UTC
        sa.Column("allowed_to",    sa.Time(timezone=False), nullable=True),
        sa.Column("cn_required",   sa.Boolean, nullable=True),        # null = inherit global
        sa.Column("rate_limit_rpm", sa.Integer, nullable=True),       # null = inherit global
        sa.Column("max_key_days",  sa.Integer, nullable=True),        # null = no expiry
        sa.Column("created_at",   sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("created_by",   sa.Text, nullable=False, server_default="admin"),
        sa.Column("updated_at",   sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("updated_by",   sa.Text, nullable=False, server_default="admin"),
    )
    op.create_index("ix_policies_entity", "policies", ["entity_type", "entity_id"], unique=True)

    # --- webhooks -----------------------------------------------------------
    op.create_table(
        "webhooks",
        sa.Column("id",          UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("team_id",     UUID(as_uuid=True),
                  sa.ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("url",         sa.Text, nullable=False),
        sa.Column("secret",      sa.Text, nullable=False),   # HMAC signing secret (plaintext stored — not a user secret)
        sa.Column("events",      ARRAY(sa.Text), nullable=False),  # [key.expiring_soon, key.rotated, key.revoked, policy.violated]
        sa.Column("enabled",     sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at",  sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("created_by",  sa.Text, nullable=False, server_default="admin"),
    )
    op.create_index("ix_webhooks_team_id", "webhooks", ["team_id"])

    # --- webhook_log --------------------------------------------------------
    op.create_table(
        "webhook_log",
        sa.Column("id",          sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("webhook_id",  UUID(as_uuid=True),
                  sa.ForeignKey("webhooks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("team_id",     UUID(as_uuid=True), nullable=False),
        sa.Column("event",       sa.Text, nullable=False),
        sa.Column("payload",     sa.Text, nullable=False),   # JSON string sent
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("success",     sa.Boolean, nullable=False),
        sa.Column("attempt",     sa.Integer, nullable=False, server_default="1"),
        sa.Column("error",       sa.Text, nullable=True),
        sa.Column("fired_at",    sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_webhook_log_webhook_id", "webhook_log", ["webhook_id"])
    op.create_index("ix_webhook_log_team_id",    "webhook_log", ["team_id"])

    # --- expires_at on team_registry_keys -----------------------------------
    op.add_column("team_registry_keys",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_trk_expires_at", "team_registry_keys", ["expires_at"])

    # --- seed new settings --------------------------------------------------
    op.execute("""
        INSERT INTO settings (key, value, updated_at, updated_by) VALUES
        ('key_warning_days', '7',  now(), 'system')
        ON CONFLICT (key) DO NOTHING
    """)


def downgrade():
    op.drop_index("ix_trk_expires_at", "team_registry_keys")
    op.drop_column("team_registry_keys", "expires_at")
    op.drop_table("webhook_log")
    op.drop_table("webhooks")
    op.drop_table("policies")
    op.execute("DELETE FROM settings WHERE key IN ('key_warning_days')")
