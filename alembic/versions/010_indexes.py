"""010 — Add performance indexes

Composite indexes on high-volume tables:
  - audit_log:          hot query paths (team, registry, outcome, timestamp)
  - webhook_log:        delivery history queries (webhook_id, team_id)
  - change_log:         admin log queries (entity_type, performed_by)
  - team_registry_keys: expiry scheduler + team lookups

Revision ID: 010
Revises: 009
"""

from alembic import op

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade():
    # ── audit_log ──────────────────────────────────────────────────────────
    # Most common admin query: filter by team + time range
    op.create_index("ix_audit_log_team_ts",     "audit_log", ["team_id",     "timestamp"])
    # Filter by registry + time range
    op.create_index("ix_audit_log_registry_ts", "audit_log", ["registry_id", "timestamp"])
    # Filter by outcome (success/denied/error) + time range
    op.create_index("ix_audit_log_outcome_ts",  "audit_log", ["outcome",     "timestamp"])
    # Time-range-only queries (changelog, metrics)
    op.create_index("ix_audit_log_ts",          "audit_log", ["timestamp"])

    # ── webhook_log ────────────────────────────────────────────────────────
    # Delivery history per webhook, newest first
    op.create_index("ix_webhook_log_webhook_ts", "webhook_log", ["webhook_id", "fired_at"])
    # Per-team webhook log queries
    op.create_index("ix_webhook_log_team_ts",    "webhook_log", ["team_id",    "fired_at"])

    # ── change_log ────────────────────────────────────────────────────────
    # Filter by entity type + time
    op.create_index("ix_change_log_entity_ts",   "change_log", ["entity_type",  "timestamp"])
    # Filter by who made the change
    op.create_index("ix_change_log_actor_ts",    "change_log", ["performed_by", "timestamp"])
    # Time-range queries
    op.create_index("ix_change_log_ts",          "change_log", ["timestamp"])

    # ── team_registry_keys ────────────────────────────────────────────────
    # ix_trk_expires_at already created in migration 006
    # All keys for a given team (admin drawer, self-service)
    op.create_index("ix_trk_team_id",     "team_registry_keys", ["team_id"])


def downgrade():
    op.drop_index("ix_audit_log_team_ts",     "audit_log")
    op.drop_index("ix_audit_log_registry_ts", "audit_log")
    op.drop_index("ix_audit_log_outcome_ts",  "audit_log")
    op.drop_index("ix_audit_log_ts",          "audit_log")

    op.drop_index("ix_webhook_log_webhook_ts", "webhook_log")
    op.drop_index("ix_webhook_log_team_ts",    "webhook_log")

    op.drop_index("ix_change_log_entity_ts",  "change_log")
    op.drop_index("ix_change_log_actor_ts",   "change_log")
    op.drop_index("ix_change_log_ts",         "change_log")

    # ix_trk_expires_at is owned by migration 006
    op.drop_index("ix_trk_team_id",    "team_registry_keys")
