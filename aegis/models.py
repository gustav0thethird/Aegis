"""
models.py — SQLAlchemy ORM models.

Schema:
  objects            — atomic secret definitions (vendor + auth + location)
  registries         — named collections of objects
  registry_objects   — many-to-many: registry ↔ object
  teams              — metadata only; no key of their own
  team_registries    — many-to-many: team ↔ registry
  team_registry_keys — API keys per team-registry assignment (hashed)
  user_teams         — many-to-many: user ↔ team
  policies           — access control rules per registry or team
  webhooks           — per-team HTTP webhook config (URL, secret, event subscriptions)
  webhook_log        — delivery history for webhook calls
  change_log         — immutable record of every admin mutation
  audit_log          — immutable request log; fields snapshotted at request time
  users              — operator accounts with role; team membership via user_teams
  settings           — key/value config store (runtime-mutable settings)
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, ForeignKey, Integer, String, Text, Time, ARRAY
)
from sqlalchemy.dialects.postgresql import JSONB as _JSONB
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from aegis.database import Base


def _now():
    return datetime.now(timezone.utc)


class Object(Base):
    __tablename__ = "objects"

    name        = Column(Text, primary_key=True)   # e.g. "db_password"
    vendor      = Column(Text, nullable=False)      # cyberark|vault|aws|conjur
    auth_ref    = Column(Text, nullable=False)      # key into auth.json
    path        = Column(Text, nullable=False)      # vault path / CyberArk object name
    platform    = Column(Text)                      # CyberArk only
    safe        = Column(Text)                      # CyberArk / Conjur
    created_at  = Column(DateTime(timezone=True), nullable=False, default=_now)
    created_by  = Column(Text, nullable=False, default="admin")

    registry_entries = relationship(
        "RegistryObject", back_populates="object", cascade="all, delete-orphan"
    )


class Registry(Base):
    __tablename__ = "registries"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(Text, nullable=False, unique=True)
    created_at  = Column(DateTime(timezone=True), nullable=False, default=_now)
    created_by  = Column(Text, nullable=False, default="admin")

    registry_entries = relationship("RegistryObject",    back_populates="registry", cascade="all, delete-orphan")
    team_links       = relationship("TeamRegistry",       back_populates="registry")
    team_keys        = relationship("TeamRegistryKey",    back_populates="registry", cascade="all, delete-orphan")


class RegistryObject(Base):
    __tablename__ = "registry_objects"

    registry_id = Column(UUID(as_uuid=True), ForeignKey("registries.id", ondelete="CASCADE"),  primary_key=True)
    object_name = Column(Text,               ForeignKey("objects.name",   ondelete="RESTRICT"), primary_key=True)
    assigned_at = Column(DateTime(timezone=True), nullable=False, default=_now)

    registry = relationship("Registry", back_populates="registry_entries")
    object   = relationship("Object",   back_populates="registry_entries")


class TeamRegistryKey(Base):
    """One API key per team-registry assignment. Full traceability: key → team + registry."""
    __tablename__ = "team_registry_keys"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    team_id     = Column(UUID(as_uuid=True), ForeignKey("teams.id",      ondelete="CASCADE"), nullable=False)
    registry_id = Column(UUID(as_uuid=True), ForeignKey("registries.id", ondelete="CASCADE"), nullable=False)
    key_hash    = Column(Text, nullable=False, unique=True)   # SHA-256 hex; plaintext never stored
    key_preview = Column(Text, nullable=False)                # first 10 chars for UI display
    created_at  = Column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at  = Column(DateTime(timezone=True))             # null = no expiry; set from registry policy
    revoked_at  = Column(DateTime(timezone=True))             # null = active
    suspended   = Column(Boolean, nullable=False, default=False)  # true = temporarily disabled (not revoked)

    team     = relationship("Team",     back_populates="keys")
    registry = relationship("Registry", back_populates="team_keys")


class Team(Base):
    __tablename__ = "teams"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(Text, nullable=False, unique=True)
    created_at  = Column(DateTime(timezone=True), nullable=False, default=_now)
    created_by  = Column(Text, nullable=False, default="admin")

    # Notification channels
    slack_webhook_url    = Column(Text, nullable=True)
    ms_teams_webhook_url = Column(Text, nullable=True)
    discord_webhook_url  = Column(Text, nullable=True)

    registry_links = relationship("TeamRegistry",    back_populates="team", cascade="all, delete-orphan")
    keys           = relationship("TeamRegistryKey", back_populates="team", cascade="all, delete-orphan")
    webhook        = relationship("Webhook",         back_populates="team", uselist=False, cascade="all, delete-orphan")
    members        = relationship("UserTeam",        back_populates="team", cascade="all, delete-orphan")


class UserTeam(Base):
    """Many-to-many: user ↔ team membership."""
    __tablename__ = "user_teams"

    user_id    = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    team_id    = Column(UUID(as_uuid=True), ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)

    user = relationship("User", back_populates="team_memberships")
    team = relationship("Team", back_populates="members")


class TeamRegistry(Base):
    __tablename__ = "team_registries"

    team_id     = Column(UUID(as_uuid=True), ForeignKey("teams.id",      ondelete="CASCADE"),  primary_key=True)
    registry_id = Column(UUID(as_uuid=True), ForeignKey("registries.id", ondelete="RESTRICT"), primary_key=True)
    assigned_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    assigned_by = Column(Text, nullable=False, default="admin")

    team     = relationship("Team",     back_populates="registry_links")
    registry = relationship("Registry", back_populates="team_links")


class Policy(Base):
    """One row per entity (registry or team). Null fields inherit global settings."""
    __tablename__ = "policies"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type     = Column(Text, nullable=False)              # registry | team
    entity_id       = Column(UUID(as_uuid=True), nullable=False)
    ip_allowlist    = Column(ARRAY(Text))                       # CIDRs; null = unrestricted
    allowed_from    = Column(Time(timezone=False))              # UTC; null = unrestricted
    allowed_to      = Column(Time(timezone=False))
    cn_required     = Column(Boolean)                           # null = inherit global
    rate_limit_rpm  = Column(Integer)                           # null = inherit global
    max_key_days    = Column(Integer)                           # null = no expiry policy
    created_at      = Column(DateTime(timezone=True), nullable=False, default=_now)
    created_by      = Column(Text, nullable=False, default="admin")
    updated_at      = Column(DateTime(timezone=True), nullable=False, default=_now)
    updated_by      = Column(Text, nullable=False, default="admin")


class Webhook(Base):
    """Per-team HTTP webhook configuration."""
    __tablename__ = "webhooks"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    team_id    = Column(UUID(as_uuid=True), ForeignKey("teams.id", ondelete="CASCADE"),
                        nullable=False, unique=True)
    url             = Column(Text, nullable=False)
    secret          = Column(Text, nullable=True)               # HMAC-SHA256 signing secret; None when signing disabled
    signing_enabled = Column(Boolean, nullable=False, default=False)
    events          = Column(ARRAY(Text), nullable=False)       # subscribed event types
    enabled         = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    created_by = Column(Text, nullable=False, default="admin")

    team = relationship("Team", back_populates="webhook")
    logs = relationship("WebhookLog", back_populates="webhook", cascade="all, delete-orphan")


class WebhookLog(Base):
    """Delivery record for every webhook attempt."""
    __tablename__ = "webhook_log"

    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    webhook_id  = Column(UUID(as_uuid=True), ForeignKey("webhooks.id", ondelete="CASCADE"), nullable=False)
    team_id     = Column(UUID(as_uuid=True), nullable=False)
    event       = Column(Text, nullable=False)
    payload     = Column(Text, nullable=False)   # JSON string sent
    status_code = Column(Integer)
    success     = Column(Boolean, nullable=False)
    attempt     = Column(Integer, nullable=False, default=1)
    error       = Column(Text)
    fired_at    = Column(DateTime(timezone=True), nullable=False, default=_now)

    webhook = relationship("Webhook", back_populates="logs")


class ChangeLog(Base):
    __tablename__ = "change_log"

    id           = Column(BigInteger, primary_key=True, autoincrement=True)
    timestamp    = Column(DateTime(timezone=True), nullable=False, default=_now)
    action       = Column(Text, nullable=False)   # created|updated|deleted|key_rotated|object_added|object_removed|registry_assigned|registry_unassigned
    entity_type  = Column(Text, nullable=False)   # object|registry|team|user|settings
    entity_id    = Column(Text, nullable=False)   # name or UUID string
    entity_name  = Column(Text, nullable=False)   # snapshotted
    detail       = Column(Text)
    diff         = Column(_JSONB)                 # {"field": {"from": old, "to": new}, ...}
    performed_by = Column(Text, nullable=False, default="admin")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id            = Column(BigInteger, primary_key=True, autoincrement=True)
    timestamp     = Column(DateTime(timezone=True), nullable=False, default=_now)
    event         = Column(Text, nullable=False)   # secrets.fetched | secrets.blocked | auth.failed
    outcome       = Column(Text, nullable=False)   # success | denied | error
    change_number = Column(Text)
    registry_id   = Column(UUID(as_uuid=True))     # snapshotted — no FK, registry may be deleted
    registry_name = Column(Text)
    team_id       = Column(UUID(as_uuid=True))     # snapshotted — the team whose key was used
    team_name     = Column(Text)
    objects       = Column(ARRAY(Text))            # snapshotted at request time
    key_preview   = Column(Text)
    source_ip     = Column(Text)
    user_agent    = Column(Text)
    error_detail  = Column(Text)


class User(Base):
    __tablename__ = "users"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username      = Column(Text, nullable=False, unique=True)
    password_hash = Column(Text, nullable=False)
    role          = Column(Text, nullable=False, default="user")   # admin | user
    theme         = Column(Text, nullable=False, default="default")
    created_at    = Column(DateTime(timezone=True), nullable=False, default=_now)
    created_by    = Column(Text, nullable=False, default="admin")

    team_memberships = relationship("UserTeam", back_populates="user", cascade="all, delete-orphan")


class Setting(Base):
    __tablename__ = "settings"

    key        = Column(Text, primary_key=True)
    value      = Column(Text)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    updated_by = Column(Text, nullable=False, default="admin")
