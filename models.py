"""
models.py — SQLAlchemy ORM models.

Schema:
  objects          — atomic secret definitions (vendor + auth + location)
  registries       — named collections of objects; own the API key
  registry_objects — many-to-many: registry ↔ object
  registry_keys    — API keys for registries (hashed); full history kept
  teams            — metadata only; no key of their own
  team_registries  — many-to-many: team ↔ registry
  change_log       — immutable record of every admin mutation
  audit_log        — immutable request log; fields snapshotted at request time
  users            — operator accounts with role + optional team assignment
  settings         — key/value config store (runtime-mutable settings)
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger, Column, DateTime, ForeignKey, String, Text, ARRAY
)
from sqlalchemy.dialects.postgresql import JSONB as _JSONB
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from database import Base


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
    revoked_at  = Column(DateTime(timezone=True))             # null = active

    team     = relationship("Team",     back_populates="keys")
    registry = relationship("Registry", back_populates="team_keys")


class Team(Base):
    __tablename__ = "teams"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(Text, nullable=False, unique=True)
    created_at  = Column(DateTime(timezone=True), nullable=False, default=_now)
    created_by  = Column(Text, nullable=False, default="admin")

    registry_links = relationship("TeamRegistry",    back_populates="team", cascade="all, delete-orphan")
    keys           = relationship("TeamRegistryKey", back_populates="team", cascade="all, delete-orphan")


class TeamRegistry(Base):
    __tablename__ = "team_registries"

    team_id     = Column(UUID(as_uuid=True), ForeignKey("teams.id",      ondelete="CASCADE"),  primary_key=True)
    registry_id = Column(UUID(as_uuid=True), ForeignKey("registries.id", ondelete="RESTRICT"), primary_key=True)
    assigned_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    assigned_by = Column(Text, nullable=False, default="admin")

    team     = relationship("Team",     back_populates="registry_links")
    registry = relationship("Registry", back_populates="team_links")


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
    team_id       = Column(UUID(as_uuid=True))                     # nullable; user role only
    theme         = Column(Text, nullable=False, default="default")
    created_at    = Column(DateTime(timezone=True), nullable=False, default=_now)
    created_by    = Column(Text, nullable=False, default="admin")


class Setting(Base):
    __tablename__ = "settings"

    key        = Column(Text, primary_key=True)
    value      = Column(Text)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    updated_by = Column(Text, nullable=False, default="admin")
