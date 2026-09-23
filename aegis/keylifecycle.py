"""
keylifecycle.py — the one way a team-registry API key is issued.

Four paths minted keys: registry assignment, admin rotation, the CI/CD inbound
webhook, and the expiry scheduler. They agreed on the generator, the hash and
the preview format - keys.py already exists because they once disagreed about
*that* - but they had drifted apart on everything else:

                        expiry          revokes old   change log   webhook
  assignment            registry only   n/a           yes          no
  admin rotation        none            yes           yes          yes
  inbound rotation      none            yes           no           no
  scheduler             effective       yes           no           yes

Two of those gaps are security bugs rather than inconsistencies. A key issued
without expires_at is never seen by the expiry scheduler, which selects on
`expires_at IS NOT NULL`, so a policy demanding 24-hour keys silently produced
permanent ones. And the assignment path resolved max_key_days from the
registry policy alone, so a team-level policy was ignored - the same mistake
the policy module was written to end.

Everything to do with issuing a key now happens here, and each route is a thin
wrapper. The properties this guarantees are asserted as a matrix in
tests/test_key_lifecycle.py rather than described.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from aegis import keys as keys_mod
from aegis import policy as policy_mod
from aegis import secret_cache
from aegis import webhook as wh
from aegis.models import TeamRegistryKey

logger = logging.getLogger("aegis.keylifecycle")


def effective_expiry(db: Session, team, registry) -> datetime | None:
    """
    When a key issued now for this pair must stop working.

    The shortest lifetime any applicable policy sets, team as well as
    registry. None means no policy asks for expiry.
    """
    max_days = policy_mod.max_key_days(db, team, registry)
    if not max_days:
        return None
    return datetime.now(timezone.utc) + timedelta(days=max_days)


def revoke_active_keys(db: Session, team, registry) -> str | None:
    """
    Revoke every active key for the pair and drop what they cached.

    A cached secret must not outlive the credential that was allowed to read
    it. Returns the preview of the key that was active, for the audit trail.
    """
    now = datetime.now(timezone.utc)
    previous = None
    for row in (db.query(TeamRegistryKey)
                  .filter(TeamRegistryKey.team_id == team.id,
                          TeamRegistryKey.registry_id == registry.id,
                          TeamRegistryKey.revoked_at.is_(None))
                  .all()):
        previous = previous or row.key_preview
        row.revoked_at = now
        secret_cache.invalidate(row.key_hash)
    return previous


def issue(db: Session, team, registry, *, actor: str, reason: str,
          revoke_existing: bool = True, notify: bool = True,
          record_change: bool = True) -> tuple[TeamRegistryKey, str]:
    """
    Issue a key for a team-registry pair.

    Returns (row, plaintext). The plaintext is returned to the caller that
    asked for the rotation and is never persisted; only its hash is stored.

    reason           recorded in the audit trail and sent with the webhook
                     ("assignment", "manual_rotation", "inbound_rotation",
                     "expiry", ...)
    revoke_existing  revoke and cache-invalidate the keys being replaced.
                     False only for a first issuance, where there are none.
    notify           fire key.rotated. Off for a first issuance: nothing was
                     rotated.
    record_change    write the change-log entry. On by default because
                     issuing a credential is a change worth attributing.
    """
    # Local import: aegis.deps imports this module's callers, and the change
    # writer lives there. Same reason webhook.py imports WebhookLog lazily.
    from aegis.deps import _write_change

    previous_preview = revoke_active_keys(db, team, registry) if revoke_existing else None

    plaintext = keys_mod.generate_key()
    row = TeamRegistryKey(
        team_id=team.id,
        registry_id=registry.id,
        key_hash=keys_mod.hash_key(plaintext),
        key_preview=keys_mod.preview(plaintext),
        expires_at=effective_expiry(db, team, registry),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    logger.info("Issued key team=%s registry=%s reason=%s expires_at=%s",
                team.name, registry.name, reason,
                row.expires_at.isoformat() if row.expires_at else "never")

    if record_change:
        _write_change(db, "key_rotated" if revoke_existing else "registry_assigned",
                      "team", str(team.id), team.name, None, actor,
                      diff={"registry": {"to": registry.name},
                            "reason": {"to": reason},
                            "key_preview": {"from": previous_preview, "to": row.key_preview},
                            "expires_at": {"to": row.expires_at.isoformat()
                                           if row.expires_at else None}})

    if notify:
        wh.fire(db, team, "key.rotated",
                registry={"id": str(registry.id), "name": registry.name},
                new_key=plaintext, key_preview=row.key_preview, reason=reason)

    return row, plaintext
