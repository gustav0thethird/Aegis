"""
Effective policy resolution.

Policies exist at two levels, team and registry, over a set of global
defaults. Until now each field combined them differently - the IP allowlist
required both to pass, allowed hours looked only at the registry, change
number and rate limit took the registry or fell back to global, and key expiry
in the scheduler read the registry alone - while the documentation described a
single precedence chain for all of them. Operators configure policy from the
documentation, so a mismatch here is a security bug, not a wording problem.

One rule now, applied to every field:

    THE MOST RESTRICTIVE APPLICABLE POLICY WINS.

Deliberately not the documented "registry overrides team". Override lets a
registry-level policy widen what a team-level policy allows: a team locked to
an office CIDR would regain access from anywhere the moment a registry set its
own allowlist. For something that sits in front of credentials, adding a
policy must never be able to grant access that was previously denied. Under
most-restrictive, layering policies can only ever narrow access, which is also
what an operator reaching for a second policy almost always means.

Concretely:

  ip_allowlist    the request must satisfy every allowlist that is set
  allowed hours   the request must fall inside every window that is set
  cn_required     required if the global setting or any policy requires it
  rate_limit_rpm  the lowest value any level sets
  max_key_days    the shortest lifetime any level sets

A level that leaves a field null is silent on it, not permissive: null means
"no opinion", so it never loosens anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import time as _time

from sqlalchemy.orm import Session

from aegis.models import Policy


@dataclass
class EffectivePolicy:
    """
    The resolved policy for one team-registry pair.

    Restriction fields keep every contributing level rather than collapsing to
    one value, because "inside every window" cannot be expressed as a single
    window once two of them overlap partially.
    """
    ip_allowlists: list[tuple[str, list[str]]] = field(default_factory=list)
    hour_windows: list[tuple[str, _time | None, _time | None]] = field(default_factory=list)
    cn_required: bool = True
    rate_limit_rpm: int | None = None
    max_key_days: int | None = None

    def sources(self) -> list[str]:
        return sorted({label for label, _ in self.ip_allowlists}
                      | {label for label, _, _ in self.hour_windows})


def get_policy(db: Session, entity_type: str, entity_id) -> Policy | None:
    return (db.query(Policy)
              .filter(Policy.entity_type == entity_type, Policy.entity_id == entity_id)
              .first())


def resolve(db: Session, team, registry, *, global_cn_required: bool = True,
            global_rate_limit_rpm: int | None = None) -> EffectivePolicy:
    """
    Combine global defaults with the team and registry policies.

    Both levels are always consulted. The caller passes the global values it
    has already read from settings, so this module stays free of the settings
    lookup and is trivial to test.
    """
    eff = EffectivePolicy(cn_required=global_cn_required,
                          rate_limit_rpm=global_rate_limit_rpm)

    levels = []
    if team is not None:
        levels.append(("team", get_policy(db, "team", team.id)))
    if registry is not None:
        levels.append(("registry", get_policy(db, "registry", registry.id)))

    for label, policy in levels:
        if policy is None:
            continue
        if policy.ip_allowlist:
            eff.ip_allowlists.append((label, list(policy.ip_allowlist)))
        if policy.allowed_from or policy.allowed_to:
            eff.hour_windows.append((label, policy.allowed_from, policy.allowed_to))
        # A level that requires a change number cannot be overridden by one
        # that does not; nothing can switch the requirement off.
        if policy.cn_required:
            eff.cn_required = True
        if policy.rate_limit_rpm is not None:
            eff.rate_limit_rpm = (policy.rate_limit_rpm if eff.rate_limit_rpm is None
                                  else min(eff.rate_limit_rpm, policy.rate_limit_rpm))
        if policy.max_key_days is not None:
            eff.max_key_days = (policy.max_key_days if eff.max_key_days is None
                                else min(eff.max_key_days, policy.max_key_days))

    return eff


def max_key_days(db: Session, team, registry) -> int | None:
    """
    Shortest key lifetime that applies to a team-registry pair.

    Key issuance, rotation and the expiry scheduler all call this, so a key
    cannot be minted with a longer life than the policy that will later be
    used to expire it.
    """
    return resolve(db, team, registry).max_key_days
