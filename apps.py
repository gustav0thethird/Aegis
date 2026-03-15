"""
apps.py — API key to app/secrets mapping (security-team managed).

Apps manifest format (JSON):
{
  "sk_a1b2c3...": {
    "id":         "550e8400-...",    # stable UUID — used as the URL identifier
    "app":        "payments-service",
    "secrets":    ["db_password", "stripe_key"],
    "created_at": "2026-03-15T10:00:00+00:00"
  }
}

API keys are opaque strings. Security generates them via the admin UI or CLI.
Developers receive one key — it defines exactly what secrets they can access.
The ID is stable across key rotations; the api_key (dict key) changes on rotation.
"""

import json
import secrets
import uuid


def load_apps(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        raise ValueError("Apps manifest must be a JSON object")
    # Backfill missing IDs for entries created before this field was added
    needs_save = any("id" not in entry for entry in data.values())
    if needs_save:
        for entry in data.values():
            if "id" not in entry:
                entry["id"] = str(uuid.uuid4())
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
    return data


def save_apps(apps, path):
    with open(path, "w") as f:
        json.dump(apps, f, indent=2)
        f.write("\n")


def resolve_key(api_key, apps):
    """Validate an API key and return its app entry. Raises ValueError if unknown."""
    entry = apps.get(api_key)
    if not entry:
        raise ValueError("Invalid or revoked API key")
    return entry


def find_by_id(apps, team_id):
    """Find an entry by its stable UUID. Returns (api_key, entry) or raises ValueError."""
    for api_key, entry in apps.items():
        if entry.get("id") == team_id:
            return api_key, entry
    raise ValueError(f"Team '{team_id}' not found")


def generate_key():
    """Generate a cryptographically random API key."""
    return "sk_" + secrets.token_urlsafe(32)


def generate_id():
    """Generate a stable UUID for a new team."""
    return str(uuid.uuid4())
