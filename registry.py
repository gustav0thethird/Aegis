"""
registry.py — routing metadata for the secrets registry.

Registry format (JSON, security-team managed):
{
  "db_password": {
    "vendor":   "cyberark" | "vault" | "aws" | "conjur",
    "platform": "WinDomain",   # CyberArk: platformId
    "safe":     "MyApp-Safe",  # CyberArk / Conjur safe name
    "name":     "db_password"  # name/path/id as the vault knows it
  }
}

No secret values are stored here. The registry is routing metadata only.
"""

import json


def load_registry(path):
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Registry must be a JSON object, got {type(data).__name__}")
    return data


def save_registry(registry, path):
    with open(path, "w") as f:
        json.dump(registry, f, indent=2)
        f.write("\n")


def get_entries(registry, keys):
    """Return registry entries for the given key list."""
    missing = [k for k in keys if k not in registry]
    if missing:
        raise ValueError(f"Keys not found in registry: {', '.join(missing)}")
    return {k: registry[k] for k in keys}
