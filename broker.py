"""
broker.py — Fetch secrets for a registry.

Entry point:
  fetch_secrets(object_rows, auth) -> {name: value}

Groups objects by vendor, acquires one session per CyberArk auth_ref,
and dispatches to the appropriate functions.py call per object.
auth is the loaded auth.json dict.

Auth format (auth.json):
{
  "cyberark": {
    "prod": {
      "host":        "cyberark.example.com",
      "app_id":      "BrokerApp",
      "auth_safe":   "Broker-Auth-Safe",
      "auth_object": "Broker-ServiceAccount"
    }
  },
  "vault": {
    "prod": { "addr": "https://vault.example.com", "token": "...", "mount": "secret" }
  },
  "aws": {
    "prod": { "region": "eu-west-1" }
  },
  "conjur": {
    "prod": { "host": "conjur.example.com", "account": "myorg", "login": "...", "api_key": "..." }
  }
}
"""

import json
import logging
import os

from functions import (
    vault_get,
    cyberark_logon,
    cyberark_find_account,
    cyberark_get,
    conjur_get,
    aws_get,
)

logger = logging.getLogger("aegis")


def load_auth() -> dict:
    path = os.environ.get("AUTH_PATH")
    if not path:
        raise RuntimeError("AUTH_PATH environment variable is not set")
    with open(path) as f:
        return json.load(f)


def fetch_secrets(object_rows: list[dict], auth: dict) -> dict[str, str]:
    """
    Fetch all secrets for the given object rows.

    object_rows: list of dicts with keys: name, vendor, auth_ref, path, platform, safe
    auth:        loaded auth.json

    Returns {object_name: plaintext_value}.
    Raises ValueError describing every failed fetch.
    """
    results: dict[str, str] = {}
    errors: list[str] = []

    by_vendor: dict[str, list[dict]] = {}
    for obj in object_rows:
        by_vendor.setdefault(obj["vendor"], []).append(obj)

    for vendor, objects in by_vendor.items():
        try:
            if vendor == "vault":
                _fetch_vault(objects, auth, results)
            elif vendor == "cyberark":
                _fetch_cyberark(objects, auth, results)
            elif vendor == "conjur":
                _fetch_conjur(objects, auth, results)
            elif vendor == "aws":
                _fetch_aws(objects, auth, results)
            else:
                for obj in objects:
                    errors.append(f"{obj['name']}: unknown vendor '{vendor}'")
        except Exception as exc:
            for obj in objects:
                if obj["name"] not in results:
                    errors.append(f"{obj['name']}: {exc}")

    if errors:
        raise ValueError("; ".join(errors))

    return results


# ---------------------------------------------------------------------------
# Per-vendor helpers
# ---------------------------------------------------------------------------

def _fetch_vault(objects: list[dict], auth: dict, results: dict) -> None:
    for obj in objects:
        cfg = _auth_cfg(auth, "vault", obj["auth_ref"], obj["name"])
        results[obj["name"]] = vault_get(obj["path"], cfg)


def _fetch_cyberark(objects: list[dict], auth: dict, results: dict) -> None:
    # One PVWA session per auth_ref (i.e. per CyberArk environment)
    by_auth_ref: dict[str, list[dict]] = {}
    for obj in objects:
        by_auth_ref.setdefault(obj["auth_ref"], []).append(obj)

    for auth_ref, group in by_auth_ref.items():
        cfg = _auth_cfg(auth, "cyberark", auth_ref, group[0]["name"])
        session = cyberark_logon(cfg)
        for obj in group:
            account_id = cyberark_find_account(
                obj["path"],
                obj.get("platform"),
                obj.get("safe"),
                cfg,
                session,
            )
            results[obj["name"]] = cyberark_get(account_id, cfg, session)


def _fetch_conjur(objects: list[dict], auth: dict, results: dict) -> None:
    for obj in objects:
        cfg = _auth_cfg(auth, "conjur", obj["auth_ref"], obj["name"])
        results[obj["name"]] = conjur_get(obj["path"], cfg)


def _fetch_aws(objects: list[dict], auth: dict, results: dict) -> None:
    for obj in objects:
        cfg = _auth_cfg(auth, "aws", obj["auth_ref"], obj["name"])
        results[obj["name"]] = aws_get(obj["path"], cfg)


def _auth_cfg(auth: dict, vendor: str, auth_ref: str, obj_name: str) -> dict:
    cfg = auth.get(vendor, {}).get(auth_ref)
    if not cfg:
        raise ValueError(
            f"No auth config for object={obj_name} vendor={vendor} ref={auth_ref}"
        )
    return cfg
