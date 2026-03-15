#!/usr/bin/env python3
"""
parser.py — admin CLI for the Aegis.

Security team uses this to manage the registry and app manifests.
Developers never touch this.

Commands:
  add-secret   Add or update a secret entry in the registry
  rm-secret    Remove a secret from the registry
  add-app      Register a new app and generate its API key
  rm-app       Revoke an app's API key
  set-secrets  Update the secret list for an existing app
  gen-key      Generate a new API key (without adding to manifest)
  list         List registry entries and apps

Examples:
  python parser.py add-secret --key db_password --vendor cyberark \\
      --platform WinDomain --safe MyApp-Safe --name db_password \\
      --registry registry.json

  python parser.py add-app --app payments-service \\
      --secrets db_password,stripe_key --apps apps.json

  python parser.py list --registry registry.json --apps apps.json
"""

import argparse
import json
import sys

from apps import load_apps, save_apps, generate_key
from registry import load_registry, save_registry


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_add_secret(args):
    try:
        registry = load_registry(args.registry)
    except FileNotFoundError:
        registry = {}

    entry = {"vendor": args.vendor, "name": args.name}
    if args.platform:
        entry["platform"] = args.platform
    if args.safe:
        entry["safe"] = args.safe

    registry[args.key] = entry
    save_registry(registry, args.registry)
    print(f"Added '{args.key}' to registry.")


def cmd_rm_secret(args):
    registry = load_registry(args.registry)
    if args.key not in registry:
        print(f"ERROR: '{args.key}' not in registry", file=sys.stderr)
        sys.exit(1)
    del registry[args.key]
    save_registry(registry, args.registry)
    print(f"Removed '{args.key}' from registry.")


def cmd_add_app(args):
    try:
        apps = load_apps(args.apps)
    except FileNotFoundError:
        apps = {}

    api_key = generate_key()
    secret_list = [s.strip() for s in args.secrets.split(",") if s.strip()]
    apps[api_key] = {"app": args.app, "secrets": secret_list}
    save_apps(apps, args.apps)

    print(f"App:     {args.app}")
    print(f"Secrets: {', '.join(secret_list)}")
    print(f"API key: {api_key}")
    print()
    print("Hand the API key to the developer. It will not be shown again.")


def cmd_rm_app(args):
    apps = load_apps(args.apps)
    if args.key not in apps:
        print(f"ERROR: API key not found in apps manifest", file=sys.stderr)
        sys.exit(1)
    app_name = apps[args.key]["app"]
    del apps[args.key]
    save_apps(apps, args.apps)
    print(f"Revoked API key for app '{app_name}'.")


def cmd_set_secrets(args):
    apps = load_apps(args.apps)
    matches = {k: v for k, v in apps.items() if v["app"] == args.app}
    if not matches:
        print(f"ERROR: no app named '{args.app}' found", file=sys.stderr)
        sys.exit(1)
    secret_list = [s.strip() for s in args.secrets.split(",") if s.strip()]
    for key in matches:
        apps[key]["secrets"] = secret_list
    save_apps(apps, args.apps)
    print(f"Updated secrets for '{args.app}': {', '.join(secret_list)}")


def cmd_gen_key(_args):
    print(generate_key())


def cmd_list(args):
    if args.registry:
        try:
            registry = load_registry(args.registry)
            print("=== Registry ===")
            for key, spec in registry.items():
                print(f"  {key}: {spec}")
        except FileNotFoundError:
            print("Registry file not found.")

    if args.apps:
        try:
            apps = load_apps(args.apps)
            print("\n=== Apps ===")
            for api_key, entry in apps.items():
                print(f"  {entry['app']} ({api_key[:10]}...)")
                print(f"    secrets: {', '.join(entry['secrets'])}")
        except FileNotFoundError:
            print("Apps file not found.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="aegis-admin", description="Aegis admin CLI")
    sub = p.add_subparsers(dest="command", required=True)

    # add-secret
    s = sub.add_parser("add-secret", help="Add or update a registry entry")
    s.add_argument("--key",      required=True, help="Registry key name")
    s.add_argument("--vendor",   required=True, choices=("cyberark", "vault", "aws", "conjur"))
    s.add_argument("--name",     required=True, help="Secret name/path as the vault knows it")
    s.add_argument("--platform", help="CyberArk: platformId")
    s.add_argument("--safe",     help="CyberArk/Conjur: safe name")
    s.add_argument("--registry", required=True, help="Path to registry.json")

    # rm-secret
    s = sub.add_parser("rm-secret", help="Remove a registry entry")
    s.add_argument("--key",      required=True)
    s.add_argument("--registry", required=True)

    # add-app
    s = sub.add_parser("add-app", help="Register a new app and generate its API key")
    s.add_argument("--app",     required=True, help="App name (e.g. payments-service)")
    s.add_argument("--secrets", required=True, help="Comma-separated registry keys the app can access")
    s.add_argument("--apps",    required=True, help="Path to apps.json")

    # rm-app
    s = sub.add_parser("rm-app", help="Revoke an app's API key")
    s.add_argument("--key",  required=True, help="API key to revoke")
    s.add_argument("--apps", required=True)

    # set-secrets
    s = sub.add_parser("set-secrets", help="Update secret list for an existing app")
    s.add_argument("--app",     required=True, help="App name")
    s.add_argument("--secrets", required=True, help="Comma-separated registry keys")
    s.add_argument("--apps",    required=True)

    # gen-key
    sub.add_parser("gen-key", help="Generate a new API key (does not add to manifest)")

    # list
    s = sub.add_parser("list", help="List registry and apps")
    s.add_argument("--registry", help="Path to registry.json")
    s.add_argument("--apps",     help="Path to apps.json")

    return p


def main():
    args = build_parser().parse_args()
    dispatch = {
        "add-secret":  cmd_add_secret,
        "rm-secret":   cmd_rm_secret,
        "add-app":     cmd_add_app,
        "rm-app":      cmd_rm_app,
        "set-secrets": cmd_set_secrets,
        "gen-key":     cmd_gen_key,
        "list":        cmd_list,
    }
    try:
        dispatch[args.command](args)
    except (ValueError, KeyError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
