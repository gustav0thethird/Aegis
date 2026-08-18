"""
Guards against unqualified intra-package imports.

aegis/ is a package, so `from webhook import ALL_EVENTS` inside a function body
resolves only if the repository root happens to be on sys.path — and it fails at
call time, not at import time. That is how the webhook update and delivery paths
shipped broken. These tests catch the whole class of mistake statically.
"""

import ast
import importlib
import pathlib
from types import SimpleNamespace

import pytest

import aegis

PKG_DIR = pathlib.Path(aegis.__file__).resolve().parent
SOURCE_FILES = sorted(PKG_DIR.glob("*.py"))
MODULE_NAMES = sorted(p.stem for p in SOURCE_FILES if p.stem != "__init__")


def _imported_roots(path):
    """Yield (root_module, lineno) for every import in the file, nested ones included."""
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0], node.lineno
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split(".")[0], node.lineno


@pytest.mark.parametrize("path", SOURCE_FILES, ids=lambda p: p.name)
def test_no_unqualified_intra_package_imports(path):
    offenders = [
        f"{path.name}:{lineno} imports '{root}' — use 'aegis.{root}'"
        for root, lineno in _imported_roots(path)
        if root in MODULE_NAMES
    ]
    assert not offenders, "unqualified intra-package imports: " + "; ".join(offenders)


@pytest.mark.parametrize("name", MODULE_NAMES)
def test_every_module_is_importable(name):
    importlib.import_module(f"aegis.{name}")


def test_webhook_event_catalogue_is_importable():
    """The symbol api.py pulls in when a team updates its webhook config."""
    from aegis.webhook import ALL_EVENTS

    assert "key.rotated" in ALL_EVENTS


def test_deliver_resolves_its_lazy_model_import():
    """
    deliver() imports WebhookLog on its first line, so calling it with a disabled
    webhook exercises that import and returns before touching the database.
    """
    from aegis import webhook

    disabled = SimpleNamespace(enabled=False)
    assert webhook.deliver(None, disabled, "key.rotated", {}) is False
