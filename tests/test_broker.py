"""
Unit tests for broker.py — auth config lookup and vendor routing.
No database or network required; external calls are mocked.
"""

import pytest
from unittest.mock import patch

from aegis.broker import _auth_cfg, fetch_secrets
from aegis.functions import _auth_key, cyberark_logon

AUTH = {
    "vault": {
        "prod": {"addr": "https://vault.example.com", "token": "s.test"},
    },
    "cyberark": {
        "prod": {"host": "cyberark.example.com", "app_id": "TestApp",
                 "auth_safe": "Safe", "auth_object": "Obj"},
    },
    "aws": {
        "prod": {"region": "us-east-1"},
    },
    "conjur": {
        "prod": {"host": "conjur.example.com", "account": "org",
                 "login": "host/broker", "api_key": "key"},
    },
}


def _obj(name, vendor, auth_ref="prod", path="secret/test"):
    return {"name": name, "vendor": vendor, "auth_ref": auth_ref,
            "path": path, "platform": None, "safe": None}


class TestAuthCfg:
    def test_returns_config_for_known_vendor_and_ref(self):
        cfg = _auth_cfg(AUTH, "vault", "prod", "my_secret")
        assert cfg["addr"] == "https://vault.example.com"

    def test_raises_for_unknown_vendor(self):
        with pytest.raises(ValueError, match="No auth config"):
            _auth_cfg(AUTH, "nonexistent_vendor", "prod", "x")

    def test_raises_for_unknown_ref(self):
        with pytest.raises(ValueError, match="No auth config"):
            _auth_cfg(AUTH, "vault", "staging", "x")

    def test_error_includes_object_name(self):
        with pytest.raises(ValueError, match="my_secret"):
            _auth_cfg(AUTH, "vault", "missing_ref", "my_secret")


class TestFetchSecrets:
    def test_vault_routing(self):
        objects = [_obj("db_pass", "vault", path="secret/db_pass")]
        with patch("aegis.broker.vault_get", return_value="s3cr3t") as mock:
            result = fetch_secrets(objects, AUTH)
        assert result == {"db_pass": "s3cr3t"}
        mock.assert_called_once_with("secret/db_pass", AUTH["vault"]["prod"])

    def test_aws_routing(self):
        objects = [_obj("aws_key", "aws", path="arn:aws:secretsmanager:us-east-1:123:secret:key")]
        with patch("aegis.broker.aws_get", return_value="aws_val") as mock:
            result = fetch_secrets(objects, AUTH)
        assert result == {"aws_key": "aws_val"}
        mock.assert_called_once()

    def test_conjur_routing(self):
        objects = [_obj("conjur_secret", "conjur", path="secrets/my-app/db")]
        with patch("aegis.broker.conjur_get", return_value="conjur_val") as mock:
            result = fetch_secrets(objects, AUTH)
        assert result == {"conjur_secret": "conjur_val"}
        mock.assert_called_once()

    def test_multiple_objects_different_vendors(self):
        objects = [
            _obj("vault_obj", "vault"),
            _obj("aws_obj",   "aws"),
        ]
        with patch("aegis.broker.vault_get", return_value="v_val"), \
             patch("aegis.broker.aws_get",   return_value="a_val"):
            result = fetch_secrets(objects, AUTH)
        assert result == {"vault_obj": "v_val", "aws_obj": "a_val"}

    def test_unknown_vendor_collected_as_error(self):
        objects = [_obj("bad", "unknown_vendor")]
        with pytest.raises(ValueError, match="unknown vendor 'unknown_vendor'"):
            fetch_secrets(objects, AUTH)

    def test_missing_auth_ref_raises(self):
        objects = [_obj("x", "vault", auth_ref="nonexistent")]
        with pytest.raises(ValueError, match="No auth config"):
            fetch_secrets(objects, AUTH)

    def test_all_vendors_attempted_before_raising(self):
        """A failure in one vendor must not prevent other vendors from running."""
        objects = [
            _obj("bad",  "vault"),
            _obj("good", "aws"),
        ]
        with patch("aegis.broker.vault_get", side_effect=Exception("vault down")), \
             patch("aegis.broker.aws_get",   return_value="ok") as mock_aws:
            with pytest.raises(ValueError, match="vault down"):
                fetch_secrets(objects, AUTH)
        # aws_get was still called despite vault failure
        mock_aws.assert_called_once()

    def test_cyberark_shares_session_across_same_auth_ref(self):
        """Objects sharing an auth_ref should reuse one CyberArk logon session."""
        objects = [
            _obj("obj1", "cyberark", path="Account1"),
            _obj("obj2", "cyberark", path="Account2"),
        ]
        with patch("aegis.broker.cyberark_logon", return_value={"token": "tok"}) as mock_logon, \
             patch("aegis.broker.cyberark_find_account", return_value="acct_id"), \
             patch("aegis.broker.cyberark_get", return_value="secret_val"):
            fetch_secrets(objects, AUTH)
        # One logon for two objects sharing the same auth_ref
        mock_logon.assert_called_once()


CYBERARK_OBJ = {
    "name": "db_pass", "vendor": "cyberark", "auth_ref": "prod",
    "path": "AccountObjectName", "platform": "WinDomain", "safe": "App-Safe",
}


class TestCyberArkArgumentMapping:
    """
    Guards the broker -> functions call contract.

    autospec binds every mock to the real signature, so an argument-count or
    ordering mismatch fails here instead of silently reaching PVWA at runtime.
    """

    def test_find_account_gets_platform_safe_name_token_host(self):
        with patch("aegis.broker.cyberark_logon", autospec=True,
                   return_value={"token": "pvwa-token"}), \
             patch("aegis.broker.cyberark_find_account", autospec=True,
                   return_value="acct-42") as mock_find, \
             patch("aegis.broker.cyberark_get", autospec=True, return_value="s3cr3t"):
            result = fetch_secrets([dict(CYBERARK_OBJ)], AUTH)

        assert result == {"db_pass": "s3cr3t"}
        mock_find.assert_called_once_with(
            "WinDomain",             # platform
            "App-Safe",              # safe
            "AccountObjectName",     # name (object path)
            "pvwa-token",            # token, unwrapped from the logon result
            "cyberark.example.com",  # host, from the auth config
        )

    def test_get_gets_account_id_token_host(self):
        with patch("aegis.broker.cyberark_logon", autospec=True,
                   return_value={"token": "pvwa-token"}), \
             patch("aegis.broker.cyberark_find_account", autospec=True,
                   return_value="acct-42"), \
             patch("aegis.broker.cyberark_get", autospec=True,
                   return_value="s3cr3t") as mock_get:
            fetch_secrets([dict(CYBERARK_OBJ)], AUTH)

        mock_get.assert_called_once_with("acct-42", "pvwa-token", "cyberark.example.com")

    def test_token_and_host_are_strings_not_config_dicts(self):
        """Regression: cfg and the logon dict used to be passed as token and host."""
        seen = {}

        def _find(platform, safe, name, token, host):
            seen.update(token=token, host=host, platform=platform, safe=safe, name=name)
            return "acct-42"

        with patch("aegis.broker.cyberark_logon", autospec=True,
                   return_value={"token": "pvwa-token"}), \
             patch("aegis.broker.cyberark_find_account", autospec=True, side_effect=_find), \
             patch("aegis.broker.cyberark_get", autospec=True, return_value="s3cr3t"):
            fetch_secrets([dict(CYBERARK_OBJ)], AUTH)

        for field in ("token", "host", "platform", "safe", "name"):
            assert isinstance(seen[field], str), f"{field} should be a str, got {type(seen[field])}"


class TestCyberArkAuthKeys:
    """cyberark_logon must read the auth.json keys the docs and example config use."""

    def test_reads_documented_key_names(self):
        cfg = {"host": "h", "app_id": "a", "auth_safe": "S", "auth_object": "O"}
        assert _auth_key(cfg, "auth_safe", "safe") == "S"
        assert _auth_key(cfg, "auth_object", "svc_object") == "O"

    def test_accepts_legacy_key_names(self):
        cfg = {"host": "h", "app_id": "a", "safe": "S", "svc_object": "O"}
        assert _auth_key(cfg, "auth_safe", "safe") == "S"
        assert _auth_key(cfg, "auth_object", "svc_object") == "O"

    def test_missing_key_raises_named_error(self):
        with pytest.raises(ValueError, match="auth_safe"):
            _auth_key({"host": "h"}, "auth_safe", "safe")

    def test_logon_does_not_keyerror_on_example_config(self):
        """The shipped auth.json.example shape must reach the HTTP call, not KeyError."""
        with patch("aegis.functions.requests.get", side_effect=RuntimeError("network")), \
             pytest.raises(RuntimeError, match="network"):
            cyberark_logon(AUTH["cyberark"]["prod"])
