"""
Third-party credentials in settings never leave the database in the clear,
and never enter the change log.

`PUT /admin/api/settings` recorded {"from": "<old value>", "to": "<new value>"}
for every key it touched, including splunk_hec_token and dd_api_key. The
change log is described as an append-only audit trail, so that turned it into
a credential archive with no way to redact after the fact. `GET` returned
every settings row verbatim, which also exposed the scan dedupe key - an HMAC
key whose whole purpose is that nobody else knows it.

Requires PostgreSQL (aegis_test).
"""
import pytest

from aegis.models import ChangeLog, Setting
from aegis.routers.admin_config import REDACTED
from tests.conftest import ADMIN_CREDS

TOKEN = "splunk-hec-token-d41d8cd98f00"


@pytest.fixture(autouse=True)
def clean_settings(db, _schema):
    keys = ["splunk_hec_token", "dd_api_key", "key_warning_days", "rate_limit_rpm"]

    def _wipe():
        db.query(Setting).filter(Setting.key.in_([*keys, "scan.dedupe_key"])).delete(
            synchronize_session=False)
        db.query(ChangeLog).filter(ChangeLog.entity_type == "settings").delete(
            synchronize_session=False)
        db.commit()
    _wipe()
    yield
    _wipe()


class TestCredentialsStayOutOfTheChangeLog:

    def test_setting_a_credential_records_only_that_it_changed(self, client, db):
        resp = client.put("/admin/api/settings", auth=ADMIN_CREDS,
                          json={"settings": {"splunk_hec_token": TOKEN}})
        assert resp.status_code == 200, resp.text

        entry = (db.query(ChangeLog)
                   .filter(ChangeLog.entity_type == "settings")
                   .order_by(ChangeLog.id.desc()).first())
        assert entry is not None
        assert entry.diff["splunk_hec_token"] == {"changed": True}
        assert TOKEN not in str(entry.diff)

    def test_replacing_a_credential_does_not_archive_the_old_one(self, client, db):
        client.put("/admin/api/settings", auth=ADMIN_CREDS,
                   json={"settings": {"dd_api_key": "first-key-value"}})
        client.put("/admin/api/settings", auth=ADMIN_CREDS,
                   json={"settings": {"dd_api_key": "second-key-value"}})

        rows = db.query(ChangeLog).filter(ChangeLog.entity_type == "settings").all()
        blob = " ".join(str(r.diff) for r in rows)
        assert "first-key-value" not in blob
        assert "second-key-value" not in blob

    def test_ordinary_settings_still_record_their_values(self, client, db):
        """Redaction is for credentials; an audit trail that records nothing is useless."""
        resp = client.put("/admin/api/settings", auth=ADMIN_CREDS,
                          json={"settings": {"rate_limit_rpm": "120"}})
        assert resp.status_code == 200
        entry = (db.query(ChangeLog)
                   .filter(ChangeLog.entity_type == "settings")
                   .order_by(ChangeLog.id.desc()).first())
        assert entry.diff["rate_limit_rpm"]["to"] == "120"


class TestCredentialsAreNotReadBack:

    def test_a_set_credential_reads_back_redacted(self, client):
        client.put("/admin/api/settings", auth=ADMIN_CREDS,
                   json={"settings": {"splunk_hec_token": TOKEN}})
        body = client.get("/admin/api/settings", auth=ADMIN_CREDS).json()
        assert body["splunk_hec_token"] == REDACTED
        assert TOKEN not in str(body)

    def test_an_unset_credential_is_distinguishable_from_a_set_one(self, client, db):
        db.add(Setting(key="dd_api_key", value="", updated_by="test"))
        db.commit()
        body = client.get("/admin/api/settings", auth=ADMIN_CREDS).json()
        assert body["dd_api_key"] == ""

    def test_internal_keys_are_not_exposed(self, client, db):
        """The scan dedupe key is an HMAC key, not a setting to display."""
        db.add(Setting(key="scan.dedupe_key", value="a" * 64, updated_by="system"))
        db.commit()
        body = client.get("/admin/api/settings", auth=ADMIN_CREDS).json()
        assert "scan.dedupe_key" not in body

    def test_saving_a_redacted_value_does_not_erase_the_credential(self, client, db):
        """
        The settings form posts back what it was given, so an untouched
        credential arrives as the marker. Writing it would replace the real
        token with asterisks.
        """
        client.put("/admin/api/settings", auth=ADMIN_CREDS,
                   json={"settings": {"splunk_hec_token": TOKEN}})
        client.put("/admin/api/settings", auth=ADMIN_CREDS,
                   json={"settings": {"splunk_hec_token": REDACTED,
                                      "rate_limit_rpm": "90"}})

        stored = db.query(Setting).filter(Setting.key == "splunk_hec_token").one()
        db.refresh(stored)
        assert stored.value == TOKEN, "redaction marker overwrote the real credential"
        assert db.query(Setting).filter(Setting.key == "rate_limit_rpm").one().value == "90"


class TestEditableSettings:

    def test_key_warning_days_can_be_saved(self, client, db):
        """
        The scheduler reads it and the settings form submits it, but it was
        missing from EDITABLE_SETTINGS - so the whole request was rejected and
        no general setting could be saved from the admin panel.
        """
        resp = client.put("/admin/api/settings", auth=ADMIN_CREDS,
                          json={"settings": {"key_warning_days": "14",
                                             "rate_limit_rpm": "60"}})
        assert resp.status_code == 200, resp.text
        assert db.query(Setting).filter(Setting.key == "key_warning_days").one().value == "14"

    def test_unknown_settings_are_still_rejected(self, client):
        resp = client.put("/admin/api/settings", auth=ADMIN_CREDS,
                          json={"settings": {"not_a_setting": "x"}})
        assert resp.status_code == 400
