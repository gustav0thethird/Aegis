"""
Unit tests for finding alerts and ticket creation.

No network: requests and smtplib are stubbed. The behaviours worth protecting
are that one broken integration cannot silence the others, that a finding is
announced once rather than on every pipeline run, and that no alert carries the
credential it is reporting.
"""

from unittest.mock import MagicMock, patch

import pytest

from aegis import alerting

FINDING = {
    "id": "11111111-1111-1111-1111-111111111111",
    "fingerprint": "abc123",
    "repository": "acme/payments",
    "ref": "refs/heads/main",
    "commit_sha": "deadbeef",
    "scanner": "gitleaks",
    "rule_id": "aws-access-token",
    "severity": "high",
    "title": "AWS Access Token",
    "file_path": "src/config.py",
    "line_start": 12,
    "secret_preview": "AKIA********(20 chars)",
    "validated": True,
    "status": "open",
    "alerted_at": None,
    "team": "payments",
}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in [
        "ALERT_SINKS", "ALERT_MIN_SEVERITY", "AEGIS_BASE_URL",
        "JIRA_URL", "JIRA_USER", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY", "JIRA_ISSUE_TYPE",
        "SERVICENOW_URL", "SERVICENOW_USER", "SERVICENOW_PASSWORD", "SERVICENOW_TABLE",
        "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM",
        "SMTP_STARTTLS", "ALERT_EMAIL_TO", "ALERT_WEBHOOK_URL",
        "WEBHOOK_ALLOWED_SCHEMES", "WEBHOOK_ALLOWED_HOSTS",
    ]:
        monkeypatch.delenv(var, raising=False)


def _response(status=201, payload=None):
    resp = MagicMock()
    resp.ok = 200 <= status < 300
    resp.status_code = status
    resp.json.return_value = payload or {}
    resp.text = "response body"
    return resp


class TestConfiguration:

    def test_no_sinks_by_default(self):
        assert alerting.configured_sinks() == []

    def test_sinks_are_parsed_and_normalised(self, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", " Jira , webhook ,")
        assert alerting.configured_sinks() == ["jira", "webhook"]

    def test_default_threshold_is_high(self):
        assert alerting.min_severity() == "high"


class TestShouldAlert:

    def test_not_when_no_sinks_configured(self):
        assert alerting.should_alert(FINDING) is False

    def test_yes_at_threshold(self, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", "webhook")
        assert alerting.should_alert(FINDING) is True

    def test_no_below_threshold(self, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", "webhook")
        assert alerting.should_alert(dict(FINDING, severity="low")) is False

    def test_threshold_is_configurable(self, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", "webhook")
        monkeypatch.setenv("ALERT_MIN_SEVERITY", "low")
        assert alerting.should_alert(dict(FINDING, severity="low")) is True

    def test_not_twice_for_the_same_finding(self, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", "webhook")
        assert alerting.should_alert(dict(FINDING, alerted_at="2026-01-01")) is False

    def test_not_for_a_triaged_finding(self, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", "webhook")
        assert alerting.should_alert(dict(FINDING, status="false_positive")) is False


class TestMessageBody:

    def test_contains_the_useful_context(self):
        body = alerting.describe(FINDING)
        assert "acme/payments" in body
        assert "src/config.py" in body
        assert "aws-access-token" in body

    def test_carries_the_masked_preview_only(self):
        body = alerting.describe(FINDING)
        assert "AKIA********(20 chars)" in body
        assert "AKIAIOSFODNN7EXAMPLE" not in body

    def test_states_the_remediation(self):
        assert "rotate" in alerting.describe(FINDING).lower()

    def test_links_back_when_a_base_url_is_set(self, monkeypatch):
        monkeypatch.setenv("AEGIS_BASE_URL", "https://aegis.example.com/")
        assert "https://aegis.example.com/admin/scan-findings/" in alerting.describe(FINDING)

    def test_summary_names_severity_and_repository(self):
        line = alerting.summary_line(FINDING)
        assert "HIGH" in line
        assert "acme/payments" in line


class TestJira:

    def _configure(self, monkeypatch):
        monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
        monkeypatch.setenv("JIRA_USER", "bot@example.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "token")
        monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")

    def test_creates_an_issue_and_returns_its_key_and_url(self, monkeypatch):
        self._configure(monkeypatch)
        with patch("aegis.alerting.requests.post",
                   return_value=_response(201, {"key": "SEC-42"})) as post:
            key, url = alerting.send_jira(FINDING)

        assert key == "SEC-42"
        assert url == "https://jira.example.com/browse/SEC-42"
        assert post.call_args[0][0] == "https://jira.example.com/rest/api/3/issue"

    def test_uses_atlassian_document_format(self, monkeypatch):
        """Jira Cloud v3 rejects a plain string description."""
        self._configure(monkeypatch)
        with patch("aegis.alerting.requests.post",
                   return_value=_response(201, {"key": "SEC-1"})) as post:
            alerting.send_jira(FINDING)

        description = post.call_args.kwargs["json"]["fields"]["description"]
        assert description["type"] == "doc"
        assert description["version"] == 1

    def test_missing_configuration_is_reported_clearly(self):
        with pytest.raises(alerting.AlertError, match="JIRA_URL"):
            alerting.send_jira(FINDING)

    def test_http_error_raises(self, monkeypatch):
        self._configure(monkeypatch)
        with patch("aegis.alerting.requests.post", return_value=_response(403)):
            with pytest.raises(alerting.AlertError, match="403"):
                alerting.send_jira(FINDING)

    def test_self_hosted_private_address_is_allowed(self, monkeypatch):
        """An internal Jira is a normal deployment, not an SSRF attempt."""
        self._configure(monkeypatch)
        monkeypatch.setenv("JIRA_URL", "https://10.0.0.5")
        with patch("aegis.alerting.requests.post",
                   return_value=_response(201, {"key": "SEC-9"})):
            key, _ = alerting.send_jira(FINDING)
        assert key == "SEC-9"

    def test_plaintext_destination_is_rejected(self, monkeypatch):
        self._configure(monkeypatch)
        monkeypatch.setenv("JIRA_URL", "http://jira.example.com")
        with pytest.raises(alerting.AlertError, match="scheme"):
            alerting.send_jira(FINDING)


class TestServiceNow:

    def _configure(self, monkeypatch):
        monkeypatch.setenv("SERVICENOW_URL", "https://acme.service-now.com")
        monkeypatch.setenv("SERVICENOW_USER", "bot")
        monkeypatch.setenv("SERVICENOW_PASSWORD", "pw")

    def test_creates_an_incident(self, monkeypatch):
        self._configure(monkeypatch)
        payload = {"result": {"number": "INC0012345", "sys_id": "abc"}}
        with patch("aegis.alerting.requests.post",
                   return_value=_response(201, payload)) as post:
            number, url = alerting.send_servicenow(FINDING)

        assert number == "INC0012345"
        assert "sys_id=abc" in url
        assert post.call_args[0][0].endswith("/api/now/table/incident")

    def test_table_is_configurable(self, monkeypatch):
        self._configure(monkeypatch)
        monkeypatch.setenv("SERVICENOW_TABLE", "sn_si_incident")
        with patch("aegis.alerting.requests.post",
                   return_value=_response(201, {"result": {}})) as post:
            alerting.send_servicenow(FINDING)
        assert post.call_args[0][0].endswith("/api/now/table/sn_si_incident")

    def test_high_severity_maps_to_top_urgency(self, monkeypatch):
        self._configure(monkeypatch)
        with patch("aegis.alerting.requests.post",
                   return_value=_response(201, {"result": {}})) as post:
            alerting.send_servicenow(FINDING)
        assert post.call_args.kwargs["json"]["urgency"] == "1"


class TestEmail:

    def _configure(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_FROM", "aegis@example.com")
        monkeypatch.setenv("ALERT_EMAIL_TO", "security@example.com, ops@example.com")

    def test_sends_to_every_recipient(self, monkeypatch):
        self._configure(monkeypatch)
        smtp = MagicMock()
        with patch("aegis.alerting.smtplib.SMTP") as ctor:
            ctor.return_value.__enter__.return_value = smtp
            alerting.send_email(FINDING)

        message = smtp.send_message.call_args[0][0]
        assert "security@example.com" in message["To"]
        assert "ops@example.com" in message["To"]

    def test_uses_starttls_by_default(self, monkeypatch):
        self._configure(monkeypatch)
        smtp = MagicMock()
        with patch("aegis.alerting.smtplib.SMTP") as ctor:
            ctor.return_value.__enter__.return_value = smtp
            alerting.send_email(FINDING)
        smtp.starttls.assert_called_once()

    def test_starttls_can_be_disabled(self, monkeypatch):
        self._configure(monkeypatch)
        monkeypatch.setenv("SMTP_STARTTLS", "false")
        smtp = MagicMock()
        with patch("aegis.alerting.smtplib.SMTP") as ctor:
            ctor.return_value.__enter__.return_value = smtp
            alerting.send_email(FINDING)
        smtp.starttls.assert_not_called()

    def test_body_carries_no_credential(self, monkeypatch):
        self._configure(monkeypatch)
        smtp = MagicMock()
        with patch("aegis.alerting.smtplib.SMTP") as ctor:
            ctor.return_value.__enter__.return_value = smtp
            alerting.send_email(FINDING)
        body = smtp.send_message.call_args[0][0].get_content()
        assert "AKIAIOSFODNN7EXAMPLE" not in body

    def test_missing_recipients_raise(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_FROM", "aegis@example.com")
        with pytest.raises(alerting.AlertError, match="ALERT_EMAIL_TO"):
            alerting.send_email(FINDING)


class TestWebhook:

    def test_posts_the_finding(self, monkeypatch):
        monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example.com/aegis")
        with patch("aegis.alerting.requests.post", return_value=_response(200)) as post:
            alerting.send_webhook(FINDING)

        body = post.call_args.kwargs["json"]
        assert body["event"] == "scan.secret_detected"
        assert body["repository"] == "acme/payments"
        assert body["secret_preview"] == "AKIA********(20 chars)"


class TestDispatch:

    def test_no_sinks_delivers_nothing(self):
        result = alerting.dispatch(FINDING)
        assert result["delivered"] == []
        assert result["errors"] == {}

    def test_one_failing_sink_does_not_stop_the_others(self, monkeypatch):
        """The alert that gets dropped would be the one about a live credential."""
        monkeypatch.setenv("ALERT_SINKS", "jira,webhook")
        monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example.com/aegis")
        # Jira is unconfigured and will fail.
        with patch("aegis.alerting.requests.post", return_value=_response(200)):
            result = alerting.dispatch(FINDING)

        assert result["delivered"] == ["webhook"]
        assert "jira" in result["errors"]

    def test_never_raises(self, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", "jira")
        with patch("aegis.alerting.requests.post", side_effect=RuntimeError("boom")):
            result = alerting.dispatch(FINDING)
        assert result["delivered"] == []
        assert "jira" in result["errors"]

    def test_unknown_sink_is_recorded_not_ignored(self, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", "carrier-pigeon")
        result = alerting.dispatch(FINDING)
        assert "carrier-pigeon" in result["errors"]

    def test_ticket_reference_is_captured(self, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", "jira")
        monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
        monkeypatch.setenv("JIRA_USER", "bot")
        monkeypatch.setenv("JIRA_API_TOKEN", "t")
        monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")
        with patch("aegis.alerting.requests.post",
                   return_value=_response(201, {"key": "SEC-7"})):
            result = alerting.dispatch(FINDING)

        assert result["ticket_key"] == "SEC-7"
        assert result["ticket_url"].endswith("/browse/SEC-7")
