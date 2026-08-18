"""
Integration tests for scan ingest, triage and alerting.

Requires PostgreSQL (aegis_test).

Ingest is authenticated with the team's inbound webhook secret, so findings are
attributed to a team without minting a second class of credential.
"""

import secrets as slib

from aegis.models import ScanFinding, ScanRun, Team, Webhook
from tests.conftest import ADMIN_CREDS

SECRET = "AKIAIOSFODNN7EXAMPLE"

SEMGREP = {
    "results": [{
        "check_id": "generic.secrets.aws-access-key",
        "path": "src/config.py",
        "start": {"line": 12},
        "end": {"line": 12},
        "extra": {
            "message": "AWS access key detected",
            "severity": "ERROR",
            "lines": SECRET,
            "metadata": {},
        },
    }]
}


def _unique(prefix):
    return f"{prefix}_{slib.token_hex(4)}"


def _team_with_ingest(db, signing=True):
    team = Team(name=_unique("team"), created_by="test")
    db.add(team)
    db.flush()

    secret = slib.token_hex(16)
    db.add(Webhook(
        team_id=team.id,
        url="https://hooks.example.com/aegis",
        events=["key.rotated"],
        enabled=False,
        signing_enabled=signing,
        secret=secret,
        created_by="test",
    ))
    db.commit()
    return team, secret


def _ingest(client, team, secret, *, scanner="semgrep", results=None, repository=None, **extra):
    body = {
        "scanner": scanner,
        "repository": repository or f"acme/{team.name}",
        "ref": "refs/heads/main",
        "commit_sha": "deadbeef",
        "source": "github-actions",
        "results": SEMGREP if results is None else results,
    }
    body.update(extra)
    return client.post(f"/api/scan/{team.id}/ingest",
                       headers={"Authorization": f"Bearer {secret}"},
                       json=body)


class TestIngestAuthentication:

    def test_no_token_returns_401(self, client, db):
        team, _secret = _team_with_ingest(db)
        resp = client.post(f"/api/scan/{team.id}/ingest",
                           json={"scanner": "semgrep", "repository": "a/b", "results": {}})
        assert resp.status_code == 401

    def test_wrong_token_returns_403(self, client, db):
        team, _secret = _team_with_ingest(db)
        assert _ingest(client, team, "not-the-secret").status_code == 403

    def test_unknown_team_returns_404(self, client):
        resp = client.post("/api/scan/11111111-1111-1111-1111-111111111111/ingest",
                           headers={"Authorization": "Bearer x"},
                           json={"scanner": "semgrep", "repository": "a/b", "results": {}})
        assert resp.status_code == 404

    def test_malformed_team_id_returns_404(self, client):
        resp = client.post("/api/scan/not-a-uuid/ingest",
                           headers={"Authorization": "Bearer x"},
                           json={"scanner": "semgrep", "repository": "a/b", "results": {}})
        assert resp.status_code == 404

    def test_team_without_signing_enabled_returns_403(self, client, db):
        team, secret = _team_with_ingest(db, signing=False)
        assert _ingest(client, team, secret).status_code == 403


class TestIngest:

    def test_creates_a_run_and_a_finding(self, client, db):
        team, secret = _team_with_ingest(db)
        resp = _ingest(client, team, secret)

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["findings"] == 1
        assert body["new_findings"] == 1

        run = db.get(ScanRun, body["scan_run_id"])
        assert run.scanner == "semgrep"
        assert run.source == "github-actions"
        assert run.finding_count == 1

    def test_finding_carries_location_and_rule(self, client, db):
        team, secret = _team_with_ingest(db)
        _ingest(client, team, secret)

        finding = db.query(ScanFinding).filter_by(team_id=team.id).one()
        assert finding.rule_id == "generic.secrets.aws-access-key"
        assert finding.file_path == "src/config.py"
        assert finding.line_start == 12
        assert finding.severity == "high"
        assert finding.status == "open"

    def test_the_credential_is_never_written_to_the_database(self, client, db):
        """The property that matters most: Aegis must not become a secret store."""
        team, secret = _team_with_ingest(db)
        _ingest(client, team, secret)

        finding = db.query(ScanFinding).filter_by(team_id=team.id).one()
        stored = " ".join(str(v) for v in [
            finding.title, finding.description, finding.secret_preview,
            finding.secret_hash, finding.file_path, finding.rule_id,
        ])
        assert SECRET not in stored

    def test_unsupported_scanner_returns_400(self, client, db):
        team, secret = _team_with_ingest(db)
        resp = _ingest(client, team, secret, scanner="trufflehog", results={})
        assert resp.status_code == 400
        assert "trufflehog" in resp.json()["detail"]

    def test_clean_scan_records_a_run_with_no_findings(self, client, db):
        team, secret = _team_with_ingest(db)
        resp = _ingest(client, team, secret, results={"results": []})

        assert resp.status_code == 200
        assert resp.json()["findings"] == 0
        assert resp.json()["new_findings"] == 0

    def test_gitleaks_payload_is_accepted(self, client, db):
        team, secret = _team_with_ingest(db)
        payload = [{
            "RuleID": "aws-access-token", "Description": "AWS Access Token",
            "File": "src/config.py", "StartLine": 3, "EndLine": 3, "Secret": SECRET,
        }]
        resp = _ingest(client, team, secret, scanner="gitleaks", results=payload)

        assert resp.status_code == 200
        assert resp.json()["new_findings"] == 1


class TestDedupe:

    def test_same_leak_reported_twice_does_not_duplicate(self, client, db):
        """A leak that stays in the codebase must raise one finding, not one per run."""
        team, secret = _team_with_ingest(db)
        repo = f"acme/{team.name}"

        first = _ingest(client, team, secret, repository=repo).json()
        second = _ingest(client, team, secret, repository=repo).json()

        assert first["new_findings"] == 1
        assert second["new_findings"] == 0
        assert second["findings"] == 1
        assert db.query(ScanFinding).filter_by(team_id=team.id).count() == 1

    def test_repeat_sighting_bumps_occurrences(self, client, db):
        team, secret = _team_with_ingest(db)
        repo = f"acme/{team.name}"

        _ingest(client, team, secret, repository=repo)
        _ingest(client, team, secret, repository=repo)

        finding = db.query(ScanFinding).filter_by(team_id=team.id).one()
        assert finding.occurrences == 2

    def test_triage_decision_survives_a_later_scan(self, client, db):
        """Marking something a false positive must not be undone by the next run."""
        team, secret = _team_with_ingest(db)
        repo = f"acme/{team.name}"
        _ingest(client, team, secret, repository=repo)

        finding = db.query(ScanFinding).filter_by(team_id=team.id).one()
        resp = client.patch(f"/admin/api/scan/findings/{finding.id}",
                            json={"status": "false_positive"}, auth=ADMIN_CREDS)
        assert resp.status_code == 200

        _ingest(client, team, secret, repository=repo)
        db.expire_all()
        assert db.query(ScanFinding).filter_by(team_id=team.id).one().status == "false_positive"


class TestAlerting:

    def test_no_alert_when_no_sinks_configured(self, client, db):
        team, secret = _team_with_ingest(db)
        assert _ingest(client, team, secret).json()["alerted"] == 0

    def test_alert_is_raised_for_a_new_high_finding(self, client, db, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", "webhook")
        monkeypatch.setattr("aegis.alerting.dispatch", lambda f: {
            "delivered": ["webhook"], "errors": {},
            "ticket_key": "SEC-1", "ticket_url": "https://jira/browse/SEC-1"})

        team, secret = _team_with_ingest(db)
        assert _ingest(client, team, secret).json()["alerted"] == 1

        finding = db.query(ScanFinding).filter_by(team_id=team.id).one()
        assert finding.alerted_at is not None
        assert finding.ticket_key == "SEC-1"

    def test_no_second_alert_for_the_same_finding(self, client, db, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", "webhook")
        monkeypatch.setattr("aegis.alerting.dispatch", lambda f: {
            "delivered": ["webhook"], "errors": {}, "ticket_key": None, "ticket_url": None})

        team, secret = _team_with_ingest(db)
        repo = f"acme/{team.name}"
        assert _ingest(client, team, secret, repository=repo).json()["alerted"] == 1
        assert _ingest(client, team, secret, repository=repo).json()["alerted"] == 0

    def test_below_threshold_does_not_alert(self, client, db, monkeypatch):
        monkeypatch.setenv("ALERT_SINKS", "webhook")
        monkeypatch.setenv("ALERT_MIN_SEVERITY", "critical")

        team, secret = _team_with_ingest(db)
        assert _ingest(client, team, secret).json()["alerted"] == 0

    def test_a_failing_sink_does_not_fail_the_ingest(self, client, db, monkeypatch):
        """CI must not go red because Jira is down."""
        monkeypatch.setenv("ALERT_SINKS", "jira")
        monkeypatch.setattr("aegis.alerting.dispatch", lambda f: {
            "delivered": [], "errors": {"jira": "connection refused"},
            "ticket_key": None, "ticket_url": None})

        team, secret = _team_with_ingest(db)
        resp = _ingest(client, team, secret)

        assert resp.status_code == 200
        assert resp.json()["alerted"] == 0
        assert "jira" in resp.json()["alert_errors"]

        finding = db.query(ScanFinding).filter_by(team_id=team.id).one()
        assert finding.alerted_at is None
        assert "connection refused" in finding.alert_error


class TestFindingsApi:

    def test_admin_can_list_findings(self, client, db):
        team, secret = _team_with_ingest(db)
        _ingest(client, team, secret)

        resp = client.get("/admin/api/scan/findings", auth=ADMIN_CREDS,
                          params={"team_id": str(team.id)})
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_findings_can_be_filtered_by_status(self, client, db):
        team, secret = _team_with_ingest(db)
        _ingest(client, team, secret)

        resp = client.get("/admin/api/scan/findings", auth=ADMIN_CREDS,
                          params={"team_id": str(team.id), "status": "resolved"})
        assert resp.json()["total"] == 0

    def test_status_update_is_validated(self, client, db):
        team, secret = _team_with_ingest(db)
        _ingest(client, team, secret)
        finding = db.query(ScanFinding).filter_by(team_id=team.id).one()

        resp = client.patch(f"/admin/api/scan/findings/{finding.id}",
                            json={"status": "banana"}, auth=ADMIN_CREDS)
        assert resp.status_code == 422

    def test_listing_requires_admin(self, client):
        assert client.get("/admin/api/scan/findings").status_code == 401

    def test_scan_runs_are_listed(self, client, db):
        team, secret = _team_with_ingest(db)
        repo = f"acme/{team.name}"
        _ingest(client, team, secret, repository=repo)

        resp = client.get("/admin/api/scan/runs", auth=ADMIN_CREDS,
                          params={"repository": repo})
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_response_never_carries_the_credential(self, client, db):
        team, secret = _team_with_ingest(db)
        _ingest(client, team, secret)

        resp = client.get("/admin/api/scan/findings", auth=ADMIN_CREDS,
                          params={"team_id": str(team.id)})
        assert SECRET not in resp.text
