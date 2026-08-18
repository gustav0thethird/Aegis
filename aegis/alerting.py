"""
alerting.py — Raise a ticket or alert when a secret is found in source code.

A finding nobody sees is not a control. When a scanner reports a credential in
a repository, this module opens a ticket and notifies the owning team through
whichever channels the deployment has configured.

Sinks: Jira, ServiceNow, email (SMTP), generic webhook. Each fires
independently — one broken integration must not suppress the others, because
the alert that gets dropped is the one about a live credential.

Destinations and their credentials come from the environment, never from the
database. A secrets broker storing its own integration passwords in a table it
also serves would be the same mistake it exists to prevent.

Config:
  ALERT_SINKS         — comma-separated: jira,servicenow,email,webhook (default: none)
  ALERT_MIN_SEVERITY  — info|low|medium|high|critical (default: high)
  AEGIS_BASE_URL      — used to link tickets back to the finding in Aegis

  JIRA_URL, JIRA_USER, JIRA_API_TOKEN, JIRA_PROJECT_KEY
  JIRA_ISSUE_TYPE                 (default: Task)

  SERVICENOW_URL, SERVICENOW_USER, SERVICENOW_PASSWORD
  SERVICENOW_TABLE                (default: incident)

  SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASSWORD,
  SMTP_FROM, SMTP_STARTTLS (true), ALERT_EMAIL_TO

  ALERT_WEBHOOK_URL
"""

import logging
import os
import smtplib
from email.message import EmailMessage

import requests

from aegis import scanning, url_guard

logger = logging.getLogger("aegis.alerting")

TIMEOUT = 15

# ServiceNow urgency: 1 high, 2 medium, 3 low.
_SNOW_URGENCY = {"critical": "1", "high": "1", "medium": "2", "low": "3", "info": "3"}


class AlertError(RuntimeError):
    """A sink could not deliver."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def configured_sinks() -> list[str]:
    raw = os.environ.get("ALERT_SINKS", "")
    return [s.strip().lower() for s in raw.split(",") if s.strip()]


def min_severity() -> str:
    return os.environ.get("ALERT_MIN_SEVERITY", "high").strip().lower()


def should_alert(finding: dict) -> bool:
    """
    Alert only for findings at or above the configured severity, and only once.

    Re-alerting on a finding already raised turns the channel into noise, and a
    team that has learned to ignore secret alerts is worse off than one that
    never had them.
    """
    if not configured_sinks():
        return False
    if finding.get("alerted_at"):
        return False
    if finding.get("status") not in (None, "open"):
        return False
    return scanning.meets_threshold(finding.get("severity", ""), min_severity())


# ---------------------------------------------------------------------------
# Message construction
# ---------------------------------------------------------------------------

def _finding_url(finding: dict) -> str:
    base = os.environ.get("AEGIS_BASE_URL", "").rstrip("/")
    return f"{base}/admin/scan-findings/{finding.get('id')}" if base else ""


def summary_line(finding: dict) -> str:
    return (
        f"[Aegis] {finding.get('severity', 'unknown').upper()} — secret detected in "
        f"{finding.get('repository', 'unknown repository')}"
    )


def describe(finding: dict) -> str:
    """Plain-text body shared by every sink. Contains no credential material."""
    lines = [
        f"A secret scanner reported a credential in {finding.get('repository')}.",
        "",
        f"Severity   : {finding.get('severity')}",
        f"Scanner    : {finding.get('scanner')}",
        f"Rule       : {finding.get('rule_id')}",
        f"Repository : {finding.get('repository')}",
        f"Ref        : {finding.get('ref') or '-'}",
        f"Commit     : {finding.get('commit_sha') or '-'}",
        f"Location   : {finding.get('file_path')}:{finding.get('line_start') or '?'}",
        f"Match      : {finding.get('secret_preview') or '(masked)'}",
        f"Validated  : {'yes — confirmed live' if finding.get('validated') else 'not confirmed'}",
        f"Team       : {finding.get('team') or '-'}",
        "",
        "The credential itself is not stored by Aegis and is not included here.",
        "",
        "Recommended action: revoke and rotate the credential at its source, then",
        "remove it from version control history.",
    ]
    url = _finding_url(finding)
    if url:
        lines += ["", f"Finding in Aegis: {url}"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------

def _require(*names: str) -> list[str]:
    values = []
    for name in names:
        value = os.environ.get(name, "").strip()
        if not value:
            raise AlertError(f"{name} is not set")
        values.append(value)
    return values


def _checked_url(url: str, field: str) -> str:
    """
    Operator-configured destination: private addresses are allowed (self-hosted
    Jira and ServiceNow are normal), but the scheme and credential rules still
    apply so alerts are not posted over plaintext.
    """
    try:
        return url_guard.validate_url(url, field, allow_private=True)
    except ValueError as exc:
        # Sinks raise AlertError; dispatch() records it against the sink name.
        raise AlertError(str(exc)) from exc


def send_jira(finding: dict) -> tuple[str | None, str | None]:
    base, user, token, project = _require(
        "JIRA_URL", "JIRA_USER", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY")
    base = _checked_url(base, "JIRA_URL").rstrip("/")
    issue_type = os.environ.get("JIRA_ISSUE_TYPE", "Task")

    body = {
        "fields": {
            "project": {"key": project},
            "summary": summary_line(finding),
            "issuetype": {"name": issue_type},
            # Jira Cloud's v3 API takes Atlassian Document Format, not a string.
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": describe(finding)}],
                }],
            },
        }
    }

    resp = requests.post(f"{base}/rest/api/3/issue", json=body,
                         auth=(user, token), timeout=TIMEOUT)
    if not resp.ok:
        raise AlertError(f"Jira responded {resp.status_code}: {resp.text[:200]}")

    key = (resp.json() or {}).get("key")
    return key, (f"{base}/browse/{key}" if key else None)


def send_servicenow(finding: dict) -> tuple[str | None, str | None]:
    base, user, password = _require(
        "SERVICENOW_URL", "SERVICENOW_USER", "SERVICENOW_PASSWORD")
    base = _checked_url(base, "SERVICENOW_URL").rstrip("/")
    table = os.environ.get("SERVICENOW_TABLE", "incident")

    body = {
        "short_description": summary_line(finding),
        "description": describe(finding),
        "category": "security",
        "urgency": _SNOW_URGENCY.get(finding.get("severity", ""), "2"),
    }

    resp = requests.post(f"{base}/api/now/table/{table}", json=body,
                         auth=(user, password), timeout=TIMEOUT,
                         headers={"Accept": "application/json"})
    if not resp.ok:
        raise AlertError(f"ServiceNow responded {resp.status_code}: {resp.text[:200]}")

    result = (resp.json() or {}).get("result", {}) or {}
    number = result.get("number")
    sys_id = result.get("sys_id")
    url = f"{base}/nav_to.do?uri={table}.do?sys_id={sys_id}" if sys_id else None
    return number, url


def send_email(finding: dict) -> tuple[str | None, str | None]:
    host, sender, recipients_raw = _require("SMTP_HOST", "SMTP_FROM", "ALERT_EMAIL_TO")
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if not recipients:
        raise AlertError("ALERT_EMAIL_TO contained no addresses")

    port = int(os.environ.get("SMTP_PORT", "587"))
    use_starttls = os.environ.get("SMTP_STARTTLS", "true").strip().lower() != "false"
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASSWORD", "")

    message = EmailMessage()
    message["Subject"] = summary_line(finding)
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message.set_content(describe(finding))

    with smtplib.SMTP(host, port, timeout=TIMEOUT) as smtp:
        if use_starttls:
            smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.send_message(message)

    return None, None


def send_webhook(finding: dict) -> tuple[str | None, str | None]:
    (url,) = _require("ALERT_WEBHOOK_URL")
    url = _checked_url(url, "ALERT_WEBHOOK_URL")

    payload = {
        "event": "scan.secret_detected",
        "severity": finding.get("severity"),
        "repository": finding.get("repository"),
        "ref": finding.get("ref"),
        "commit_sha": finding.get("commit_sha"),
        "scanner": finding.get("scanner"),
        "rule_id": finding.get("rule_id"),
        "file_path": finding.get("file_path"),
        "line_start": finding.get("line_start"),
        "secret_preview": finding.get("secret_preview"),
        "validated": finding.get("validated"),
        "team": finding.get("team"),
        "fingerprint": finding.get("fingerprint"),
        "url": _finding_url(finding),
    }
    resp = requests.post(url, json=payload, timeout=TIMEOUT)
    if not resp.ok:
        raise AlertError(f"Webhook responded {resp.status_code}: {resp.text[:200]}")
    return None, None


_SINKS = {
    "jira": send_jira,
    "servicenow": send_servicenow,
    "email": send_email,
    "webhook": send_webhook,
}

SUPPORTED_SINKS = sorted(_SINKS)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def dispatch(finding: dict) -> dict:
    """
    Send `finding` to every configured sink.

    Returns {"delivered": [...], "errors": {sink: message}, "ticket_key":,
    "ticket_url":}. Never raises: a finding that could not be announced still
    has to be recorded, and losing the record too would leave nothing behind.
    """
    delivered: list[str] = []
    errors: dict[str, str] = {}
    ticket_key = ticket_url = None

    for name in configured_sinks():
        sink = _SINKS.get(name)
        if sink is None:
            errors[name] = f"unknown sink (supported: {', '.join(SUPPORTED_SINKS)})"
            logger.warning("Unknown alert sink configured: %s", name)
            continue
        try:
            key, url = sink(finding)
            delivered.append(name)
            # First sink that returns a ticket reference wins; Jira and
            # ServiceNow are not normally both enabled.
            if key and not ticket_key:
                ticket_key, ticket_url = key, url
            logger.info("Alert delivered sink=%s repository=%s severity=%s",
                        name, finding.get("repository"), finding.get("severity"))
        except Exception as exc:
            errors[name] = str(exc)
            logger.error("Alert sink %s failed for %s: %s",
                         name, finding.get("repository"), exc)

    return {
        "delivered": delivered,
        "errors": errors,
        "ticket_key": ticket_key,
        "ticket_url": ticket_url,
    }
