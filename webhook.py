"""
webhook.py — HTTP webhook delivery + Slack / MS Teams / Discord notifications.

Events fired:
  key.expiring_soon  — key will expire within warning_days
  key.rotated        — key was rotated (scheduled or manual); new key in payload
  key.revoked        — key was revoked without replacement (team unassigned)
  policy.violated    — request blocked by a registry or team policy
"""

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone

import requests

logger = logging.getLogger("aegis.webhook")

WEBHOOK_TIMEOUT   = 10   # seconds per attempt
RETRY_ATTEMPTS    = 3
RETRY_BACKOFF     = [0, 5, 30]   # seconds before each attempt (0 = immediate first try)

ALL_EVENTS = {
    "key.expiring_soon",
    "key.rotated",
    "key.revoked",
    "policy.violated",
}

# Colour map shared across all formatters
_COLOURS = {
    "key.expiring_soon": {"hex": "F59E0B", "int": 0xF59E0B, "slack": "#f59e0b"},
    "key.rotated":       {"hex": "6366F1", "int": 0x6366F1, "slack": "#6366f1"},
    "key.revoked":       {"hex": "EF4444", "int": 0xEF4444, "slack": "#ef4444"},
    "policy.violated":   {"hex": "EF4444", "int": 0xEF4444, "slack": "#ef4444"},
}
_DEFAULT_COLOUR = {"hex": "94A3B8", "int": 0x94A3B8, "slack": "#94a3b8"}


def _sign(payload_str: str, secret: str) -> str:
    """Return HMAC-SHA256 hex digest of the JSON payload string."""
    return hmac.new(secret.encode(), payload_str.encode(), hashlib.sha256).hexdigest()


def build_payload(event: str, team: dict, registry: dict | None = None,
                  new_key: str | None = None, key_preview: str | None = None,
                  reason: str | None = None, detail: str | None = None) -> dict:
    return {
        "event":      event,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "team":       team,
        "registry":   registry,
        "new_key":    new_key,       # present only on key.rotated; None otherwise
        "key_preview": key_preview,
        "reason":     reason,
        "detail":     detail,
    }


# ---------------------------------------------------------------------------
# HTTP webhook delivery
# ---------------------------------------------------------------------------

def deliver(db, webhook, event: str, payload: dict) -> bool:
    """
    Deliver payload to webhook URL with optional HMAC signature.
    Logs every attempt to webhook_log. Returns True if any attempt succeeded.
    """
    from models import WebhookLog  # local import avoids circular

    if not webhook.enabled:
        return False
    if event not in (webhook.events or []):
        return False

    payload_str = json.dumps(payload, default=str)
    headers     = {
        "Content-Type":  "application/json",
        "X-Aegis-Event": event,
    }
    if getattr(webhook, "signing_enabled", False) and webhook.secret:
        sig = _sign(payload_str, webhook.secret)
        headers["X-Aegis-Signature"] = f"sha256={sig}"

    for attempt, delay in enumerate(RETRY_BACKOFF, start=1):
        if delay:
            time.sleep(delay)
        status_code = None
        success     = False
        error       = None
        try:
            resp        = requests.post(webhook.url, data=payload_str,
                                        headers=headers, timeout=WEBHOOK_TIMEOUT)
            status_code = resp.status_code
            success     = resp.ok
            if not success:
                error = f"HTTP {status_code}: {resp.text[:200]}"
        except Exception as exc:
            error = str(exc)

        log = WebhookLog(
            webhook_id=webhook.id,
            team_id=webhook.team_id,
            event=event,
            payload=payload_str,
            status_code=status_code,
            success=success,
            attempt=attempt,
            error=error,
        )
        db.add(log)
        db.commit()

        if success:
            logger.info("Webhook delivered event=%s team=%s attempt=%d", event, webhook.team_id, attempt)
            return True
        logger.warning("Webhook attempt %d failed event=%s team=%s error=%s",
                       attempt, event, webhook.team_id, error)

    return False


# ---------------------------------------------------------------------------
# Notification channel formatters
# ---------------------------------------------------------------------------

def _slack_payload(event: str, team: dict, registry: dict | None, detail: str | None) -> dict:
    colour = _COLOURS.get(event, _DEFAULT_COLOUR)["slack"]
    fields = [
        {"type": "mrkdwn", "text": f"*Team*\n{team['name']}"},
    ]
    if registry:
        fields.append({"type": "mrkdwn", "text": f"*Registry*\n{registry['name']}"})

    blocks = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f":shield: *{event}*"},
        },
        {
            "type": "section",
            "fields": fields,
        },
    ]
    if detail:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"_{detail}_"},
        })

    return {
        "text": f"Aegis: {event} — {team['name']}",
        "attachments": [{"color": colour, "blocks": blocks}],
    }


def _ms_teams_payload(event: str, team: dict, registry: dict | None, detail: str | None) -> dict:
    colour = _COLOURS.get(event, _DEFAULT_COLOUR)["hex"]
    facts  = [{"name": "Team", "value": team["name"]}]
    if registry:
        facts.append({"name": "Registry", "value": registry["name"]})
    if detail:
        facts.append({"name": "Detail", "value": detail})

    return {
        "@type":    "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": colour,
        "summary":  f"Aegis: {event}",
        "sections": [{
            "activityTitle":    f"**{event}**",
            "activitySubtitle": "Aegis Secrets Broker",
            "facts":            facts,
        }],
    }


def _discord_payload(event: str, team: dict, registry: dict | None, detail: str | None) -> dict:
    colour = _COLOURS.get(event, _DEFAULT_COLOUR)["int"]
    fields = [{"name": "Team", "value": team["name"], "inline": True}]
    if registry:
        fields.append({"name": "Registry", "value": registry["name"], "inline": True})
    if detail:
        fields.append({"name": "Detail", "value": detail, "inline": False})

    return {
        "embeds": [{
            "title":     event,
            "color":     colour,
            "fields":    fields,
            "footer":    {"text": "Aegis Secrets Broker"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }],
    }


def notify_channels(team, event: str, registry: dict | None = None,
                    detail: str | None = None) -> None:
    """
    Send Slack, MS Teams, and Discord notifications for a team event.
    Each channel fires independently — one failure doesn't block the others.
    """
    team_dict = {"id": str(team.id), "name": team.name}

    if getattr(team, "slack_webhook_url", None):
        try:
            requests.post(
                team.slack_webhook_url,
                json=_slack_payload(event, team_dict, registry, detail),
                timeout=WEBHOOK_TIMEOUT,
            )
            logger.info("Slack notification sent event=%s team=%s", event, team.id)
        except Exception as exc:
            logger.warning("Slack notification failed event=%s team=%s: %s", event, team.id, exc)

    if getattr(team, "ms_teams_webhook_url", None):
        try:
            requests.post(
                team.ms_teams_webhook_url,
                json=_ms_teams_payload(event, team_dict, registry, detail),
                timeout=WEBHOOK_TIMEOUT,
            )
            logger.info("MS Teams notification sent event=%s team=%s", event, team.id)
        except Exception as exc:
            logger.warning("MS Teams notification failed event=%s team=%s: %s", event, team.id, exc)

    if getattr(team, "discord_webhook_url", None):
        try:
            requests.post(
                team.discord_webhook_url,
                json=_discord_payload(event, team_dict, registry, detail),
                timeout=WEBHOOK_TIMEOUT,
            )
            logger.info("Discord notification sent event=%s team=%s", event, team.id)
        except Exception as exc:
            logger.warning("Discord notification failed event=%s team=%s: %s", event, team.id, exc)


# ---------------------------------------------------------------------------
# Unified fire() — HTTP webhook + all notification channels
# ---------------------------------------------------------------------------

def fire(db, team, event: str, **kwargs) -> None:
    """Build payload and deliver to HTTP webhook + all configured notification channels."""
    team_dict = {"id": str(team.id), "name": team.name}
    payload   = build_payload(event, team_dict, **kwargs)

    # HTTP webhook (with retry + logging)
    webhook = getattr(team, "webhook", None)
    if webhook and webhook.enabled and event in (webhook.events or []):
        deliver(db, webhook, event, payload)

    # Notification channels (best-effort, no retry)
    registry_dict = kwargs.get("registry")
    detail_str    = kwargs.get("detail")
    notify_channels(team, event, registry=registry_dict, detail=detail_str)
