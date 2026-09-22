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
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from aegis import errors, url_guard

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


def include_rotated_key() -> bool:
    """
    Whether a key.rotated event carries the plaintext key.

    Off by default. Signing proves an event came from Aegis; it says nothing
    about what the receiver does with it, so shipping the credential to an
    ordinary HTTP endpoint widens its trust boundary to that endpoint, its
    proxy, its logs and its monitoring.

    Subscribers learn that a rotation happened and which key it replaced. The
    key itself is returned to whoever asked for the rotation, in the response
    to their authenticated request - including the CI/CD inbound webhook,
    which returns it to the caller that triggered it.
    """
    return os.environ.get("WEBHOOK_INCLUDE_ROTATED_KEY", "false").strip().lower() == "true"


def build_payload(event: str, team: dict, registry: dict | None = None,
                  new_key: str | None = None, key_preview: str | None = None,
                  reason: str | None = None, detail: str | None = None) -> dict:
    return {
        "event":      event,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "team":       team,
        "registry":   registry,
        # Opt-in; see include_rotated_key(). key_preview identifies which key
        # rotated either way.
        "new_key":    new_key if include_rotated_key() else None,
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
    from aegis.models import WebhookLog  # local import avoids circular

    if not webhook.enabled:
        return False
    if event not in (webhook.events or []):
        return False

    # Sent over the wire and signed; contains the plaintext key on a rotation.
    payload_str = json.dumps(payload, default=str)
    # Written to webhook_log; never contains a credential. The delivery record
    # keeps key_preview, which is enough to correlate a rotation with a key.
    log_payload_str = json.dumps(errors.redact(payload), default=str)
    headers     = {
        "Content-Type":  "application/json",
        "X-Aegis-Event": event,
    }
    if getattr(webhook, "signing_enabled", False) and webhook.secret:
        sig = _sign(payload_str, webhook.secret)
        headers["X-Aegis-Signature"] = f"sha256={sig}"

    # Re-checked at delivery time: rows stored before URL validation existed
    # are still in the database, and DNS may have moved since the write.
    reason = url_guard.check_url(webhook.url)
    if reason:
        logger.error("Webhook delivery blocked event=%s team=%s: %s",
                     event, webhook.team_id, reason)
        db.add(WebhookLog(
            webhook_id=webhook.id,
            team_id=webhook.team_id,
            event=event,
            payload=log_payload_str,
            status_code=None,
            success=False,
            attempt=1,
            error=f"blocked by URL policy: {reason}",
        ))
        db.commit()
        return False

    for attempt, delay in enumerate(RETRY_BACKOFF, start=1):
        if delay:
            time.sleep(delay)
        status_code = None
        success     = False
        error       = None
        try:
            # url_guard.request re-validates and pins the connection to the
            # address it resolved, so a short-TTL rebind between the check
            # above and this call cannot redirect the payload.
            resp        = url_guard.request("POST", webhook.url, data=payload_str,
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
            payload=log_payload_str,
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


def _channel_url(team, attr: str, event: str) -> str | None:
    """Return the channel URL only if it is set and still safe to request."""
    url = getattr(team, attr, None)
    if not url:
        return None
    reason = url_guard.check_url(url)
    if reason:
        logger.error("%s blocked event=%s team=%s: %s", attr, event, team.id, reason)
        return None
    return url


def notify_channels(team, event: str, registry: dict | None = None,
                    detail: str | None = None) -> None:
    """
    Send Slack, MS Teams, and Discord notifications for a team event.
    Each channel fires independently — one failure doesn't block the others.
    """
    team_dict = {"id": str(team.id), "name": team.name}

    slack_url = _channel_url(team, "slack_webhook_url", event)
    if slack_url:
        try:
            url_guard.request(
                "POST", slack_url,
                json=_slack_payload(event, team_dict, registry, detail),
                timeout=WEBHOOK_TIMEOUT,
            )
            logger.info("Slack notification sent event=%s team=%s", event, team.id)
        except Exception as exc:
            logger.warning("Slack notification failed event=%s team=%s: %s", event, team.id, exc)

    ms_teams_url = _channel_url(team, "ms_teams_webhook_url", event)
    if ms_teams_url:
        try:
            url_guard.request(
                "POST", ms_teams_url,
                json=_ms_teams_payload(event, team_dict, registry, detail),
                timeout=WEBHOOK_TIMEOUT,
            )
            logger.info("MS Teams notification sent event=%s team=%s", event, team.id)
        except Exception as exc:
            logger.warning("MS Teams notification failed event=%s team=%s: %s", event, team.id, exc)

    discord_url = _channel_url(team, "discord_webhook_url", event)
    if discord_url:
        try:
            url_guard.request(
                "POST", discord_url,
                json=_discord_payload(event, team_dict, registry, detail),
                timeout=WEBHOOK_TIMEOUT,
            )
            logger.info("Discord notification sent event=%s team=%s", event, team.id)
        except Exception as exc:
            logger.warning("Discord notification failed event=%s team=%s: %s", event, team.id, exc)


# ---------------------------------------------------------------------------
# Unified fire() — HTTP webhook + all notification channels
# ---------------------------------------------------------------------------

# Delivery runs off the request path by default.
#
# deliver() sleeps between retries (0s, 5s, 30s) around attempts that each
# allow 10s, and notify_channels() adds further outbound calls. Firing an
# event inline therefore added up to a minute and a half to the response -
# and policy violations fire an event, so anyone able to trigger a 403 could
# make the service spend a worker on their behalf.
#
# Delivery is best-effort either way: this is a notification path, and its
# outcome is recorded in webhook_log. A worker pool is deliberately modest -
# a durable outbox is the right answer if delivery ever has to survive a
# restart, and is tracked separately.
_pool: ThreadPoolExecutor | None = None


def _executor() -> ThreadPoolExecutor:
    global _pool
    if _pool is None:
        _pool = ThreadPoolExecutor(
            max_workers=int(os.environ.get("WEBHOOK_WORKERS", "4")),
            thread_name_prefix="aegis-webhook",
        )
    return _pool


def _dispatch_is_sync() -> bool:
    """
    Whether the caller waits for delivery.

    Background is the default. Sync exists for deterministic tests and for
    deployments that would rather a request fail than an event be missed.
    """
    return os.environ.get("WEBHOOK_DISPATCH_MODE", "background").strip().lower() == "sync"


def _fire_now(team_id, webhook_id, event: str, payload: dict, registry, detail) -> None:
    """
    Deliver in a worker thread.

    Only identifiers cross the thread boundary. ORM objects belong to the
    request's session, which is closed by the time this runs, so the rows are
    loaded again here; the alternative is a DetachedInstanceError on the first
    attribute access.
    """
    from aegis.database import SessionLocal
    from aegis.models import Team, Webhook

    db = SessionLocal()
    try:
        team = db.query(Team).filter(Team.id == team_id).first()
        if team is None:
            return
        if webhook_id is not None:
            webhook = db.query(Webhook).filter(Webhook.id == webhook_id).first()
            if webhook is not None:
                deliver(db, webhook, event, payload)
        notify_channels(team, event, registry=registry, detail=detail)
    except Exception as exc:
        logger.error("Webhook dispatch failed event=%s team=%s: %s",
                     event, team_id, type(exc).__name__)
    finally:
        db.close()


def fire(db, team, event: str, **kwargs) -> None:
    """
    Build the payload and deliver it to the team's webhook and notification
    channels. Returns as soon as the work is queued unless
    WEBHOOK_DISPATCH_MODE=sync.
    """
    team_dict = {"id": str(team.id), "name": team.name}
    payload   = build_payload(event, team_dict, **kwargs)

    webhook = getattr(team, "webhook", None)
    if not (webhook and webhook.enabled and event in (webhook.events or [])):
        webhook = None

    registry_dict = kwargs.get("registry")
    detail_str    = kwargs.get("detail")

    if _dispatch_is_sync():
        if webhook is not None:
            deliver(db, webhook, event, payload)
        notify_channels(team, event, registry=registry_dict, detail=detail_str)
        return

    channels = any(getattr(team, attr, None) for attr in
                   ("slack_webhook_url", "ms_teams_webhook_url", "discord_webhook_url"))
    if webhook is None and not channels:
        # Nothing to deliver; skip the thread entirely.
        return

    _executor().submit(_fire_now, team.id, (webhook.id if webhook is not None else None),
                       event, payload, registry_dict, detail_str)
