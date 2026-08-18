"""
admin_webhooks.py — Admin team webhooks.
"""

import secrets as secrets_lib
from typing import List

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aegis import webhook as wh
from aegis.database import get_db
from aegis.deps import (
    _get_team,
    _require_admin,
    _validated_url,
    _write_change,
)
from aegis.models import (
    Webhook,
    WebhookLog,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Admin API — webhooks
# ---------------------------------------------------------------------------

class WebhookRequest(BaseModel):
    url:             str
    events:          List[str]
    enabled:         bool = True
    signing_enabled: bool = False


def _webhook_response(w: Webhook) -> dict:
    return {
        "id":              str(w.id),
        "team_id":         str(w.team_id),
        "url":             w.url,
        "events":          w.events,
        "enabled":         w.enabled,
        "signing_enabled": w.signing_enabled,
        "created_at":      w.created_at.isoformat(),
    }


@router.get("/admin/api/teams/{team_id}/webhook")
def admin_get_webhook(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    return _webhook_response(team.webhook) if team.webhook else {}


@router.put("/admin/api/teams/{team_id}/webhook", status_code=200)
def admin_set_webhook(team_id: str, req: WebhookRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team    = _get_team(db, team_id)
    unknown = set(req.events) - wh.ALL_EVENTS
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown event types: {unknown}")

    req.url = _validated_url(req.url, "url")

    new_secret = None
    if team.webhook:
        w                 = team.webhook
        w.url             = req.url
        w.events          = req.events
        w.enabled         = req.enabled
        # Enable signing: generate secret if not already set
        if req.signing_enabled and not w.signing_enabled:
            new_secret        = secrets_lib.token_urlsafe(32)
            w.secret          = new_secret
            w.signing_enabled = True
        elif not req.signing_enabled:
            w.signing_enabled = False
            w.secret          = None
    else:
        new_secret = secrets_lib.token_urlsafe(32) if req.signing_enabled else None
        w = Webhook(team_id=team.id, url=req.url, secret=new_secret,
                    signing_enabled=req.signing_enabled,
                    events=req.events, enabled=req.enabled,
                    created_by=session["username"])
        db.add(w)
    db.commit()
    db.refresh(w)
    _write_change(db, "updated", "team", str(team.id), team.name,
                  "webhook configured", session["username"])
    resp = _webhook_response(w)
    if new_secret:
        resp["new_secret"] = new_secret   # returned once when signing first enabled
    return resp


@router.post("/admin/api/teams/{team_id}/webhook/regenerate-secret", status_code=200)
def admin_regenerate_webhook_secret(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    if not team.webhook:
        raise HTTPException(status_code=404, detail="No webhook configured for this team")
    if not team.webhook.signing_enabled:
        raise HTTPException(status_code=400, detail="Signing is not enabled for this webhook")
    new_secret          = secrets_lib.token_urlsafe(32)
    team.webhook.secret = new_secret
    db.commit()
    _write_change(db, "updated", "team", str(team.id), team.name,
                  "webhook secret regenerated", session["username"])
    return {"new_secret": new_secret}


@router.delete("/admin/api/teams/{team_id}/webhook", status_code=204)
def admin_delete_webhook(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    if team.webhook:
        db.delete(team.webhook)
        db.commit()
        _write_change(db, "deleted", "team", str(team.id), team.name,
                      "webhook removed", session["username"])


@router.post("/admin/api/teams/{team_id}/webhook/test", status_code=200)
def admin_test_webhook(team_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team = _get_team(db, team_id)
    if not team.webhook:
        raise HTTPException(status_code=404, detail="No webhook configured for this team")
    payload = wh.build_payload(
        "key.expiring_soon",
        team={"id": str(team.id), "name": team.name},
        detail="This is a test delivery from Aegis",
    )
    ok = wh.deliver(db, team.webhook, "key.expiring_soon", payload)
    return {"success": ok}


@router.get("/admin/api/teams/{team_id}/webhook/log")
def admin_webhook_log(team_id: str, page: int = 1, limit: int = 25,
                      session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    team  = _get_team(db, team_id)
    limit = min(limit, 100)
    q     = db.query(WebhookLog).filter(WebhookLog.team_id == team.id)\
              .order_by(WebhookLog.fired_at.desc())
    total = q.count()
    rows  = q.offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total, "page": page, "limit": limit,
        "rows": [{
            "id":          r.id,
            "event":       r.event,
            "status_code": r.status_code,
            "success":     r.success,
            "attempt":     r.attempt,
            "error":       r.error,
            "fired_at":    r.fired_at.isoformat(),
        } for r in rows],
    }


