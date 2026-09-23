"""
admin_identity.py — Identity bindings.

A binding says which workload identity may authenticate as a team-registry
pair. It holds no secret: issuer, audience, subject and claim rules are public
facts about a workload, and none of them grant anything without a token the
issuer actually signed. They are still change-logged like any other access
grant, because creating one grants access to a registry.
"""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from aegis.database import get_db
from aegis.deps import _require_admin, _write_change
from aegis.models import IdentityBinding, Registry, Team

router = APIRouter()


class IdentityBindingRequest(BaseModel):
    name: str
    issuer: str
    # Required, never defaulted: a binding that accepted any audience would
    # accept tokens a workload was issued for some other service.
    audience: str
    subject: str
    team_id: str
    registry_id: str
    claim_rules: Optional[dict] = Field(default=None)
    enabled: bool = True


class IdentityBindingUpdate(BaseModel):
    enabled: Optional[bool] = None
    claim_rules: Optional[dict] = None


def _response(row: IdentityBinding) -> dict:
    return {
        "id": str(row.id),
        "name": row.name,
        "issuer": row.issuer,
        "audience": row.audience,
        "subject": row.subject,
        "claim_rules": row.claim_rules or {},
        "team_id": str(row.team_id),
        "team_name": row.team.name if row.team else None,
        "registry_id": str(row.registry_id),
        "registry_name": row.registry.name if row.registry else None,
        "enabled": row.enabled,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "created_by": row.created_by,
        "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
    }


def _get_binding(db: Session, binding_id: str) -> IdentityBinding:
    try:
        ident = uuid.UUID(binding_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Identity binding not found") from None
    row = db.query(IdentityBinding).filter(IdentityBinding.id == ident).first()
    if not row:
        raise HTTPException(status_code=404, detail="Identity binding not found")
    return row


@router.get("/admin/api/identity-bindings")
def admin_list_identity_bindings(session: dict = Depends(_require_admin),
                                 db: Session = Depends(get_db)):
    rows = db.query(IdentityBinding).order_by(IdentityBinding.created_at.desc()).all()
    return {"bindings": [_response(r) for r in rows], "total": len(rows)}


@router.post("/admin/api/identity-bindings", status_code=201)
def admin_create_identity_binding(req: IdentityBindingRequest,
                                  session: dict = Depends(_require_admin),
                                  db: Session = Depends(get_db)):
    try:
        team_id = uuid.UUID(req.team_id)
        registry_id = uuid.UUID(req.registry_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="team_id and registry_id must be UUIDs") from None

    if not db.query(Team).filter(Team.id == team_id).first():
        raise HTTPException(status_code=404, detail="Team not found")
    if not db.query(Registry).filter(Registry.id == registry_id).first():
        raise HTTPException(status_code=404, detail="Registry not found")

    duplicate = db.query(IdentityBinding).filter(
        IdentityBinding.issuer == req.issuer,
        IdentityBinding.audience == req.audience,
        IdentityBinding.subject == req.subject,
        IdentityBinding.team_id == team_id,
        IdentityBinding.registry_id == registry_id,
    ).first()
    if duplicate:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="An identical identity binding already exists")

    row = IdentityBinding(
        name=req.name, issuer=req.issuer, audience=req.audience, subject=req.subject,
        claim_rules=req.claim_rules or None, team_id=team_id, registry_id=registry_id,
        enabled=req.enabled, created_by=session["username"])
    db.add(row)
    db.commit()
    db.refresh(row)

    _write_change(db, "created", "identity_binding", str(row.id), row.name,
                  None, session["username"],
                  diff={"issuer": {"to": row.issuer}, "audience": {"to": row.audience},
                        "subject": {"to": row.subject},
                        "team_id": {"to": str(row.team_id)},
                        "registry_id": {"to": str(row.registry_id)}})
    return _response(row)


@router.put("/admin/api/identity-bindings/{binding_id}")
def admin_update_identity_binding(binding_id: str, req: IdentityBindingUpdate,
                                  session: dict = Depends(_require_admin),
                                  db: Session = Depends(get_db)):
    """
    Only `enabled` and `claim_rules` are mutable. Changing the issuer, audience
    or subject would repoint an existing grant at a different workload, which
    should be a new binding and a deletion.
    """
    row = _get_binding(db, binding_id)
    diff = {}
    if req.enabled is not None and req.enabled != row.enabled:
        diff["enabled"] = {"from": row.enabled, "to": req.enabled}
        row.enabled = req.enabled
    if req.claim_rules is not None and req.claim_rules != (row.claim_rules or {}):
        diff["claim_rules"] = {"from": row.claim_rules or {}, "to": req.claim_rules}
        row.claim_rules = req.claim_rules or None
    if diff:
        db.commit()
        db.refresh(row)
        _write_change(db, "updated", "identity_binding", str(row.id), row.name,
                      None, session["username"], diff=diff)
    return _response(row)


@router.delete("/admin/api/identity-bindings/{binding_id}", status_code=204)
def admin_delete_identity_binding(binding_id: str, session: dict = Depends(_require_admin),
                                  db: Session = Depends(get_db)):
    row = _get_binding(db, binding_id)
    name, ident = row.name, str(row.id)
    snapshot = {"issuer": row.issuer, "audience": row.audience, "subject": row.subject}
    db.delete(row)
    db.commit()
    _write_change(db, "deleted", "identity_binding", ident, name,
                  None, session["username"],
                  diff={k: {"from": v} for k, v in snapshot.items()})
