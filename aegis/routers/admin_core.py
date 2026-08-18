"""
admin_core.py — Admin ping, objects and registries.
"""

from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aegis.database import get_db
from aegis.deps import (
    _compute_diff,
    _get_registry,
    _obj_snapshot,
    _require_admin,
    _write_change,
)
from aegis.models import (
    Object,
    Registry,
    RegistryObject,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Admin API — ping
# ---------------------------------------------------------------------------

@router.get("/admin/api/ping")
def admin_ping(session: dict = Depends(_require_admin)):
    return {"ok": True, "role": session["role"]}


# ---------------------------------------------------------------------------
# Admin API — objects
# ---------------------------------------------------------------------------

class ObjectRequest(BaseModel):
    name:     str
    vendor:   str
    auth_ref: str
    path:     str
    platform: Optional[str] = None
    safe:     Optional[str] = None


def _obj_response(obj: Object) -> dict:
    return {
        "name":     obj.name,
        "vendor":   obj.vendor,
        "auth_ref": obj.auth_ref,
        "path":     obj.path,
        "platform": obj.platform,
        "safe":     obj.safe,
        "created_at": obj.created_at.isoformat() if obj.created_at else None,
    }


@router.get("/admin/api/objects")
def admin_list_objects(session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    objects = db.query(Object).order_by(Object.name).all()
    result = []
    for obj in objects:
        d = _obj_response(obj)
        d["registry_count"] = len(obj.registry_entries)
        result.append(d)
    return result


@router.post("/admin/api/objects", status_code=201)
def admin_create_object(req: ObjectRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    if db.query(Object).filter(Object.name == req.name).first():
        raise HTTPException(status_code=400, detail=f"Object '{req.name}' already exists")
    obj = Object(name=req.name, vendor=req.vendor, auth_ref=req.auth_ref,
                 path=req.path, platform=req.platform, safe=req.safe,
                 created_by=session["username"])
    db.add(obj)
    db.commit()
    db.refresh(obj)
    _write_change(db, "created", "object", obj.name, obj.name,
                  None, session["username"],
                  diff={"vendor": {"to": obj.vendor}, "auth_ref": {"to": obj.auth_ref},
                        "path": {"to": obj.path}, "platform": {"to": obj.platform},
                        "safe": {"to": obj.safe}})
    d = _obj_response(obj)
    d["registry_count"] = 0
    return d


class ObjectUpdateRequest(BaseModel):
    vendor:   str
    auth_ref: str
    path:     str
    platform: Optional[str] = None
    safe:     Optional[str] = None


@router.put("/admin/api/objects/{name}")
def admin_update_object(name: str, req: ObjectUpdateRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    obj = db.query(Object).filter(Object.name == name).first()
    if not obj:
        raise HTTPException(status_code=404, detail=f"Object '{name}' not found")
    before = _obj_snapshot(obj)
    obj.vendor   = req.vendor
    obj.auth_ref = req.auth_ref
    obj.path     = req.path
    obj.platform = req.platform
    obj.safe     = req.safe
    db.commit()
    db.refresh(obj)
    after = _obj_snapshot(obj)
    _write_change(db, "updated", "object", name, name,
                  None, session["username"], diff=_compute_diff(before, after))
    d = _obj_response(obj)
    d["registry_count"] = len(obj.registry_entries)
    return d


@router.delete("/admin/api/objects/{name}", status_code=204)
def admin_delete_object(name: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    obj = db.query(Object).filter(Object.name == name).first()
    if not obj:
        raise HTTPException(status_code=404, detail=f"Object '{name}' not found")
    if obj.registry_entries:
        raise HTTPException(status_code=409, detail=f"Object '{name}' is used by {len(obj.registry_entries)} registry/registries")
    snap = _obj_snapshot(obj)
    _write_change(db, "deleted", "object", name, name, None, session["username"],
                  diff={"vendor": {"from": snap["vendor"]}, "path": {"from": snap["path"]}})
    db.delete(obj)
    db.commit()


# ---------------------------------------------------------------------------
# Admin API — registries
# ---------------------------------------------------------------------------

def _reg_response(reg: Registry) -> dict:
    return {
        "id":         str(reg.id),
        "name":       reg.name,
        "created_at": reg.created_at.isoformat() if reg.created_at else None,
        "objects":    [ro.object_name for ro in reg.registry_entries],
        "team_count": len(reg.team_links),
    }


@router.get("/admin/api/registries")
def admin_list_registries(session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    regs = db.query(Registry).order_by(Registry.name).all()
    return [_reg_response(r) for r in regs]


class RegistryRequest(BaseModel):
    name: str


@router.post("/admin/api/registries", status_code=201)
def admin_create_registry(req: RegistryRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    if db.query(Registry).filter(Registry.name == req.name).first():
        raise HTTPException(status_code=400, detail=f"Registry '{req.name}' already exists")
    reg = Registry(name=req.name, created_by=session["username"])
    db.add(reg)
    db.commit()
    db.refresh(reg)
    _write_change(db, "created", "registry", str(reg.id), reg.name, None, session["username"],
                  diff={"name": {"to": reg.name}})
    return _reg_response(reg)


@router.delete("/admin/api/registries/{reg_id}", status_code=204)
def admin_delete_registry(reg_id: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    reg = _get_registry(db, reg_id)
    if reg.team_links:
        raise HTTPException(status_code=409, detail=f"Registry is assigned to {len(reg.team_links)} team(s)")
    obj_names = [ro.object_name for ro in reg.registry_entries]
    _write_change(db, "deleted", "registry", reg_id, reg.name, None, session["username"],
                  diff={"name": {"from": reg.name}, "objects": {"from": obj_names}})
    db.delete(reg)
    db.commit()


class AddObjectRequest(BaseModel):
    object_name: str


@router.post("/admin/api/registries/{reg_id}/objects", status_code=201)
def admin_add_object_to_registry(reg_id: str, req: AddObjectRequest, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    reg = _get_registry(db, reg_id)
    obj = db.query(Object).filter(Object.name == req.object_name).first()
    if not obj:
        raise HTTPException(status_code=404, detail=f"Object '{req.object_name}' not found")
    if db.query(RegistryObject).filter(RegistryObject.registry_id == reg.id, RegistryObject.object_name == req.object_name).first():
        raise HTTPException(status_code=409, detail="Object already in registry")
    db.add(RegistryObject(registry_id=reg.id, object_name=req.object_name))
    db.commit()
    db.refresh(reg)
    _write_change(db, "object_added", "registry", str(reg.id), reg.name,
                  None, session["username"],
                  diff={"objects": {"added": req.object_name}})
    return _reg_response(reg)


@router.delete("/admin/api/registries/{reg_id}/objects/{object_name}", status_code=204)
def admin_remove_object_from_registry(reg_id: str, object_name: str, session: dict = Depends(_require_admin), db: Session = Depends(get_db)):
    reg = _get_registry(db, reg_id)
    ro = db.query(RegistryObject).filter(RegistryObject.registry_id == reg.id, RegistryObject.object_name == object_name).first()
    if not ro:
        raise HTTPException(status_code=404, detail=f"Object '{object_name}' not in registry")
    db.delete(ro)
    db.commit()
    _write_change(db, "object_removed", "registry", str(reg.id), reg.name,
                  None, session["username"],
                  diff={"objects": {"removed": object_name}})




