"""
health.py — Liveness, readiness and dependency probes.
"""

from fastapi import (
    APIRouter,
    Depends,
)
from fastapi.responses import JSONResponse
from sqlalchemy import text as sa_text
from sqlalchemy.orm import Session

from aegis.database import get_db
from aegis.deps import _get_redis

router = APIRouter()

# ---------------------------------------------------------------------------
# Developer endpoints
# ---------------------------------------------------------------------------

def _dependency_status(db: Session) -> tuple[bool, dict]:
    """Probe every backing service. Returns (all_ok, per-dependency detail)."""
    details: dict = {}
    ok = True
    try:
        db.execute(sa_text("SELECT 1"))
        details["db"] = "ok"
    except Exception as e:
        details["db"] = str(e)
        ok = False
    try:
        _get_redis().ping()
        details["redis"] = "ok"
    except Exception as e:
        details["redis"] = str(e)
        ok = False
    return ok, details


@router.get("/health")
def health(db: Session = Depends(get_db)):
    """Full dependency check. Retained for existing compose/ALB/ECS health checks."""
    ok, details = _dependency_status(db)
    return JSONResponse({"status": "ok" if ok else "degraded", **details},
                        status_code=200 if ok else 503)


@router.get("/healthz")
def healthz():
    """
    Liveness probe. Deliberately checks nothing external.

    Kubernetes restarts the container when this fails, so it must only report
    failure when the process itself is unusable. Reporting a Redis or database
    outage here would turn a dependency blip into a cluster-wide restart loop,
    destroying the pods that would otherwise recover on their own.
    """
    return {"status": "ok"}


@router.get("/readyz")
def readyz(db: Session = Depends(get_db)):
    """
    Readiness probe. Fails while a backing service is unreachable, which pulls
    the pod out of the Service endpoints without restarting it.
    """
    ok, details = _dependency_status(db)
    return JSONResponse({"status": "ok" if ok else "degraded", **details},
                        status_code=200 if ok else 503)


