"""
eso.py — External Secrets Operator provider.
"""

from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    Security,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from aegis.database import get_db
from aegis.deps import (
    _authenticate_registry_key,
    _eso_registry_extract_allowed,
    _fetch_for_key,
    bearer,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# External Secrets Operator provider
#
# ESO's generic `webhook` provider calls these endpoints and extracts the value
# with a JSON path, which lets a Kubernetes cluster materialise brokered secrets
# without giving workloads credentials for the underlying vaults.
#
#   ClusterSecretStore -> GET /eso/v1/secret/{name}   jsonPath $.value
#   (dataFrom.extract) -> GET /eso/v1/secrets         jsonPath $.data
#
# Authentication, policy enforcement, auditing and revocation are identical to
# /secrets — this is a response shape for ESO, not a second way in.
# ---------------------------------------------------------------------------

@router.get("/eso/v1/secrets")
def eso_get_all(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(bearer),
    x_change_number: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """Whole registry, shaped for ESO dataFrom.extract (jsonPath: $.data)."""
    if not _eso_registry_extract_allowed():
        raise HTTPException(
            status_code=403,
            detail="Whole-registry extraction is disabled; fetch objects individually")
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    source_ip  = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    key_row = _authenticate_registry_key(db, credentials.credentials, source_ip, user_agent)
    fetched = _fetch_for_key(db, key_row, x_change_number, source_ip, user_agent,
                             use_cache=True)
    return {
        "data": fetched,
        "registry": key_row.registry.name,
        "team": key_row.team.name,
    }


@router.get("/eso/v1/secret/{object_name}")
def eso_get_one(
    object_name: str,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(bearer),
    x_change_number: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """Single object, shaped for ESO data[].remoteRef (jsonPath: $.value)."""
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    source_ip  = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    key_row = _authenticate_registry_key(db, credentials.credentials, source_ip, user_agent)
    fetched = _fetch_for_key(db, key_row, x_change_number, source_ip, user_agent,
                             only=object_name, use_cache=True)
    return {"key": object_name, "value": fetched[object_name]}


