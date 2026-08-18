"""
secrets.py — Developer secret retrieval.
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
    _fetch_for_key,
    bearer,
)

router = APIRouter()


@router.get("/secrets")
def get_secrets(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(bearer),
    x_change_number: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    source_ip  = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    key_row = _authenticate_registry_key(db, credentials.credentials, source_ip, user_agent)
    return _fetch_for_key(db, key_row, x_change_number, source_ip, user_agent)


