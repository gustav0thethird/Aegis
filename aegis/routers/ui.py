"""
ui.py — Static admin UI routes.
"""

from fastapi import APIRouter
from fastapi.responses import (
    FileResponse,
    RedirectResponse,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Admin UI
# ---------------------------------------------------------------------------

@router.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="/login", status_code=302)


@router.get("/login", include_in_schema=False)
def login_ui():
    return FileResponse("static/login.html")


@router.get("/admin", include_in_schema=False)
def admin_ui():
    return FileResponse("static/index.html")


@router.get("/dashboard", include_in_schema=False)
def dashboard_ui():
    return FileResponse("static/dashboard.html")


@router.get("/docs", include_in_schema=False)
def docs_ui():
    return FileResponse("static/docs.html")


