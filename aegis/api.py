"""
api.py — FastAPI service for the Aegis.

Developer endpoint:
  GET  /health
  GET  /secrets      Bearer = registry API key, X-Change-Number header required

Auth:
  POST /api/login    username + password → session token
  POST /api/logout
  GET  /api/me
  PUT  /api/me/theme

User (role=user, self-service):
  GET  /api/my-teams   (plural; /api/my-team kept as backward-compat alias)
  GET  /api/my-webhook           — view webhook + notification channels
  PUT  /api/my-webhook           — configure outgoing webhook + notifications
  DELETE /api/my-webhook         — remove webhook
  GET  /api/my-metrics           — team-scoped audit counts + key stats
  GET  /api/my-metrics/prometheus — team-scoped Prometheus metrics (for Grafana)
  POST /api/inbound/{team_id}    — inbound webhook receiver (CI/CD trigger); Bearer = signing secret

UI:
  GET  /             → redirect to /login
  GET  /login        Standalone login page (redirects to /admin or /dashboard on success)
  GET  /admin        Admin panel (role=admin)
  GET  /dashboard    Team dashboard (role=user)
  GET  /docs         API documentation + companion tester

Admin API (session token with role=admin OR HTTP Basic with an admin account):
  GET    /admin/api/ping

  Objects: GET/POST/PUT/DELETE /admin/api/objects[/{name}]

  Registries: GET/POST/DELETE /admin/api/registries[/{id}]
              POST   /admin/api/registries/{id}/objects
              DELETE /admin/api/registries/{id}/objects/{name}

  Teams: GET/POST/DELETE /admin/api/teams[/{id}]
         POST/DELETE /admin/api/teams/{id}/registries/{reg_id}
         POST        /admin/api/teams/{team_id}/registries/{reg_id}/rotate-key

  Users: GET/POST /admin/api/users
         PUT/DELETE /admin/api/users/{id}

  Settings: GET/PUT /admin/api/settings

  Logs: GET /admin/api/changelog
        GET /admin/api/audit
"""

import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as _StarletteHTTPException

from aegis import scheduler
from aegis.database import SessionLocal
from aegis.deps import _hash_pw
from aegis.models import User
from aegis.routers import (
    admin_config,
    admin_core,
    admin_logs,
    admin_teams,
    admin_users,
    admin_webhooks,
    eso,
    health,
    metrics,
    scanning,
    secrets,
    self_service,
    session,
    ui,
)
from aegis.siem import start_s3_flush_thread

logger = logging.getLogger("aegis")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Aegis", version="2.0.0", docs_url=None, redoc_url=None)

# Start the S3 flush thread if S3 is a configured log destination.
_destinations = os.environ.get("LOG_DESTINATIONS", "stdout").lower()
if "s3" in _destinations:
    start_s3_flush_thread()

# Startup — seed default admin user if none exists
# ---------------------------------------------------------------------------

@app.on_event("startup")
def _seed_admin():
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.role == "admin").first():
            admin_pw = os.environ.get("ADMIN_PASSWORD", "changeme")
            db.add(User(
                username="admin",
                password_hash=_hash_pw(admin_pw),
                role="admin",
                theme="default",
                created_by="system",
            ))
            db.commit()
            logger.info("Seeded default admin user")
    finally:
        db.close()


@app.on_event("startup")
def _start_scheduler():
    """
    Start the background key-expiry scheduler.

    This was never called, so keys with an expiry policy were never rotated and
    key.expiring_soon never fired. The job takes an advisory lock, so running a
    scheduler in every replica is safe.
    """
    if os.environ.get("SCHEDULER_ENABLED", "true").strip().lower() == "false":
        logger.info("Scheduler disabled by SCHEDULER_ENABLED=false")
        return
    scheduler.start()


# ---------------------------------------------------------------------------
# 404 / error handlers
# ---------------------------------------------------------------------------

# Paths that always answer in JSON, never with the HTML error page.
_JSON_PREFIXES = ("/api/", "/admin/api/", "/eso/")
_JSON_PATHS = {"/health", "/healthz", "/readyz", "/secrets", "/metrics"}


def _wants_json(path: str) -> bool:
    return path in _JSON_PATHS or path.startswith(_JSON_PREFIXES)


@app.exception_handler(_StarletteHTTPException)
async def http_exception_handler(request: Request, exc: _StarletteHTTPException):
    # API paths return JSON
    if _wants_json(request.url.path):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    # UI paths return the 404 page for 404s, JSON for everything else
    if exc.status_code == 404:
        return FileResponse("static/404.html", status_code=404)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)




# ---------------------------------------------------------------------------
# Routers
#
# Each module owns one domain and imports what it needs from aegis.deps. This
# file does assembly only: nothing here should grow request-handling logic.
# ---------------------------------------------------------------------------

app.include_router(ui.router)
app.include_router(health.router)
app.include_router(session.router)
app.include_router(self_service.router)
app.include_router(secrets.router)
app.include_router(eso.router)
app.include_router(scanning.router)
app.include_router(metrics.router)
app.include_router(admin_core.router)
app.include_router(admin_teams.router)
app.include_router(admin_users.router)
app.include_router(admin_config.router)
app.include_router(admin_logs.router)
app.include_router(admin_webhooks.router)

app.mount("/static", StaticFiles(directory="static"), name="static")
