"""
scanning.py — Secret scanning ingest, triage and alerting.
"""

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import (
    datetime,
    timezone,
)
from typing import (
    Any,
    Optional,
)

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aegis import (
    alerting,
    scanning,
)
from aegis.database import (
    SessionLocal,
    get_db,
)
from aegis.deps import (
    _authenticate_team_webhook,
    _require_admin,
    _require_any_user,
    _resolve_user_team,
    _write_change,
    logger,
)
from aegis.models import (
    ScanFinding,
    ScanRun,
    Team,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Secret scanning — ingest, triage and alerting
#
# Aegis does not run scanners. Semgrep, Gitleaks or anything else runs where the
# code is and POSTs its results here, authenticated with the team's inbound
# webhook secret so findings are attributed to a team without issuing a second
# class of credential.
#
# The matched credential is never stored: see aegis/scanning.py.
# ---------------------------------------------------------------------------

# A scan reporting hundreds of findings must not hold the request open while
# every one of them opens a ticket. Anything past the cap stays un-alerted and
# is picked up by the next run or by an explicit re-alert.
_ALERT_MAX_PER_RUN = int(os.environ.get("ALERT_MAX_PER_RUN", "25"))


class ScanIngestRequest(BaseModel):
    scanner: str                                 # semgrep | gitleaks | aegis
    repository: str
    ref: Optional[str] = None
    commit_sha: Optional[str] = None
    scanner_version: Optional[str] = None
    source: Optional[str] = None                 # github-actions | pre-commit | manual
    results: Any = None                          # raw scanner output



def _finding_payload(finding: ScanFinding, team: Team) -> dict:
    """Plain dict for the alerting sinks, so they never touch the ORM."""
    return {
        "id": str(finding.id),
        "fingerprint": finding.fingerprint,
        "repository": finding.repository,
        "ref": finding.ref,
        "commit_sha": finding.commit_sha,
        "scanner": finding.scanner,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "title": finding.title,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "secret_preview": finding.secret_preview,
        "validated": finding.validated,
        "status": finding.status,
        "alerted_at": finding.alerted_at,
        "team": team.name,
    }


def _raise_alert(db: Session, finding: ScanFinding, team: Team) -> dict:
    """Dispatch a finding to the configured sinks and record the outcome."""
    result = alerting.dispatch(_finding_payload(finding, team))
    if result["delivered"]:
        finding.alerted_at = datetime.now(timezone.utc)
        if result["ticket_key"]:
            finding.ticket_key = result["ticket_key"]
            finding.ticket_url = result["ticket_url"]
    finding.alert_error = "; ".join(f"{k}: {v}" for k, v in result["errors"].items()) or None
    return result


# A small pool: alerting talks to Jira, ServiceNow and SMTP, and flooding them
# with concurrent requests from a burst of scans helps nobody.
_alert_pool: Optional[ThreadPoolExecutor] = None


def _alert_executor() -> ThreadPoolExecutor:
    global _alert_pool
    if _alert_pool is None:
        _alert_pool = ThreadPoolExecutor(
            max_workers=int(os.environ.get("ALERT_WORKERS", "2")),
            thread_name_prefix="aegis-alert",
        )
    return _alert_pool


def _alert_dispatch_is_sync() -> bool:
    """
    Whether ingest waits for alerts to be delivered.

    Background is the default: a slow or unreachable Jira should not hold a CI
    request open. Sync exists for deployments that want the pipeline to block
    until a ticket exists, and for deterministic tests.
    """
    return os.environ.get("ALERT_DISPATCH_MODE", "background").strip().lower() == "sync"


def _dispatch_alerts(finding_ids: list, team_id) -> dict:
    """
    Deliver alerts for the given findings and record the outcome on each.

    Runs on its own database session so it is safe off the request thread. The
    findings must already be committed before this is called.
    """
    delivered = 0
    errors: dict[str, str] = {}
    db = SessionLocal()
    try:
        team = db.get(Team, team_id)
        if team is None:
            return {"delivered": 0, "errors": {"team": "team no longer exists"}}
        for finding_id in finding_ids:
            finding = db.get(ScanFinding, finding_id)
            if finding is None:
                continue
            # Re-checked here: the finding may have been triaged, or alerted by
            # a concurrent run, between queueing and delivery.
            if not alerting.should_alert(_finding_payload(finding, team)):
                continue
            result = _raise_alert(db, finding, team)
            errors.update(result["errors"])
            if result["delivered"]:
                delivered += 1
        db.commit()
    except Exception as exc:
        logger.error("Alert dispatch failed: %s", exc)
        db.rollback()
        errors["dispatch"] = str(exc)
    finally:
        db.close()
    return {"delivered": delivered, "errors": errors}


@router.post("/api/scan/{team_id_str}/ingest")
def api_scan_ingest(
    team_id_str: str,
    req: ScanIngestRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Accept scanner output for a repository owned by this team.

    Findings are deduplicated by fingerprint across runs, so a leak that stays
    in the codebase raises one ticket rather than one per pipeline run.
    """
    team = _authenticate_team_webhook(db, team_id_str, request)

    try:
        findings = scanning.normalize(req.scanner, req.results, req.repository)
    except scanning.UnsupportedScanner as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    run = ScanRun(
        team_id=team.id,
        repository=req.repository,
        ref=req.ref,
        commit_sha=req.commit_sha,
        scanner=req.scanner.lower(),
        scanner_version=req.scanner_version,
        source=req.source,
        finding_count=len(findings),
    )
    db.add(run)
    db.flush()

    now = datetime.now(timezone.utc)
    new_rows: list[ScanFinding] = []

    for item in findings:
        existing = db.query(ScanFinding).filter(
            ScanFinding.fingerprint == item["fingerprint"]
        ).first()

        if existing:
            # Same leak seen again: refresh where it was last observed, but keep
            # first_seen_at and any triage decision already made.
            existing.occurrences += 1
            existing.last_seen_at = now
            existing.ref = req.ref or existing.ref
            existing.commit_sha = req.commit_sha or existing.commit_sha
            existing.line_start = item["line_start"] or existing.line_start
            existing.line_end = item["line_end"] or existing.line_end
            existing.scan_run_id = run.id
            continue

        row = ScanFinding(
            fingerprint=item["fingerprint"],
            scan_run_id=run.id,
            team_id=team.id,
            repository=req.repository,
            ref=req.ref,
            commit_sha=req.commit_sha,
            scanner=req.scanner.lower(),
            rule_id=item["rule_id"],
            severity=item["severity"],
            title=item["title"],
            description=item["description"],
            file_path=item["file_path"],
            line_start=item["line_start"],
            line_end=item["line_end"],
            secret_hash=item["secret_hash"],
            secret_preview=item["secret_preview"],
            validated=item["validated"],
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(row)
        new_rows.append(row)

    run.new_finding_count = len(new_rows)
    db.flush()

    # Select what to alert on, then commit before dispatching: the background
    # worker uses its own session and can only see committed rows.
    to_alert = [
        row.id for row in new_rows
        if alerting.should_alert(_finding_payload(row, team))
    ][:_ALERT_MAX_PER_RUN]

    db.commit()

    alert_errors: dict[str, str] = {}
    # In sync mode the count is knowable, so report a real number even when
    # nothing qualified. In background mode it is not yet known, hence None.
    delivered = 0 if _alert_dispatch_is_sync() else None
    if to_alert:
        if _alert_dispatch_is_sync():
            result = _dispatch_alerts(to_alert, team.id)
            delivered = result["delivered"]
            alert_errors = result["errors"]
        else:
            _alert_executor().submit(_dispatch_alerts, list(to_alert), team.id)

    logger.info("Scan ingested team=%s repo=%s scanner=%s findings=%d new=%d queued=%d",
                team.name, req.repository, req.scanner,
                len(findings), len(new_rows), len(to_alert))

    return {
        "ok": True,
        "scan_run_id": str(run.id),
        "findings": len(findings),
        "new_findings": len(new_rows),
        # Findings handed to the alert sinks. Delivery happens off this request
        # unless ALERT_DISPATCH_MODE=sync, so "queued" is what can honestly be
        # reported here; per-finding outcome lands on the finding itself.
        "alerts_queued": len(to_alert),
        "alerted": delivered,
        "alert_errors": alert_errors or None,
    }


def _finding_response(f: ScanFinding) -> dict:
    return {
        "id": str(f.id),
        "fingerprint": f.fingerprint,
        "repository": f.repository,
        "ref": f.ref,
        "commit_sha": f.commit_sha,
        "scanner": f.scanner,
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "file_path": f.file_path,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "secret_preview": f.secret_preview,
        "validated": f.validated,
        "status": f.status,
        "occurrences": f.occurrences,
        "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
        "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
        "ticket_key": f.ticket_key,
        "ticket_url": f.ticket_url,
        "alerted_at": f.alerted_at.isoformat() if f.alerted_at else None,
        "alert_error": f.alert_error,
    }


def _query_findings(db, *, team_id=None, status=None, severity=None, repository=None):
    q = db.query(ScanFinding)
    if team_id:
        q = q.filter(ScanFinding.team_id == team_id)
    if status:
        q = q.filter(ScanFinding.status == status)
    if severity:
        q = q.filter(ScanFinding.severity == severity)
    if repository:
        q = q.filter(ScanFinding.repository == repository)
    return q.order_by(ScanFinding.last_seen_at.desc())


@router.get("/admin/api/scan/findings")
def admin_scan_findings(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    repository: Optional[str] = None,
    team_id: Optional[str] = None,
    page: int = 1,
    limit: int = 25,
    session: dict = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    limit = min(limit, 100)
    tid = None
    if team_id:
        try:
            tid = uuid.UUID(team_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid team_id") from None

    q = _query_findings(db, team_id=tid, status=status, severity=severity,
                        repository=repository)
    total = q.count()
    rows = q.offset((page - 1) * limit).limit(limit).all()
    return {"total": total, "page": page, "limit": limit,
            "rows": [_finding_response(f) for f in rows]}


class ScanFindingUpdate(BaseModel):
    status: str            # open | triaged | resolved | false_positive


_FINDING_STATUSES = {"open", "triaged", "resolved", "false_positive"}


@router.patch("/admin/api/scan/findings/{finding_id}")
def admin_update_scan_finding(
    finding_id: str,
    req: ScanFindingUpdate,
    session: dict = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    if req.status not in _FINDING_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"status must be one of {sorted(_FINDING_STATUSES)}")
    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found") from None

    finding = db.get(ScanFinding, fid)
    if not finding:
        raise HTTPException(status_code=404, detail="Not found")

    before = finding.status
    finding.status = req.status
    finding.updated_by = session["username"]
    db.commit()

    _write_change(db, "updated", "scan_finding", str(finding.id), finding.repository,
                  performed_by=session["username"],
                  diff={"status": {"from": before, "to": req.status}})
    return _finding_response(finding)


@router.post("/admin/api/scan/findings/{finding_id}/alert")
def admin_alert_scan_finding(
    finding_id: str,
    session: dict = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    """Re-send a finding to the configured sinks — for a failed or capped alert."""
    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found") from None

    finding = db.get(ScanFinding, fid)
    if not finding:
        raise HTTPException(status_code=404, detail="Not found")
    if not alerting.configured_sinks():
        raise HTTPException(status_code=400, detail="No alert sinks are configured")

    result = _raise_alert(db, finding, finding.team)
    db.commit()
    return {"delivered": result["delivered"], "errors": result["errors"] or None,
            "ticket_key": finding.ticket_key, "ticket_url": finding.ticket_url}


@router.get("/admin/api/scan/runs")
def admin_scan_runs(
    repository: Optional[str] = None,
    page: int = 1,
    limit: int = 25,
    session: dict = Depends(_require_admin),
    db: Session = Depends(get_db),
):
    limit = min(limit, 100)
    q = db.query(ScanRun)
    if repository:
        q = q.filter(ScanRun.repository == repository)
    q = q.order_by(ScanRun.created_at.desc())
    total = q.count()
    rows = q.offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total, "page": page, "limit": limit,
        "rows": [{
            "id": str(r.id),
            "repository": r.repository,
            "ref": r.ref,
            "commit_sha": r.commit_sha,
            "scanner": r.scanner,
            "scanner_version": r.scanner_version,
            "source": r.source,
            "finding_count": r.finding_count,
            "new_finding_count": r.new_finding_count,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        } for r in rows],
    }


@router.get("/api/my-scan-findings")
def api_my_scan_findings(
    team_id: Optional[str] = None,
    status: Optional[str] = "open",
    page: int = 1,
    limit: int = 25,
    session: dict = Depends(_require_any_user),
    db: Session = Depends(get_db),
):
    """A team's own findings, scoped by team membership."""
    team = _resolve_user_team(session, db, team_id)
    limit = min(limit, 100)
    q = _query_findings(db, team_id=team.id, status=status)
    total = q.count()
    rows = q.offset((page - 1) * limit).limit(limit).all()
    return {"team_id": str(team.id), "team_name": team.name,
            "total": total, "page": page, "limit": limit,
            "rows": [_finding_response(f) for f in rows]}
