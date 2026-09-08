"""Dashboard + audit endpoints."""

import datetime
from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from .deps import current_user

router = APIRouter(prefix="/api/v1", tags=["dashboard"])


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db),
              user=Depends(current_user)):
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    week_ago = now - datetime.timedelta(days=7)
    findings = db.query(models.Finding).filter(
        models.Finding.org_id == user.org_id).all()
    scans = db.query(models.Scan).filter(
        models.Scan.org_id == user.org_id).all()
    targets = db.query(models.Target).filter(
        models.Target.org_id == user.org_id,
        models.Target.archived == False).count()  # noqa: E712
    open_sev = defaultdict(int)
    status_count = defaultdict(int)
    for f in findings:
        open_sev[f.severity] += 1
        status_count[f.status] += 1
    by_day = defaultdict(int)
    for s in scans:
        if s.created_at and s.created_at >= week_ago:
            by_day[s.created_at.date().isoformat()] += 1
    recent = db.query(models.Scan).filter(
        models.Scan.org_id == user.org_id).order_by(
            models.Scan.id.desc()).limit(8).all()
    return {
        "counts": {"targets": targets, "scans": len(scans),
                   "findings": len(findings),
                   "open_findings": status_count.get("open", 0)
                   + status_count.get("triaged", 0)},
        "open_by_severity": dict(open_sev),
        "findings_by_status": dict(status_count),
        "scans_last_7d": dict(by_day),
        "activity": [{"id": s.id, "engine": s.engine_id, "status": s.status,
                      "target": s.target.address if s.target else "",
                      "created_at": str(s.created_at)} for s in recent],
    }


@router.get("/audit")
def audit(limit: int = 100, db: Session = Depends(get_db),
          user=Depends(current_user)):
    rows = db.query(models.AuditLog).order_by(
        models.AuditLog.id.desc()).limit(min(limit, 500)).all()
    return [{"id": r.id, "ts": str(r.ts), "actor": r.actor,
             "action": r.action, "target_type": r.target_type,
             "target_id": r.target_id, "detail": r.detail or {}}
            for r in rows]