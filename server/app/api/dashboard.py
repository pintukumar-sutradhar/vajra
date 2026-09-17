"""Dashboard + audit endpoints."""

import datetime
import math
from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from .deps import current_user

router = APIRouter(prefix="/api/v1", tags=["dashboard"])

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 2.0,
              "info": 0.5}
OPEN_STATUS = ("open", "triaged")


def _risk_index(sev_counts):
    """0 (clean) .. 100 (deeply exposed), monotonic in severity-weighted count."""
    raw = sum(SEV_WEIGHT.get(s, 0) * c for s, c in sev_counts.items())
    if raw <= 0:
        return 0
    return int(round(100 * (1 - math.exp(-raw / 22.0))))


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db),
              user=Depends(current_user)):
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    org = user.org_id

    findings = db.query(models.Finding).filter(
        models.Finding.org_id == org).all()
    scans = db.query(models.Scan).filter(
        models.Scan.org_id == org).all()
    targets = db.query(models.Target).filter(
        models.Target.org_id == org,
        models.Target.archived == False).all()  # noqa: E712
    suppressed = db.query(models.SuppressedCheck).filter(
        models.SuppressedCheck.org_id == org).count()

    day_span = [now.date() - datetime.timedelta(days=i)
                for i in range(13, -1, -1)]
    day_set = {d.isoformat() for d in day_span}

    open_sev = defaultdict(int)
    all_sev = defaultdict(int)
    status_count = defaultdict(int)
    module_count = defaultdict(int)
    target_sev = defaultdict(lambda: defaultdict(int))
    finding_day = defaultdict(int)
    scan_day = defaultdict(int)

    for f in findings:
        all_sev[f.severity] += 1
        if f.status in OPEN_STATUS:
            open_sev[f.severity] += 1
        status_count[f.status] += 1
        m = f.source_module or f.module or "unknown"
        module_count[m] += 1
        target_sev[f.target_id][f.severity] += 1
        seen = f.first_seen or f.last_seen
        if seen and seen.date().isoformat() in day_set:
            finding_day[seen.date().isoformat()] += 1

    scan_status = defaultdict(int)
    for s in scans:
        scan_status[s.status] += 1
        if s.created_at and s.created_at.date().isoformat() in day_set:
            scan_day[s.created_at.date().isoformat()] += 1

    active = [s for s in scans
              if s.status in ("pending", "queued", "running")]

    top_targets = []
    tgt_by_id = {t.id: t for t in targets}
    for t in targets:
        sev = target_sev.get(t.id, {})
        cr, hi, md = (sev.get("critical", 0), sev.get("high", 0),
                      sev.get("medium", 0))
        if cr + hi + md:
            top_targets.append({
                "id": t.id,
                "address": t.name or t.address,
                "critical": cr, "high": hi, "medium": md,
                "risk": _risk_index({"critical": cr, "high": hi,
                                     "medium": md})})
    top_targets.sort(key=lambda x: x["risk"], reverse=True)
    top_targets = top_targets[:6]

    top_modules = sorted(module_count.items(),
                         key=lambda x: x[1], reverse=True)[:8]
    top_modules = [{"module": m, "count": c} for m, c in top_modules]

    recent = db.query(models.Scan).filter(
        models.Scan.org_id == org).order_by(
            models.Scan.id.desc()).limit(8).all()
    activity = []
    for s in recent:
        t = tgt_by_id.get(s.target_id)
        activity.append({
            "id": s.id, "engine": s.engine_id, "status": s.status,
            "progress": s.progress or 0, "profile": s.profile,
            "target": (t.name or t.address) if t else "",
            "created_at": str(s.created_at),
            "findings": (s.stats or {}).get("findings", 0)})

    risk = _risk_index(open_sev)

    return {
        "counts": {
            "targets": len(targets),
            "scans": len(scans),
            "findings": len(findings),
            "open_findings": sum(open_sev.values()),
            "critical_high": open_sev.get("critical", 0)
            + open_sev.get("high", 0),
            "active_scans": len(active),
            "suppressed": suppressed},
        "risk_score": risk,
        "security_score": max(0, 100 - risk),
        "open_by_severity": dict(open_sev),
        "all_by_severity": dict(all_sev),
        "findings_by_status": dict(status_count),
        "scans_by_status": dict(scan_status),
        "scans_last_14d": {d.isoformat(): scan_day.get(d.isoformat(), 0)
                           for d in day_span},
        "findings_14d": {d.isoformat(): finding_day.get(d.isoformat(), 0)
                         for d in day_span},
        "top_targets": top_targets,
        "top_modules": top_modules,
        "activity": activity,
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