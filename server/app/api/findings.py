"""Findings: organization-wide list/filter/export + triage lifecycle."""

import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..audit import log as audit_log
from ..db import get_db
from .deps import current_user

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

STATUSES = {"open", "triaged", "false-positive", "accepted-risk", "fixed"}
LIFECYCLE = {"open": {"triaged", "false-positive", "accepted-risk", "fixed"},
             "triaged": {"open", "false-positive", "accepted-risk", "fixed"},
             "false-positive": {"open"},
             "accepted-risk": {"open", "fixed"},
             "fixed": {"open"}}


def _finding_out(f, users=None):
    assignee = None
    if users and f.assignee_id and f.assignee_id in users:
        assignee = users[f.assignee_id]
    return {"id": f.id, "scan_id": f.scan_id, "target_id": f.target_id,
            "engine_id": f.engine_id, "ref": f.ref or "",
            "title": f.title, "severity": f.severity,
            "confidence": f.confidence, "category": f.category,
            "asset": f.asset, "cwe": f.cwe, "cvss": f.cvss,
            "source_module": f.source_module, "detail": f.detail,
            "evidence": f.evidence or {}, "remediation": f.remediation,
            "proof": getattr(f, "proof", "") or "",
            "cap": getattr(f, "cap", "") or "",
            "status": f.status, "state_note": f.state_note,
            "state_changed_at": str(f.state_changed_at)
            if f.state_changed_at else None,
            "first_seen": str(f.first_seen), "last_seen": str(f.last_seen),
            "resolved_by_scan_id": f.resolved_by_scan_id,
            "risk": float(getattr(f, "risk", 0.0) or 0.0)
            or models.compute_risk(f.severity, f.confidence, f.cap),
            "assignee_id": f.assignee_id,
            "assignee": assignee,
            "due_date": str(f.due_date) if f.due_date else None,
            "rechecked_at": str(f.rechecked_at) if f.rechecked_at else None,
            "recheck_outcome": getattr(f, "recheck_outcome", "") or "",
            "rechecked_by_scan_id": getattr(f, "rechecked_by_scan_id", None)}


def _apply_filters(q, args):
    if args.get("severity"):
        q = q.filter(models.Finding.severity == args["severity"])
    if args.get("status"):
        q = q.filter(models.Finding.status == args["status"])
    if args.get("scan_id"):
        q = q.filter(models.Finding.scan_id == args["scan_id"])
    if args.get("engine_id"):
        q = q.filter(models.Finding.engine_id == args["engine_id"])
    if args.get("target_id"):
        q = q.filter(models.Finding.target_id == args["target_id"])
    if args.get("module"):
        q = q.filter(models.Finding.source_module == args["module"])
    if args.get("assignee_id"):
        q = q.filter(models.Finding.assignee_id == args["assignee_id"])
    if args.get("min_risk"):
        q = q.filter(models.Finding.risk >= float(args["min_risk"]))
    if args.get("overdue"):
        if args.get("overdue") in ("1", "true"):
            from datetime import datetime, timezone
            q = q.filter(models.Finding.due_date.is_not(None),
                         models.Finding.due_date < datetime.now(
                             timezone.utc).replace(tzinfo=None),
                         models.Finding.status.in_(("open", "triaged")))
    if args.get("asset"):
        q = q.filter(models.Finding.asset.like("%" + args["asset"] + "%"))
    if args.get("q"):
        like = "%" + args["q"] + "%"
        q = q.filter(models.Finding.title.like(like) |
                     models.Finding.asset.like(like) |
                     models.Finding.detail.like(like))
    return q


_SORTS = {
    "newest": models.Finding.id.desc(),
    "oldest": models.Finding.id.asc(),
    "severity": models.Finding.severity.asc(),
    "risk": models.Finding.risk.desc(),
    "last_seen": models.Finding.last_seen.desc(),
}


def _org_users(db, org_id):
    return {u.id: {"id": u.id, "username": u.username,
                   "display_name": u.display_name or u.username}
            for u in db.query(models.User).filter(
                models.User.org_id == org_id).all()}


@router.get("")
def list_findings(severity: str = "", status: str = "",
                  scan_id: int = 0, engine_id: str = "",
                  target_id: int = 0, q: str = "", module: str = "",
                  assignee_id: int = 0, min_risk: float = 0.0,
                  asset: str = "", overdue: str = "",
                  sort: str = "", limit: int = 200,
                  db: Session = Depends(get_db),
                  user=Depends(current_user)):
    base = db.query(models.Finding).filter(
        models.Finding.org_id == user.org_id)
    base = _apply_filters(base, {"severity": severity, "status": status,
                                 "scan_id": scan_id,
                                 "engine_id": engine_id,
                                 "target_id": target_id, "q": q,
                                 "module": module, "assignee_id": assignee_id,
                                 "min_risk": min_risk, "asset": asset,
                                 "overdue": overdue})
    order = _SORTS.get(sort, models.Finding.last_seen.desc())
    rows = base.order_by(order).limit(min(limit, 500)).all()
    users = _org_users(db, user.org_id)
    return [_finding_out(f, users) for f in rows]


class TriageIn(BaseModel):
    status: str = ""
    note: str = ""
    assignee_id: int | None = None
    due_date: str = ""


@router.patch("/{finding_id}")
def triage(finding_id: int, body: TriageIn,
           db: Session = Depends(get_db),
           user=Depends(current_user)):
    f = db.get(models.Finding, finding_id)
    if not f or f.org_id != user.org_id:
        raise HTTPException(404, "not found")
    new_status = body.status or f.status
    if new_status != f.status:
        if new_status not in LIFECYCLE.get(f.status, set()):
            raise HTTPException(422, "transition %s -> %s not allowed"
                                % (f.status, new_status))
        f.status = new_status
        f.state_note = body.note or f.state_note
        f.state_changed_by = user.id
        f.state_changed_at = models._utcnow()
    elif body.note:
        f.state_note = body.note
    if body.assignee_id is not None:
        if body.assignee_id:
            u = db.get(models.User, body.assignee_id)
            if not u or u.org_id != user.org_id:
                raise HTTPException(422, "unknown assignee")
        f.assignee_id = body.assignee_id or None
    if body.due_date:
        try:
            f.due_date = datetime.datetime.fromisoformat(
                body.due_date.replace("Z", "+00:00")).replace(
                tzinfo=None)
        except Exception:
            raise HTTPException(422, "bad due_date; use ISO 8601")
    db.commit()
    audit_log(db, user.username, "finding.triage", "finding", f.id,
              {"status": f.status})
    return _finding_out(f, _org_users(db, user.org_id))


@router.get("/stats")
def stats(db: Session = Depends(get_db), user=Depends(current_user)):
    rows = db.query(models.Finding).filter(
        models.Finding.org_id == user.org_id).all()
    by_sev = {}
    by_status = {}
    by_engine = {}
    for f in rows:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_status[f.status] = by_status.get(f.status, 0) + 1
        by_engine[f.engine_id] = by_engine.get(f.engine_id, 0) + 1
    open_ = sum(by_status.get(k, 0) for k in ("open", "triaged"))
    return {"total": len(rows), "open": open_,
            "by_severity": by_sev, "by_status": by_status,
            "by_engine": by_engine}


class BulkIn(BaseModel):
    ids: list[int]
    status: str = ""
    note: str = ""
    assignee_id: int | None = None


@router.post("/bulk")
def bulk(ids: list[int] | None = None, body: BulkIn | None = None,
         db: Session = Depends(get_db), user=Depends(current_user),
         payload: dict = None):
    """Bulk triage: one status transition / note / assignment across many
    findings (used by the findings page selection bar)."""
    if body is None:
        if payload is not None:
            body = BulkIn(**{k: payload.get(k) for k in
                             ("ids", "status", "note", "assignee_id")})
        else:
            raise HTTPException(422, "body required")
    changed = 0
    now = models._utcnow()
    for fid in set((body.ids or [])[:500]):
        f = db.get(models.Finding, fid)
        if not f or f.org_id != user.org_id:
            continue
        if body.status and body.status != f.status:
            if body.status not in LIFECYCLE.get(f.status, set()):
                continue
            f.status = body.status
            f.state_changed_by = user.id
            f.state_changed_at = now
        if body.note:
            f.state_note = body.note
        if body.assignee_id is not None:
            f.assignee_id = body.assignee_id or None
        changed += 1
    db.commit()
    if changed:
        audit_log(db, user.username, "finding.bulk", "finding", 0,
                  {"count": changed, "status": body.status,
                   "note": body.note or ""})
    return {"ok": True, "changed": changed}


@router.post("/{finding_id}/recheck")
def recheck(finding_id: int, db: Session = Depends(get_db),
            user=Depends(current_user)):
    """Re-verify a finding: enqueue a targeted probe that re-runs exactly the
    module which produced the finding, on the same target. If it reproduces,
    the finding is refreshed and stamped 'reproduced'; if not, it is moved to
    fixed when the check completes."""
    f = db.get(models.Finding, finding_id)
    if not f or f.org_id != user.org_id:
        raise HTTPException(404, "not found")
    if not f.source_module:
        raise HTTPException(422, "finding has no source module to re-probe")
    tgt = db.get(models.Target, f.target_id)
    scan_src = db.get(models.Scan, f.scan_id)
    original = scan_src.profile if scan_src else "quick"
    s = models.Scan(org_id=user.org_id, target_id=f.target_id,
                    engine_id=f.engine_id, profile=original,
                    params={"recheck": finding_id,
                            "modules": [f.source_module]},
                    started_by=user.id, status="pending",
                    verbose=1)
    db.add(s)
    db.flush()
    db.add(models.JobItem(scan_id=s.id, status="queued"))
    db.commit()
    audit_log(db, user.username, "finding.recheck", "finding", f.id,
              {"scan": s.id, "module": f.source_module})
    return {"ok": True, "scan_id": s.id, "module": f.source_module}


@router.get("/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db),
                user=Depends(current_user)):
    f = db.get(models.Finding, finding_id)
    if not f or f.org_id != user.org_id:
        raise HTTPException(404, "not found")
    return _finding_out(f, _org_users(db, user.org_id))