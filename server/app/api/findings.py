"""Findings: organization-wide list/filter/export + triage lifecycle."""

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


def _finding_out(f):
    return {"id": f.id, "scan_id": f.scan_id, "target_id": f.target_id,
            "engine_id": f.engine_id, "ref": f.ref or "",
            "title": f.title, "severity": f.severity,
            "confidence": f.confidence, "category": f.category,
            "asset": f.asset, "cwe": f.cwe, "cvss": f.cvss,
            "source_module": f.source_module, "detail": f.detail,
            "evidence": f.evidence or {}, "remediation": f.remediation,
            "status": f.status, "state_note": f.state_note,
            "state_changed_at": str(f.state_changed_at)
            if f.state_changed_at else None,
            "first_seen": str(f.first_seen), "last_seen": str(f.last_seen),
            "resolved_by_scan_id": f.resolved_by_scan_id}


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
    if args.get("q"):
        like = "%" + args["q"] + "%"
        q = q.filter(models.Finding.title.like(like) |
                     models.Finding.asset.like(like))
    return q


@router.get("")
def list_findings(severity: str = "", status: str = "",
                  scan_id: int = 0, engine_id: str = "",
                  target_id: int = 0, q: str = "",
                  limit: int = 200, db: Session = Depends(get_db),
                  user=Depends(current_user)):
    base = db.query(models.Finding).filter(
        models.Finding.org_id == user.org_id)
    base = _apply_filters(base, {"severity": severity, "status": status,
                                 "scan_id": scan_id,
                                 "engine_id": engine_id,
                                 "target_id": target_id, "q": q})
    rows = base.order_by(models.Finding.last_seen.desc()).limit(
        min(limit, 500)).all()
    return [_finding_out(f) for f in rows]


class TriageIn(BaseModel):
    status: str = ""
    note: str = ""


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
    db.commit()
    audit_log(db, user.username, "finding.triage", "finding", f.id,
              {"status": f.status})
    return _finding_out(f)


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


@router.get("/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db),
                user=Depends(current_user)):
    f = db.get(models.Finding, finding_id)
    if not f or f.org_id != user.org_id:
        raise HTTPException(404, "not found")
    return _finding_out(f)