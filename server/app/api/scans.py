"""Scans: create/list/get/cancel + live event stream (SSE) + findings."""

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..audit import log as audit_log
from ..db import get_db
from ..security import encrypt_creds
from .deps import current_user
from .engines import available_engines

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

SENSITIVE = {"ad_pass", "web_pass", "nthash", "web_otp", "web_totp_secret"}
TERMINAL = {"completed", "failed", "canceled"}


class ScanIn(BaseModel):
    target_id: int
    engine_id: str
    profile: str = ""
    params: dict = {}


def _engine(db, engine_id):
    e = db.query(models.EngineDef).filter(
        models.EngineDef.engine_id == engine_id).first()
    if not e:
        raise HTTPException(404, "unknown engine")
    return e


def _mask(params):
    masked = dict(params or {})
    for k in SENSITIVE:
        if masked.get(k):
            masked[k] = "***"
    return masked


def _out(s):
    return {"id": s.id, "target_id": s.target_id,
            "target": (s.target.address if s.target else s.target_id),
            "engine_id": s.engine_id, "profile": s.profile,
            "params": s.params or {}, "status": s.status,
            "progress": s.progress, "exit_code": s.exit_code,
            "error": s.error, "stats": s.stats or {},
            "started_by": s.started_by,
            "created_at": str(s.created_at),
            "started_at": str(s.started_at) if s.started_at else None,
            "finished_at": str(s.finished_at) if s.finished_at else None}


@router.get("")
def list_scans(engine_id: str = "", target_id: int = 0,
               status_: str = "", limit: int = 50,
               db: Session = Depends(get_db),
               user=Depends(current_user)):
    q = db.query(models.Scan).filter(models.Scan.org_id == user.org_id)
    if engine_id:
        q = q.filter(models.Scan.engine_id == engine_id)
    if target_id:
        q = q.filter(models.Scan.target_id == target_id)
    if status_:
        q = q.filter(models.Scan.status == status_)
    rows = q.order_by(models.Scan.id.desc()).limit(min(limit, 500)).all()
    return [_out(s) for s in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_scan(body: ScanIn, db: Session = Depends(get_db),
                user=Depends(current_user)):
    tgt = db.get(models.Target, body.target_id)
    if not tgt or tgt.org_id != user.org_id:
        raise HTTPException(404, "target not found")
    engine = _engine(db, body.engine_id)
    if body.engine_id not in ("infrastructure",) and \
            tgt.kind not in (engine.target_kinds or []):
        raise HTTPException(422, "target kind %s not supported by engine %s"
                            % (tgt.kind, body.engine_id))
    if not tgt.authorization_proof.strip():
        raise HTTPException(422, "target has no authorization proof")
    profile = body.profile or (engine.cfg or {}).get("default_profile", "full")
    if profile not in (engine.profiles or []) + ["recon"]:
        raise HTTPException(422, "unknown profile for this engine: %s"
                            % profile)
    sensitive = {k: v for k, v in (body.params or {}).items()
                 if k in SENSITIVE and v}
    public = _mask(body.params)
    s = models.Scan(org_id=user.org_id, target_id=tgt.id,
                    engine_id=body.engine_id, profile=profile,
                    params=public, started_by=user.id,
                    status="pending")
    remaining = {k: v for k, v in (body.params or {}).items()
                 if k not in SENSITIVE}
    db.add(s)
    db.flush()
    if sensitive:
        stored = {k: sensitive[k] for k in SENSITIVE if k in sensitive}
        stored.update(remaining)
        s.creds_enc = encrypt_creds(stored)
    db.add(models.JobItem(scan_id=s.id, status="queued"))
    db.commit()
    audit_log(db, user.username, "scan.create", "scan", s.id,
              {"engine": body.engine_id, "profile": profile,
               "target": tgt.address})
    return _out(s)


@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db),
             user=Depends(current_user)):
    s = db.get(models.Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "not found")
    return _out(s)


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: int, db: Session = Depends(get_db),
                user=Depends(current_user)):
    s = db.get(models.Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "not found")
    if s.status in TERMINAL:
        return _out(s)
    s.cancel_requested = True
    job = db.query(models.JobItem).filter(
        models.JobItem.scan_id == scan_id).first()
    if job and job.status == "queued":
        job.status = "canceled"
        s.status = "canceled"
        s.finished_at = models._utcnow()
    db.commit()
    audit_log(db, user.username, "scan.cancel", "scan", s.id)
    return _out(s)


@router.get("/{scan_id}/findings")
def scan_findings(scan_id: int, db: Session = Depends(get_db),
                  user=Depends(current_user)):
    s = db.get(models.Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "not found")
    rows = db.query(models.Finding).filter(
        models.Finding.scan_id == scan_id).order_by(
            models.Finding.id).all()
    from .findings import _finding_out
    return [_finding_out(f) for f in rows]


@router.get("/{scan_id}/events")
async def scan_events(scan_id: int, request: Request, last: int = 0,
                      db: Session = Depends(get_db),
                      user=Depends(current_user)):
    s = db.get(models.Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "not found")

    async def stream():
        raw = request.headers.get("last-event-id")
        cursor = int(raw) if raw and raw.isdigit() else last
        while True:
            db.rollback()
            rows = db.query(models.ScanEvent).filter(
                models.ScanEvent.scan_id == scan_id,
                models.ScanEvent.id > cursor).order_by(
                    models.ScanEvent.id).all()
            for r in rows:
                cursor = r.id
                yield "id: %d\ndata: %s\n\n" % (
                    r.id, json.dumps({"id": r.id, "level": r.level,
                                      "message": r.message,
                                      "ts": str(r.ts)}))
            fresh = db.get(models.Scan, scan_id)
            if fresh and fresh.status in TERMINAL:
                yield "event: done\ndata: {\"status\": \"%s\"}\n\n" % (
                    fresh.status)
                return
            await asyncio.sleep(1.0)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})