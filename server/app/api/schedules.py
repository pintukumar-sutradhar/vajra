"""Schedules: recurring scan plans.

A schedule holds a fix for a target/engine/profile and an interval. The
worker's poll loop fires schedules whose next_run is due by enqueuing a scan
just like a manual one (same engine contract, same queue), so a plan needs no
special engine support — it is simply a recurring create-scan.
"""

import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..audit import log as audit_log
from ..db import get_db
from .deps import current_user
from .scans import _engine

router = APIRouter(prefix="/api/v1/schedules", tags=["schedules"])

PROFILES = ("quick", "recon", "full", "deep", "webonly", "network", "crawl")


def _out(s):
    nxt = s.next_run
    return {"id": s.id, "org_id": s.org_id, "target_id": s.target_id,
            "target": (s.target.address if s.target else s.target_id),
            "engine_id": s.engine_id, "profile": s.profile,
            "params": s.params or {}, "label": s.label,
            "interval_hours": s.interval_hours,
            "next_run": str(nxt) if nxt else None,
            "enabled": s.enabled,
            "last_run_at": str(s.last_run_at) if s.last_run_at else None,
            "last_scan_id": s.last_scan_id,
            "created_by": s.created_by, "created_at": str(s.created_at)}


class ScheduleIn(BaseModel):
    target_id: int
    engine_id: str
    profile: str = "full"
    params: dict = {}
    label: str = ""
    interval_hours: float = 24.0
    enabled: bool = True


@router.get("")
def list_schedules(db: Session = Depends(get_db),
                   user=Depends(current_user)):
    rows = db.query(models.Schedule).filter(
        models.Schedule.org_id == user.org_id).order_by(
            models.Schedule.id).all()
    return [_out(s) for s in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_schedule(body: ScheduleIn, db: Session = Depends(get_db),
                    user=Depends(current_user)):
    tgt = db.get(models.Target, body.target_id)
    if not tgt or tgt.org_id != user.org_id:
        raise HTTPException(404, "target not found")
    engine = _engine(db, body.engine_id)
    if tgt.archived:
        raise HTTPException(422, "target is archived")
    if body.engine_id not in ("infrastructure",) and \
            tgt.kind not in (engine.target_kinds or []):
        raise HTTPException(422, "target kind %s not supported by engine %s"
                            % (tgt.kind, body.engine_id))
    profile = (body.profile or (engine.cfg or {}).get("default_profile",
                                                      "full"))
    if profile not in (engine.profiles or []) + ["recon"]:
        raise HTTPException(422, "unknown profile for this engine: %s"
                            % profile)
    if body.interval_hours < 0.25:
        raise HTTPException(422, "minimum interval is 15 minutes")
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    s = models.Schedule(org_id=user.org_id, target_id=tgt.id,
                        engine_id=body.engine_id, profile=profile,
                        params=body.params or {}, label=body.label[:200],
                        interval_hours=body.interval_hours,
                        enabled=body.enabled,
                        next_run=now + datetime.timedelta(
                            hours=float(body.interval_hours)),
                        created_by=user.id)
    db.add(s)
    db.commit()
    audit_log(db, user.username, "schedule.create", "schedule", s.id,
              {"target": tgt.address, "engine": body.engine_id,
               "interval_hours": body.interval_hours})
    return _out(s)


def _get(db, user, schedule_id):
    s = db.get(models.Schedule, schedule_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "not found")
    return s


@router.get("/{schedule_id}")
def get_schedule(schedule_id: int, db: Session = Depends(get_db),
                 user=Depends(current_user)):
    return _out(_get(db, user, schedule_id))


@router.patch("/{schedule_id}")
def update_schedule(schedule_id: int, body: ScheduleIn | None = None,
                    label: str = "", interval_hours: float = 0.0,
                    enabled: bool | None = None, profile: str = "",
                    params: dict | None = None,
                    db: Session = Depends(get_db),
                    user=Depends(current_user)):
    s = _get(db, user, schedule_id)
    if body is not None:
        if body.label is not None:
            s.label = body.label[:200]
        if body.interval_hours is not None:
            if body.interval_hours < 0.25:
                raise HTTPException(422, "minimum interval is 15 minutes")
            s.interval_hours = body.interval_hours
        if body.enabled is not None:
            s.enabled = body.enabled
        if body.profile:
            s.profile = body.profile
        if body.params is not None:
            s.params = body.params
    else:
        if label:
            s.label = label[:200]
        if interval_hours:
            if interval_hours < 0.25:
                raise HTTPException(422, "minimum interval is 15 minutes")
            s.interval_hours = interval_hours
        if enabled is not None:
            s.enabled = enabled
        if profile:
            s.profile = profile
        if params is not None:
            s.params = params
    db.commit()
    audit_log(db, user.username, "schedule.update", "schedule", s.id,
              {"enabled": s.enabled})
    return _out(s)


@router.delete("/{schedule_id}")
def delete_schedule(schedule_id: int, db: Session = Depends(get_db),
                    user=Depends(current_user)):
    s = _get(db, user, schedule_id)
    db.delete(s)
    db.commit()
    audit_log(db, user.username, "schedule.delete", "schedule", s.id)
    return {"ok": True}


@router.post("/{schedule_id}/run")
def run_now(schedule_id: int, db: Session = Depends(get_db),
            user=Depends(current_user)):
    """Manually fire the schedule now (advances next_run like a normal run)."""
    s = _get(db, user, schedule_id)
    tgt = db.get(models.Target, s.target_id)
    if tgt is None or tgt.archived:
        raise HTTPException(409, "target is unavailable")
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    scan = models.Scan(org_id=s.org_id, target_id=s.target_id,
                       engine_id=s.engine_id, profile=s.profile,
                       params=dict(s.params or {}), status="pending",
                       started_by=user.id)
    db.add(scan)
    db.flush()
    db.add(models.JobItem(scan_id=scan.id, status="queued"))
    s.last_run_at = now
    s.last_scan_id = scan.id
    s.next_run = now + datetime.timedelta(
        hours=max(0.25, float(s.interval_hours or 24.0)))
    db.commit()
    audit_log(db, user.username, "schedule.run-now", "schedule", s.id,
              {"scan": scan.id})
    return {"ok": True, "scan_id": scan.id}