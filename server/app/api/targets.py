"""Targets (assets under test) CRUD."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..audit import log as audit_log
from ..db import get_db
from .deps import current_user

router = APIRouter(prefix="/api/v1/targets", tags=["targets"])

KINDS = {"url", "ip", "cidr", "hostname", "domain"}


class TargetIn(BaseModel):
    kind: str = Field(..., pattern="^(url|ip|cidr|hostname|domain)$")
    address: str
    name: str = ""
    notes: str = ""
    tags: dict = {}
    authorization_proof: str = ""


class TargetState(BaseModel):
    ok: bool
    target: dict


def _out(t):
    return {"id": t.id, "kind": t.kind, "address": t.address, "name": t.name,
            "notes": t.notes, "tags": t.tags or {},
            "authorization_proof": t.authorization_proof,
            "archived": t.archived, "created_at": str(t.created_at)}


@router.get("")
def list_targets(q: str = "", include_archived: bool = False,
                 db: Session = Depends(get_db),
                 user=Depends(current_user)):
    rows = db.query(models.Target).filter(
        models.Target.org_id == user.org_id)
    if not include_archived:
        rows = rows.filter(models.Target.archived == False)  # noqa: E712
    if q:
        rows = rows.filter(models.Target.address.contains(q))
    return [_out(t) for t in rows.order_by(models.Target.created_at.desc())]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_target(body: TargetIn, db: Session = Depends(get_db),
                  user=Depends(current_user)):
    if not body.authorization_proof.strip():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "authorization_proof is required: an explicit authorized-scope "
            "statement (ticket/reference) must accompany every target")
    t = models.Target(org_id=user.org_id, kind=body.kind,
                      address=body.address.strip(), name=body.name,
                      notes=body.notes, tags=body.tags or {},
                      authorization_proof=body.authorization_proof.strip(),
                      created_by=user.id)
    db.add(t)
    db.commit()
    audit_log(db, user.username, "target.create", "target", t.id,
              {"address": t.address, "kind": t.kind})
    return _out(t)


@router.get("/{target_id}")
def get_target(target_id: int, db: Session = Depends(get_db),
               user=Depends(current_user)):
    t = db.get(models.Target, target_id)
    if not t or t.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return _out(t)


@router.patch("/{target_id}")
def update_target(target_id: int, body: TargetIn,
                  db: Session = Depends(get_db),
                  user=Depends(current_user)):
    t = db.get(models.Target, target_id)
    if not t or t.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    for k, v in body.dict().items():
        if k == "tags" and isinstance(v, dict):
            t.tags = v
        elif v is not None and k not in ("authorization_proof",):
            setattr(t, k, v)
    if body.authorization_proof.strip():
        t.authorization_proof = body.authorization_proof.strip()
    db.commit()
    audit_log(db, user.username, "target.update", "target", t.id)
    return _out(t)


@router.delete("/{target_id}")
def archive_target(target_id: int, db: Session = Depends(get_db),
                   user=Depends(current_user)):
    t = db.get(models.Target, target_id)
    if not t or t.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    t.archived = True
    db.commit()
    audit_log(db, user.username, "target.archive", "target", t.id)
    return {"ok": True}