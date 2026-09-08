"""Scanning engine library: templates exposed to the API/UI."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from .deps import current_user

router = APIRouter(prefix="/api/v1/engines", tags=["engines"])


def available_engines(db):
    return db.query(models.EngineDef).filter(
        models.EngineDef.enabled == True).order_by(  # noqa: E712
            models.EngineDef.id).all()


def _out(e):
    return {"engine_id": e.engine_id, "label": e.label,
            "description": e.description, "icon": e.icon,
            "target_kinds": list(e.target_kinds or []),
            "profiles": list(e.profiles or []),
            "params_schema": e.params_schema or {},
            "default_profile": (e.cfg or {}).get("default_profile", "full")}


@router.get("")
def list_engines(db: Session = Depends(get_db),
                 user=Depends(current_user)):
    return [_out(e) for e in available_engines(db)]


@router.get("/{engine_id}")
def get_engine(engine_id: str, db: Session = Depends(get_db),
               user=Depends(current_user)):
    e = db.query(models.EngineDef).filter(
        models.EngineDef.engine_id == engine_id).first()
    if not e:
        from fastapi import HTTPException
        raise HTTPException(404, "unknown engine")
    return _out(e)