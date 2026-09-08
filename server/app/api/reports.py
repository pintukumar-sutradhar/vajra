"""Reports: serve the engine-generated HTML report and raw scan artifacts."""

import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from .deps import current_user

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


def _check(db, user, scan_id):
    s = db.get(models.Scan, scan_id)
    if not s or s.org_id != user.org_id:
        raise HTTPException(404, "not found")
    return s


def _safe_join(root, rel):
    root = os.path.abspath(root)
    target = os.path.abspath(os.path.join(root, rel.lstrip("/\\")))
    if not (target == root or target.startswith(root + os.sep)):
        raise HTTPException(403, "forbidden path")
    return target


@router.get("/{scan_id}/html")
def report_html(scan_id: int, db: Session = Depends(get_db),
                user=Depends(current_user)):
    s = _check(db, user, scan_id)
    if s.status not in ("completed", "failed"):
        raise HTTPException(409, "scan not finished yet")
    path = (s.stats or {}).get("report_html", "")
    if not path or not os.path.isfile(path):
        raise HTTPException(404, "no report generated")
    return FileResponse(path, media_type="text/html")


@router.get("/{scan_id}/asset/{path:path}")
def asset(scan_id: int, path: str, db: Session = Depends(get_db),
          user=Depends(current_user)):
    s = _check(db, user, scan_id)
    root = (s.stats or {}).get("bundle_dir", "")
    if not root:
        raise HTTPException(404, "no artifacts")
    target = _safe_join(root, path)
    if not os.path.isfile(target):
        raise HTTPException(404, "missing asset")
    return FileResponse(target)


@router.post("/{scan_id}/regenerate")
def regenerate(scan_id: int, db: Session = Depends(get_db),
               user=Depends(current_user)):
    _check(db, user, scan_id)
    raise HTTPException(501, "report regeneration lands in Phase 3")