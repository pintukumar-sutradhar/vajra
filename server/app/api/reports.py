"""Reports: serve the engine-generated HTML report, raw artifacts and PDFs."""

import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..reporting import build_pdf
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


@router.get("/{scan_id}/static/{path:path}")
def static_file(scan_id: int, path: str, db: Session = Depends(get_db),
                user=Depends(current_user)):
    """Serve any file under the scan bundle (report.html, evidence/*.png, ...)
    so relative PoC-screenshot links in the report resolve inside the UI."""
    s = _check(db, user, scan_id)
    root = (s.stats or {}).get("bundle_dir", "")
    if not root:
        raise HTTPException(404, "no artifacts")
    target = _safe_join(root, path or "")
    if not os.path.isfile(target):
        raise HTTPException(404, "missing static file")
    if path.endswith(".html"):
        return FileResponse(target, media_type="text/html")
    return FileResponse(target)


@router.get("/{scan_id}/pdf")
def report_pdf(scan_id: int, db: Session = Depends(get_db),
               user=Depends(current_user)):
    s = _check(db, user, scan_id)
    if s.status not in ("completed", "failed"):
        raise HTTPException(409, "scan not finished yet")
    target = db.get(models.Target, s.target_id)
    findings = (db.query(models.Finding)
                  .filter(models.Finding.scan_id == scan_id)
                  .order_by(models.Finding.id).all())
    edef = (db.query(models.EngineDef)
              .filter(models.EngineDef.engine_id == s.engine_id).first())
    engine_label = edef.label if edef else s.engine_id
    who = db.get(models.User, user.id)
    try:
        data = build_pdf(s, target, findings, engine_label, who)
    except Exception as exc:
        raise HTTPException(500, "report generation failed: %s" % exc)
    stamp = s.created_at.strftime("%Y%m%d") if s.created_at else "scan"
    fname = "vajra-pentest-report-%s-%s.pdf" % (scan_id, stamp)
    return Response(content=data, media_type="application/pdf",
                    headers={"Content-Disposition":
                             'attachment; filename="%s"' % fname})


@router.post("/{scan_id}/regenerate")
def regenerate(scan_id: int, db: Session = Depends(get_db),
               user=Depends(current_user)):
    _check(db, user, scan_id)
    raise HTTPException(501, "report regeneration lands in Phase 3")