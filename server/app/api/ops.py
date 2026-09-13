"""Shared hard-delete helpers for targets and scans.

Deletion intentionally removes the record AND its run artifacts on disk,
because the workspace is the single source of truth for assets under test.
"""

import shutil

from .. import models
from ..config import settings

TERMINAL = {"completed", "failed", "canceled"}


def _rm_runs(scan_ids):
    for sid in scan_ids:
        shutil.rmtree(settings.runs_dir / str(sid), ignore_errors=True)


def _purge_scans(db, scans):
    ids = [s.id for s in scans]
    db.query(models.Finding).filter(
        models.Finding.resolved_by_scan_id.in_(ids)).update(
        {"resolved_by_scan_id": None}, synchronize_session=False)
    db.query(models.Finding).filter(
        models.Finding.scan_id.in_(ids)).delete(synchronize_session=False)
    db.query(models.ScanEvent).filter(
        models.ScanEvent.scan_id.in_(ids)).delete(synchronize_session=False)
    db.query(models.JobItem).filter(
        models.JobItem.scan_id.in_(ids)).delete(synchronize_session=False)
    db.query(models.Scan).filter(models.Scan.id.in_(ids)).delete(
        synchronize_session=False)
    _rm_runs(ids)


def delete_scan(db, scan):
    """Delete one scan (guarded: must be terminal first).

    Returns (ok, blocker). Caller raises HTTP 409 when ok is False.
    """
    if scan.status not in TERMINAL:
        return False, scan
    _purge_scans(db, [scan])
    return True, None


def delete_target(db, target):
    """Delete a target and everything derived from it (scans, findings,
    events, jobs, run dirs). Refuses while any of its scans is live."""
    scans = db.query(models.Scan).filter(
        models.Scan.target_id == target.id).all()
    live = [s for s in scans if s.status not in TERMINAL]
    if live:
        return False, live[0]
    if scans:
        _purge_scans(db, scans)
    db.query(models.Finding).filter(
        models.Finding.target_id == target.id).delete(
        synchronize_session=False)
    db.delete(target)
    return True, None