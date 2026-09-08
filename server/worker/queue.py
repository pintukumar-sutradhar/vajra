"""Job queue: claim queued scan jobs and run them via driver.run_scan."""

import datetime
import socket
import time

from ..app import models
from ..app.db import SessionLocal


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def claim_one(db, worker_name):
    job = db.query(models.JobItem).filter(
        models.JobItem.status == "queued").order_by(
            models.JobItem.id).first()
    if not job:
        return None
    job.status = "claimed"
    job.claimed_at = _utcnow()
    job.attempts = (job.attempts or 0) + 1
    job.worker = worker_name
    scan = db.get(models.Scan, job.scan_id)
    if scan and scan.status == "pending":
        scan.status = "running"
    db.commit()
    return job


def tick(worker_name=None):
    """Process one queued job if any; returns the scan id or None."""
    from .driver import run_scan
    db = SessionLocal()
    try:
        job = claim_one(db, worker_name or socket.gethostname())
        if not job:
            return None
        job_id = job.id
        scan_id = job.scan_id
    finally:
        db.close()
    run_scan(scan_id)
    db = SessionLocal()
    try:
        job = db.get(models.JobItem, job_id)
        scan = db.get(models.Scan, scan_id)
        if job:
            job.status = "done" if scan and scan.status == "completed" \
                else "failed"
            job.last_error = scan.error if scan and scan.error else ""
            db.commit()
    finally:
        db.close()
    return scan_id


def worker_main():
    from ..app.config import settings
    name = "%s/%d" % (socket.gethostname(), __import__("os").getpid())
    print("[worker] %s starting (poll %.1fs)" % (name,
                                                 settings.worker_interval))
    while True:
        try:
            started = tick(name)
            if started:
                print("[worker] scan %s finished" % started)
        except KeyboardInterrupt:
            print("[worker] stopped")
            return
        except Exception as exc:
            print("[worker] tick error: %s" % exc)
        time.sleep(settings.worker_interval)