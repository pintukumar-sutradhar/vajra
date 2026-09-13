"""Job queue: claim queued scan jobs and run them via driver.run_scan."""

import datetime
import socket
import time

from ..app import models
from ..app.db import SessionLocal

CLAIM_STALE_S = 60


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _commit_retry_commit(db):
    from .driver import _commit_retry
    _commit_retry(db)


def reclaim_orphans(worker_name):
    """Fail scans whose worker died mid-run (stale/absent heartbeat).

    A stuck 'claimed' job previously buried the scan in 'running' forever,
    silently ignoring cancel requests. The driver now writes a heartbeat every
    ~2s, so a claim without a fresh heartbeat for >CLAIM_STALE_S belongs to a
    dead worker and must be reclaimed. Scans that already reached a terminal
    state just get their job finalized.
    """
    from .driver import _log, kill_engine
    if worker_name is None:
        worker_name = "%s/%d" % (socket.gethostname(), __import__("os").getpid())
    db = SessionLocal()
    try:
        now = _utcnow()
        cutoff = now - datetime.timedelta(seconds=CLAIM_STALE_S)
        jobs = db.query(models.JobItem).filter(
            models.JobItem.status == "claimed").all()
        changed = False
        for job in jobs:
            if job.worker and job.worker == worker_name:
                continue
            beat = job.heartbeat_at
            if beat is not None and beat >= cutoff:
                continue
            if beat is None:
                if not job.claimed_at or job.claimed_at >= cutoff:
                    continue
            scan = db.get(models.Scan, job.scan_id)
            if scan is not None and scan.status not in (
                    "completed", "canceled", "failed"):
                scan.status = "failed"
                scan.error = "worker lost during run; scan reclaimed"
                scan.finished_at = _utcnow()
                _log(job.scan_id, "worker lost — run stopped", "error")
            kill_engine(job.scan_id)
            job.status = "done" if scan is not None and \
                scan.status == "completed" else "failed"
            if scan is not None and job.last_error not in (None, ""):
                pass
            elif scan is not None:
                job.last_error = scan.error or "worker lost"
            changed = True
        if changed:
            _commit_retry_commit(db)
    finally:
        db.close()


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
    _commit_retry_commit(db)
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
            _commit_retry_commit(db)
    finally:
        db.close()
    return scan_id


def worker_main():
    import os as _os
    import signal as _signal
    from ..app.config import settings
    from .driver import ACTIVE
    name = "%s/%d" % (socket.gethostname(), _os.getpid())

    def _shutdown(signum, _frame):
        print("[worker] shutting down (%s)..." % signum)
        for proc in list(ACTIVE.values()):
            try:
                proc.terminate()
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        _os._exit(0)

    _signal.signal(_signal.SIGTERM, _shutdown)
    print("[worker] %s starting (poll %.1fs)" % (name,
                                                 settings.worker_interval))
    print("[worker] reclaiming orphans...")
    try:
        reclaim_orphans(name)
    except Exception as exc:
        print("[worker] reclaim error: %s" % exc)
    while True:
        try:
            reclaim_orphans(name)
            started = tick(name)
            if started:
                print("[worker] scan %s finished" % started)
        except KeyboardInterrupt:
            print("[worker] stopped")
            return
        except Exception as exc:
            print("[worker] tick error: %s" % exc)
        time.sleep(settings.worker_interval)