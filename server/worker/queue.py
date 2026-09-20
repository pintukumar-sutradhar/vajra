"""Job queue: claim queued scan jobs and run them via driver.run_scan."""

import builtins
import datetime
import socket
import time

from ..app import models
from ..app.db import SessionLocal

# Worker output lands in a log file under nohup, where python block-buffers
# stdout; flush every line so operation logs stay live instead of draining at
# exit (or never, when the worker is SIGTERM'd).
def print(*args, **kwargs):
    kwargs.setdefault("flush", True)
    builtins.print(*args, **kwargs)

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


def scheduler_tick():
    """Fires any schedules whose next_run is due: enqueues a Scan exactly like
    a manual one, then advances next_run by the interval. Cheap enough to run
    on every worker poll — an empty check is a single indexed query."""
    db = SessionLocal()
    try:
        now = _utcnow()
        due = db.query(models.Schedule).filter(
            models.Schedule.enabled.is_(True),
            models.Schedule.next_run.is_not(None),
            models.Schedule.next_run <= now).all()
        if not due:
            return
        for s in due:
            target = db.get(models.Target, s.target_id)
            if target is None or target.archived:
                s.enabled = False
                continue
            scan = models.Scan(org_id=s.org_id, target_id=s.target_id,
                               engine_id=s.engine_id, profile=s.profile,
                               params=dict(s.params or {}),
                               started_by=s.created_by, status="pending")
            db.add(scan)
            db.flush()
            db.add(models.JobItem(scan_id=scan.id, status="queued"))
            s.last_run_at = now
            s.last_scan_id = scan.id
            s.next_run = now + datetime.timedelta(
                hours=max(0.25, float(s.interval_hours or 24.0)))
        _commit_retry_commit(db)
    finally:
        db.close()


def _finalize(job_id, scan_id):
    """Close out a JobItem once its scan reached a terminal state."""
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


def _claim(worker_name):
    """Claim one queued job for this worker; returns (job_id, scan_id) or
    None when the queue is empty. Transactional and safe to call from several
    threads — each claim is its own session and retried on SQLite locks."""
    db = SessionLocal()
    try:
        job = claim_one(db, worker_name)
        if not job:
            return None
        return job.id, job.scan_id
    finally:
        db.close()


def _run_job(job_id, scan_id, worker_name, active):
    """Run one claimed scan to completion, then finalize its job. Runs inside
    a pool thread, so concurrent scans each own their subprocess and run dir;
    the driver keeps every piece of state keyed by scan_id, which is all the
    isolation the engine needs (its own workspace, outputs, heartbeat)."""
    from .driver import run_scan
    print("[worker] scan %s started (%d active)" % (scan_id, active))
    try:
        run_scan(scan_id)
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        print("[worker] scan %s driver error: %s" % (scan_id, exc))
    _finalize(job_id, scan_id)
    print("[worker] scan %s finished" % scan_id)


def tick(worker_name=None):
    """Synchronously claim and run one queued job; the scan id (or None).
    Single-slot helper for embedders and dev scripts; the real worker runs
    scans concurrently via worker_main."""
    from .driver import run_scan
    claimed = _claim(worker_name or socket.gethostname())
    if not claimed:
        return None
    job_id, scan_id = claimed
    run_scan(scan_id)
    _finalize(job_id, scan_id)
    return scan_id


def worker_main():
    import os as _os
    import signal as _signal
    from concurrent.futures import ThreadPoolExecutor
    from ..app.config import settings
    from .driver import ACTIVE
    name = "%s/%d" % (socket.gethostname(), _os.getpid())
    concurrent = max(1, int(getattr(settings, "max_workers", 1) or 1))

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
    print("[worker] %s starting (poll %.1fs, %d concurrent)" % (
        name, settings.worker_interval, concurrent))
    print("[worker] reclaiming orphans...")
    try:
        reclaim_orphans(name)
    except Exception as exc:
        print("[worker] reclaim error: %s" % exc)
    executor = ThreadPoolExecutor(
        max_workers=concurrent, thread_name_prefix="scan")
    inflight = {}
    try:
        while True:
            try:
                reclaim_orphans(name)
                scheduler_tick()
            except Exception as exc:
                print("[worker] scheduler error: %s" % exc)
            for fut in [f for f in inflight if f.done()]:
                try:
                    fut.result()
                except Exception as exc:
                    print("[worker] pool error: %s" % exc)
                del inflight[fut]
            try:
                # Fill all free slots now; a claim that finds nothing stops
                # the tight loop. Polls keep refilling slots as scans finish.
                while len(inflight) < concurrent:
                    claimed = _claim(name)
                    if claimed is None:
                        break
                    job_id, scan_id = claimed
                    inflight[executor.submit(
                        _run_job, job_id, scan_id, name,
                        len(inflight) + 1)] = scan_id
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                print("[worker] claim error: %s" % exc)
            time.sleep(settings.worker_interval)
    finally:
        for proc in list(ACTIVE.values()):
            try:
                proc.terminate()
            except Exception:
                pass
        executor.shutdown(wait=False)