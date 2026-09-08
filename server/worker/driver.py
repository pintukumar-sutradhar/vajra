"""Headless scan driver: run the VAJRA engine as a subprocess for a Scan
and harvest findings/evidence/reports back into the platform DB.

The core engine is intentionally UNTOUCHED — the platform consumes it via
the existing CLI contract (vajra.py), like a constrained operator.
"""

import datetime
import glob
import os
import re
import selectors
import subprocess
import sys
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
BANNER = re.compile(r"VAJRA v[\d.]+")
_PROGRESS = re.compile(r"(\d{1,3})%")
_BLANK = re.compile(r"^[\s\-_=]*$", re.M)

_INTERVAL = 1.0


def _classify(line):
    low = line.lower()
    if "[critical" in low or "fatal" in low:
        return "error"
    if "[finding]" in low:
        return "finding"
    if "[!]" in low or "error" in low or "failed probe" in low or \
            "exception" in low:
        return "warning"
    return "info"


def expand_exclusions(tokens):
    """Expand group tokens like 'ad.' into full module names."""
    out = [t for t in tokens if not t.endswith(".")]
    groups = [t for t in tokens if t.endswith(".")]
    if groups:
        try:
            from modules import get_modules
            names = [m["name"] for m in get_modules()]
        except Exception:
            names = []
        for g in groups:
            out.extend(n for n in names if n.startswith(g))
    return sorted(set(out))


def build_argv(target, engine_cfg, profile, params, creds, run_dir, repo):
    argv = [sys.executable, str(repo / "vajra.py"),
            "-t", target.address, "--profile", profile, "--yes",
            "--output", str(run_dir / "Outputs"),
            "--no-color"]
    ex = list(engine_cfg.get("exclude_modules") or [])
    if engine_cfg.get("no_brute"):
        ex.append("network.brute")
    if ex:
        argv += ["--exclude-modules", ",".join(expand_exclusions(ex))]
    if engine_cfg.get("ad"):
        argv += ["--ad"]
    if params.get("aggressive"):
        argv += ["--aggressive"]
    if params.get("udp"):
        argv += ["--udp"]
    if params.get("syn"):
        argv += ["--syn"]
    c = {**(params or {}), **(creds or {})}
    for flag, key in (("--web-user", "web_user"), ("--web-pass", "web_pass"),
                      ("--web-login", "web_login"),
                      ("--web-otp", "web_otp"),
                      ("--web-totp-secret", "web_totp_secret"),
                      ("--ad-user", "ad_user"), ("--ad-pass", "ad_pass"),
                      ("--nthash", "nthash")):
        if c.get(key):
            argv += [flag, str(c[key])]
    if not params.get("external_intel"):
        argv += ["--no-external-intel"]
    return argv


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _push_events(scan_id, lines):
    from ..app import models
    from ..app.db import SessionLocal
    if not lines:
        return
    session = SessionLocal()
    try:
        for lvl, msg in lines:
            session.add(models.ScanEvent(scan_id=scan_id, level=lvl,
                                         message=msg[:2000]))
        session.commit()
    finally:
        session.close()


def _log(scan_id, msg, lvl="info"):
    _push_events(scan_id, [(lvl, msg)])


def _read_bundle(bundle_dir):
    dbs = glob.glob(str(bundle_dir / "*.sqlite")) + \
        glob.glob(str(bundle_dir / "*.db"))
    report = None
    for cand in sorted(glob.glob(str(bundle_dir / "report*.html"))):
        report = cand
        break
    rows = []
    for db_path in dbs:
        try:
            from core.database import Database
            rows.extend(Database(db_path).findings())
        except Exception:
            pass
    return rows, report


def _slugify(s):
    return re.sub(r"[^A-Za-z0-9]+", "_", (s or "")).strip("_")[:48] or "finding"


def _screenshots_for(bundle, title):
    """Match the engine's per-finding evidence PNGs (fNNN_<slug>.png) to a
    finding by title slug. Returns relative bundle paths for the PDF/UI."""
    if not bundle or not bundle.is_dir():
        return []
    ev_dir = bundle / "evidence"
    if not ev_dir.is_dir():
        return []
    slug = _slugify(title)
    return sorted("evidence/" + p.name for p in ev_dir.glob("f*.png")
                  if slug in p.name)


def _harvest(scan, run_dir):
    from ..app import models
    from ..app.db import SessionLocal
    session = SessionLocal()
    try:
        bundles = [b for b in sorted(run_dir.glob("Outputs/*/*/"))]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ref = 0
        total = 0
        by_sev = {}
        rows_by_bundle = []
        for bundle in bundles:
            rows_by_bundle.append((bundle,) + _read_bundle(bundle))
        for bundle, findings, report in rows_by_bundle:
            for f in sorted(findings, key=lambda r: order.get(
                    (r.get("severity") or "info").lower(), 5)):
                ref += 1
                sev = (f.get("severity") or "info").lower()
                module = f.get("module") or ""
                session.add(models.Finding(
                    org_id=scan.org_id, scan_id=scan.id,
                    target_id=scan.target_id, engine_id=scan.engine_id,
                    ref="VULN-%02d" % ref,
                    title=(f.get("title") or "")[:500],
                    severity=sev, category=f.get("category") or "",
                    asset=f.get("target") or scan.target.address,
                    source_module=module,
                    detail=f.get("detail") or "",
                    evidence={"text": f.get("evidence") or "",
                              "screenshots": _screenshots_for(
                                  bundle, f.get("title") or "")},
                    remediation=f.get("remediation") or "",
                    confidence=f.get("confidence") or "tentative",
                    dedup_key="%s:%s" % (module, f.get("title") or "")))
                total += 1
                by_sev[sev] = by_sev.get(sev, 0) + 1
        scan.stats = {
            "findings": total, "by_severity": by_sev,
            "bundle_dir": str(rows_by_bundle[0][0])
            if rows_by_bundle else "",
            "report_html": rows_by_bundle[0][2] if rows_by_bundle else ""}
        session.commit()
        return total, bool(rows_by_bundle and rows_by_bundle[0][2])
    finally:
        session.close()


def run_scan(scan_id):
    from ..app import models
    from ..app.config import REPO, settings
    from ..app.db import SessionLocal
    from ..app.security import decrypt_creds
    from .engine_defs import get_engine

    run_dir = settings.runs_dir / str(scan_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
        if scan is None:
            return
        eng = get_engine(scan.engine_id) or {}
        creds = {}
        if scan.creds_enc:
            try:
                creds = decrypt_creds(scan.creds_enc)
            except Exception:
                creds = {}
        target = db.get(models.Target, scan.target_id)
        argv = build_argv(target, eng.get("cfg", {}), scan.profile,
                          scan.params or {}, creds, run_dir, REPO)
        scan.workdir = str(run_dir)
        scan.status = "running"
        scan.started_at = _utcnow()
        scan.progress = 0.0
        db.commit()
        _log(scan_id, "engine %s -> %s (%s)" % (scan.engine_id,
                                                target.address,
                                                scan.profile))
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONPYCACHEPREFIX"] = str(settings.var_dir / "pycache")
        proc = subprocess.Popen(argv, cwd=str(run_dir), env=env,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        lines = []
        last_flush = 0.0

        def flush(force=False):
            nonlocal lines, last_flush
            if lines and (force or len(lines) >= 40 or
                          _INTERVAL - last_flush <= 0):
                _push_events(scan_id, lines)
                lines = []
                last_flush = 0.0

        while proc.poll() is None:
            for key, _ in sel.select(timeout=0.25):
                data = key.fileobj.readline()
                if data:
                    clean = ANSI.sub("", data).strip()
                    if clean and not BANNER.search(clean) and \
                            not _BLANK.match(clean):
                        lines.append((_classify(clean), clean))
                        m = _PROGRESS.search(clean)
                        if m:
                            scan.progress = min(99.0, float(m.group(1)))
                            last_flush = 1.0
            flush()
            if scan.cancel_requested:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                scan.status = "canceled"
                scan.progress = 100.0
                scan.finished_at = _utcnow()
                db.commit()
                _log(scan_id, "cancel requested by operator", "warning")
                return
        flush(force=True)
        code = proc.returncode
        scan.exit_code = code
        if scan.cancel_requested:
            scan.status = "canceled"
        else:
            total, has_report = _harvest(scan, run_dir)
            scan.progress = 100.0
            if has_report:
                scan.status = "completed"
                _log(scan_id, "scan complete: %d findings, report ready"
                     % total)
            else:
                scan.status = "failed"
                scan.error = "engine exited (%d) without a report" % code
                _log(scan_id, scan.error, "error")
        scan.finished_at = _utcnow()
        db.commit()
    except Exception as exc:
        scan = db.get(models.Scan, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.error = str(exc)[:2000]
            scan.finished_at = _utcnow()
            db.commit()
        _log(scan_id, "worker error: %s" % exc, "error")
    finally:
        db.close()