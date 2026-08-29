"""Vajra - credential brute-force: FTP, SSH (paramiko optional), HTTP basic
auth and discovered login forms."""
import socket
import time
import base64
from concurrent.futures import ThreadPoolExecutor

from core.database import Finding
from core.utils import load_json

try:
    import paramiko
    HAVE_PARAMIKO = True
except Exception:
    paramiko = None
    HAVE_PARAMIKO = False

import ftplib


def _ftp_check(host, port, user, pw):
    try:
        f = ftplib.FTP()
        f.connect(host, port, timeout=8)
        f.login(user, pw)
        try:
            files = len(f.nlst())
        except Exception:
            files = -1
        f.quit()
        return True, files
    except ftplib.error_perm as e:
        msg = str(e)
        if "530" in msg:
            return False, None
        if "530" not in msg and ("logged in" in msg.lower()):
            return True, -1
        return False, None
    except Exception:
        return None, None


def _ssh_check(host, port, user, pw):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(host, port=port, username=user, password=pw,
                    timeout=8, allow_agent=False, look_for_keys=False)
        cli.close()
        return True
    except Exception as e:
        msg = str(e).lower()
        if "auth" in msg or "password" in msg or "authentication" in msg:
            return False
        return None
    finally:
        try:
            cli.close()
        except Exception:
            pass


def run(engine):
    t = engine.target
    host = t.scan_host()
    users = engine.users() or ["admin", "root", "test"]
    pwds = engine.passwords() or ["admin", "123456"]
    deep = engine.deep
    ftp_user_cap, ftp_pwd_cap = (40, 6000) if deep else (12, 400)
    ssh_user_cap, ssh_pwd_cap = (25, 4000) if deep else (8, 300)
    form_cap = int(engine.cfg("form_attempts", 20000 if deep else 2500))
    delay = float(engine.cfg("brute_delay", 0.0))
    services = {s["port"]: s for s in engine.state.get("services", [])}
    creds_found = []

    ftp_port = 21 if 21 in services else None
    if ftp_port:
        combos = [(u, p) for u in users[:ftp_user_cap]
                  for p in pwds[:ftp_pwd_cap]]
        engine.log.info("FTP brute: %d combinations" % len(combos))
        anon_ok = False
        ok, nfiles = _ftp_check(host, 21, "anonymous", "vajra@example.com")
        if ok is True:
            anon_ok = True
            creds_found.append(("21/ftp", "anonymous", ""))
            engine.db.add_finding(Finding(
                t.display, "network.brute", "credentials", "high",
                "Anonymous FTP access allowed",
                detail="Anonymous login succeeded; %s files listed." %
                       ("unknown" if nfiles < 0 else str(nfiles)),
                remediation="Disable anonymous FTP or restrict to read-only "
                            "chrooted shares.", confidence="firm"))
        for u, p in combos:
            if anon_ok:
                break
            ok, nf = _ftp_check(host, 21, u, p)
            if ok is True:
                creds_found.append(("21/ftp", u, p))
                engine.db.add_finding(Finding(
                    t.display, "network.brute", "credentials", "critical",
                    "FTP credentials cracked via brute force (%s:%s)" % (u, p),
                    evidence="host=%s port=21 user=%s" % (host, u),
                    confidence="firm"))
                break
            if delay:
                time.sleep(delay)

    ssh_port = 22 if 22 in services else None
    if ssh_port:
        if not HAVE_PARAMIKO:
            engine.db.add_finding(Finding(
                t.display, "network.brute", "coverage", "info",
                "SSH brute skipped - paramiko not installed",
                detail="pip install paramiko to enable SSH credential attacks.",
                confidence="firm"))
        else:
            combos = [(u, p) for u in users[:ssh_user_cap]
                      for p in pwds[:ssh_pwd_cap]]
            engine.log.info("SSH brute: %d combinations" % len(combos))
            stop = False
            for u, p in combos:
                if stop:
                    break
                r = _ssh_check(host, 22, u, p)
                if r is True:
                    creds_found.append(("22/ssh", u, p))
                    engine.db.add_finding(Finding(
                        t.display, "network.brute", "credentials", "critical",
                        "SSH credentials cracked via brute force (%s:%s)" % (u, p),
                        evidence="host=%s port=22 user=%s" % (host, u),
                        confidence="firm"))
                    stop = True
                elif r is None and delay == 0:
                    time.sleep(0.2)
                if delay:
                    time.sleep(delay)

    http_targets = []
    wt = engine.state.get("web_targets") or []
    for w in wt:
        http_targets.append(w["url"].rstrip("/"))

    auth_paths = engine.state.get("http_auth_paths", [])
    if http_targets and auth_paths:
        for url, path in auth_paths[:3]:
            hit = _basic_brute(engine, url + path,
                               users[:20], pwds[:min(len(pwds), form_cap // 2)])
            if hit:
                creds_found.append(("%s%s" % (url, path), hit[0], hit[1]))
                engine.db.add_finding(Finding(
                    t.display, "network.brute", "credentials", "high",
                    "HTTP Basic Auth cracked on %s (%s:%s)" %
                    (path, hit[0], hit[1]),
                    evidence=url + path, confidence="firm"))

    forms = engine.state.get("forms", [])
    login_forms = [f for f in forms if any(
        fd["type"] == "password" for fd in f.get("fields", []))][:2]
    for form in login_forms:
        user_field = next((fd["name"] for fd in form["fields"]
                           if "user" in fd["name"].lower() or "email" in fd["name"].lower()
                           or "login" in fd["name"].lower()), None)
        pass_field = next((fd["name"] for fd in form["fields"]
                           if fd["type"] == "password"), None)
        if not pass_field:
            continue
        baseline = engine.http.post(form["action"],
                                    data=_mkdata(form["fields"], user_field, pass_field,
                                                 "vjr-nouser", engine.nonce()))
        blen = len(baseline.body)
        found = None
        attempts = 0
        for u in users[:10]:
            for p in pwds[:max(1, form_cap // 10)]:
                data = _mkdata(form["fields"], user_field, pass_field, u, p)
                r = engine.http.post(form["action"], data=data)
                success = (r.status != baseline.status) or \
                          (abs(len(r.body) - blen) > max(50, int(blen * 0.05))) or \
                          any(k in r.headers.get("location", "").lower()
                              for k in ("welcome", "dashboard", "home"))
                if success:
                    found = (u, p)
                    break
                attempts += 1
                if attempts >= form_cap:
                    break
            if found or attempts >= form_cap:
                break
        if found:
            creds_found.append((form["action"], found[0], found[1]))
            engine.db.add_finding(Finding(
                t.display, "network.brute", "credentials", "high",
                "Login form weak password (%s:%s) at %s" %
                (found[0], found[1], form["action"]),
                detail="Detected via response differential heuristics; verify manually.",
                confidence="possible"))

    if creds_found:
        summary = "\n".join("%-28s %s:%s" % c for c in creds_found)
        engine.log.finding("[brute] valid credentials:\n" + summary)
        box = engine.state.setdefault("creds", [])
        for svc, u, p in creds_found:
            box.append((svc, u, p))


def _mkdata(fields, user_field, pass_field, user, pwd):
    data = {}
    for f in fields:
        data[f["name"]] = f.get("value", "")
    if user_field:
        data[user_field] = user
    if pass_field:
        data[pass_field] = pwd
    return data


def _basic_brute(engine, url, users, pwds):
    probe = engine.http.get(url, allow_redirects=False)
    if probe.status != 401 and "www-authenticate" not in probe.headers:
        return None
    realm = ""
    wa = probe.headers.get("www-authenticate", "")
    if 'realm="' in wa:
        realm = wa.split('realm="')[1].split('"')[0]
    for u in users:
        for p in pwds:
            r = engine.http.get(url, allow_redirects=False, auth=(u, p))
            if r.status not in (401, 403, 0):
                return (u, p)
            if engine.cfg("brute_delay", 0):
                time.sleep(float(engine.cfg("brute_delay")))
    return None
