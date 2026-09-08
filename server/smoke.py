"""End-to-end local smoke test for the VAJRA platform (Phase 1).

Runs a real engine scan (webapp/quick) against a tiny local HTTP target and
exercises: auth -> brand -> engines -> targets -> scan create (with and
without the authorization gate) -> worker -> poll -> findings -> triage ->
events -> report download.

Usage:  VAJRA_DB_URL=sqlite:////tmp/vajra_smoke.db \
        VAJRA_PLATFORM_VAR=/tmp/vajra_smoke_var \
        python server/smoke.py
"""

import os
import shutil
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

_smoke_var = Path("/tmp/vajra_smoke_var")
_smoke_db = "/tmp/vajra_smoke_db/platform.db"
os.environ["VAJRA_DB_URL"] = "sqlite:///" + _smoke_db
os.environ["VAJRA_PLATFORM_VAR"] = str(_smoke_var)

failures = []


def check(label, cond, extra=""):
    if cond:
        print("  [ok] %s" % label)
    else:
        print("  [FAIL] %s %s" % (label, extra))
        failures.append(label)


INDEX = b"""<html><head><title>vajra-smoke app</title></head>
<body><h1>Smoke app</h1>
<form action="/login" method="post">
<input name="username"><input name="password">
<button type="submit">Sign in</button></form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = INDEX
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def run_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.thread = threading.Thread(target=server.serve_forever,
                                     daemon=True)
    server.thread.start()
    return server


def main():
    for d in (_smoke_var, Path(_smoke_db).parent):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)

    from fastapi.testclient import TestClient
    from server.app import models
    from server.app.main import app

    target = run_target()
    url = "http://127.0.0.1:%d/" % target.server_address[1]
    print("target: %s" % url)

    with TestClient(app) as c:
        r = c.get("/health")
        check("health", r.status_code == 200 and r.json().get("ok"))
        r = c.get("/api/v1/auth/brand")
        check("brand", r.status_code == 200 and r.json().get("product"))
        r = c.post("/api/v1/auth/login",
                   json={"username": "admin", "password": "admin123"})
        check("login", r.status_code == 200, r.text[:200])
        token = r.json()["token"]
        H = {"Authorization": "Bearer " + token}
        check("me", c.get("/api/v1/auth/me", headers=H).status_code == 200)

        r = c.get("/api/v1/engines", headers=H)
        engines = [e["engine_id"] for e in r.json()]
        check("engines", "webapp" in engines and
              "active_directory" in engines, str(engines))

        r = c.post("/api/v1/targets", headers=H,
                   json={"kind": "url", "address": url,
                         "authorization_proof": ""})
        check("authorization gate", r.status_code == 422, r.text[:160])

        r = c.post("/api/v1/targets", headers=H,
                   json={"kind": "url", "address": url,
                         "name": "smoke local",
                         "authorization_proof": "LOCAL-SMOKE-AUTH-REF"})
        check("target create", r.status_code == 201, r.text[:200])
        target_id = r.json()["id"]

        bad = c.post("/api/v1/scans", headers=H,
                     json={"target_id": target_id, "engine_id": "webapp",
                           "profile": "quick"})
        check("scan create", bad.status_code == 201, bad.text[:300])
        scan_id = bad.json()["id"]
        check("scan pending", bad.json()["status"] == "pending")

        from server.worker.queue import tick
        deadline = time.time() + 420
        while time.time() < deadline:
            tick()
            s = c.get("/api/v1/scans/%d" % scan_id, headers=H).json()
            if s["status"] in ("completed", "failed", "canceled"):
                break
            time.sleep(2)
        check("scan terminal", s["status"] in ("completed", "failed"),
              str(s))
        check("scan progress 100", s["progress"] == 100.0)
        check("scan exit_code 0", s["exit_code"] == 0, str(s.get("exit_code")))

        ev = c.get("/api/v1/scans/%d/events" % scan_id, headers=H)
        txt = ev.text
        check("events stream", ev.status_code == 200 and len(txt) > 0,
              "-%d-" % len(txt))

        f = c.get("/api/v1/scans/%d/findings" % scan_id, headers=H)
        findings = f.json()
        check("findings list", f.status_code == 200,
              f.text[:200])
        n = len(findings)
        print("  findings on smoke target: %d" % n)
        if n:
            rid = findings[0]["id"]
            prev_sev = findings[0]["severity"]
            t = c.patch("/api/v1/findings/%d" % rid, headers=H,
                        json={"status": "accepted-risk", "note": "smoke"})
            check("triage transition", t.status_code == 200 and
                  t.json()["status"] == "accepted-risk", t.text[:200])
            t2 = c.patch("/api/v1/findings/%d" % rid, headers=H,
                         json={"status": "bogus"})
            check("triage guard", t2.status_code == 422, t2.text[:120])

        rr = c.get("/api/v1/reports/%d/html" % scan_id, headers=H)
        html_ok = rr.status_code == 200 and (
            "<html" in rr.text[:300].lower())
        check("report html", html_ok, "status=%d" % rr.status_code)
        check("dashboard", c.get("/api/v1/dashboard", headers=H)
              .status_code == 200)
        check("audit", c.get("/api/v1/audit", headers=H)
              .status_code == 200)
        check("no creds in params", bad.json()["params"] == {}, "")

    print("\nAFTER: report bundle at %s" % _smoke_var)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()