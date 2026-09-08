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
<p><a href="/echo?q=hello">echo</a></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/echo"):
            q = self.path.split("q=", 1)[1] if "q=" in self.path else ""
            body = ("<html><body><h1>Echo</h1><p>Reflected: %s</p>"
                    "</body></html>" % q[:80]).encode()
        else:
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

        live_pdf = c.get("/api/v1/reports/%d/pdf" % scan_id, headers=H)
        check("pdf running guard", live_pdf.status_code == 409,
              str(live_pdf.status_code))

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

        st = c.get("/api/v1/reports/%d/static/report.html" % scan_id, headers=H)
        check("static report", st.status_code == 200 and
              "<html" in st.text[:300].lower(),
              "status=%d" % st.status_code)
        traversal = c.get("/api/v1/reports/%d/static/../../etc/passwd"
                          % scan_id, headers=H)
        check("static traversal guard", traversal.status_code in (403, 404),
              str(traversal.status_code))

        eng = c.get("/api/v1/engines", headers=H).json()
        ids = [e["engine_id"] for e in eng]
        check("engine catalog", all(x in ids for x in
              ["webapp", "api", "infrastructure", "active_directory",
               "external"]), str(ids))
        api_def = next((e for e in eng if e["engine_id"] == "api"), None)
        check("api engine params", api_def is not None and
              "aggressive" in api_def["params_schema"], str(api_def))

        # ---- api engine e2e (url target) ----
        api_scan = c.post("/api/v1/scans", headers=H,
                          json={"target_id": target_id,
                                "engine_id": "api", "profile": "quick",
                                "params": {"aggressive": False}})
        check("api scan create", api_scan.status_code == 201,
              api_scan.text[:200])

        # ---- infrastructure engine e2e (host target) ----
        ht = c.post("/api/v1/targets", headers=H,
                    json={"kind": "ip", "address": "127.0.0.1",
                          "name": "smoke loopback",
                          "authorization_proof": "LOCAL-SMOKE-AUTH-REF"})
        check("host target create", ht.status_code == 201, ht.text[:160])
        inf_scan = c.post("/api/v1/scans", headers=H,
                          json={"target_id": ht.json()["id"],
                                "engine_id": "infrastructure",
                                "profile": "quick"})
        check("infra scan create", inf_scan.status_code == 201,
              inf_scan.text[:200])

        for sid in (api_scan.json()["id"], inf_scan.json()["id"]):
            deadline = time.time() + 300
            while time.time() < deadline:
                tick()
                st = c.get("/api/v1/scans/%d" % sid, headers=H).json()
                if st["status"] in ("completed", "failed", "canceled"):
                    break
                time.sleep(2)
            check("secondary scan terminal (%d)" % sid,
                  st["status"] in ("completed", "failed"), str(st))
            check("secondary scan exit 0 (%d)" % sid,
                  st.get("exit_code") == 0, str(st.get("exit_code")))

        sc_info = c.get("/api/v1/scans/%d" % scan_id, headers=H).json()
        bundle_dir = (sc_info.get("stats") or {}).get("bundle_dir", "")
        import glob as _glob
        pngs = _glob.glob(os.path.join(bundle_dir, "evidence", "*.png")) \
            if bundle_dir else []
        pdf_shot = c.get("/api/v1/reports/%d/pdf" % scan_id, headers=H)
        check("pdf embeds screenshots",
              (not pngs) or (b"image" in pdf_shot.content.lower()),
              "pngs=%d bytes=%d" % (len(pngs), len(pdf_shot.content)))

        not_ready = c.get("/api/v1/reports/999999/pdf", headers=H)
        check("pdf missing scan guard", not_ready.status_code in (404, 409),
              str(not_ready.status_code))

        check("dashboard", c.get("/api/v1/dashboard", headers=H)
              .status_code == 200)
        check("audit", c.get("/api/v1/audit", headers=H)
              .status_code == 200)
        check("no creds in params", bad.json()["params"] == {}, "")

    print("\nAFTER: report bundle at %s" % _smoke_var)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()