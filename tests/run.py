#!/usr/bin/env python3
"""VAJRA detection-integrity regression tests.

Starts the hostile fixtures in tests/fixtures/serve.py and runs the real
discovery modules against each one, through the real proof gate
(core.proof + Engine.record), then asserts:

  * against the four hostile fixtures the engine reports NOTHING — these are
    servers that answer 200 / 403 / 302 / JSON-error for every path, and each
    one produced findings before the proof gate existed;
  * against the `vulnerable` fixture the engine still reports the genuine
    issues, so the fix is not over-suppression;
  * an HTML-escaping parameter is not reported as XSS, while a parameter
    reflected into a <script> body is.

    python3 tests/run.py            # quiet
    python3 tests/run.py -v         # show every finding and suppression
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import threading
import traceback
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import Engine                      # noqa: E402
from core.database import Database                  # noqa: E402
from core.http_client import HttpClient             # noqa: E402
from core import proof as P                         # noqa: E402
from core import evidence as E                      # noqa: E402
from tests.fixtures import serve as fixtures        # noqa: E402

BASE_PORT = 8910
WORDS = ["admin", "login", "uploads", "backup", "index.php", "search",
         "dashboard", "api", "config", "static", "images", "download"]


class _Target:
    def __init__(self, url):
        self.display = url
        self.address = url
        self.is_domain = False
        self.kind = "web"


class _Args:
    aggressive = False
    stealth = False
    threads = 8


class _Log:
    """Captures engine logging so tests can assert on suppression lines."""

    def __init__(self, quiet=True):
        self.lines = []
        self.quiet = quiet

    def _rec(self, level, msg):
        self.lines.append((level, msg))
        if not self.quiet and level in ("error", "warning", "finding"):
            print("      [%s] %s" % (level, msg))

    def info(self, m, *a):
        self._rec("info", m)

    def debug(self, m, *a):
        self._rec("debug", m)

    def warn(self, m, *a):
        self._rec("warning", m)

    def error(self, m, *a):
        self._rec("error", m)

    def finding(self, m, *a):
        self._rec("finding", m)

    def success(self, m, *a):
        self._rec("success", m)

    def phase(self, m, *a):
        self._rec("phase", m)

    def suppressed(self):
        return [m for lv, m in self.lines if "[SUPPRESS]" in m]


class Harness:
    """The minimum surface the discovery modules need, wired to the real
    proof gate so these tests exercise production logic rather than a copy."""

    record = Engine.record
    suppress = Engine.suppress

    def __init__(self, url, tmpdir, quiet=True):
        self.target = _Target(url)
        self.state = {"web_targets": [{"url": url, "primary": True}]}
        self.http = HttpClient(timeout=6, follow=True)
        self.db = Database(os.path.join(tmpdir, "data.sqlite"))
        self.log = _Log(quiet)
        self.args = _Args()
        self._suppressed_count = 0
        self._cfg = {"dir_threads": 8}

    def cfg(self, k, d=None):
        return self._cfg.get(k, d)

    def dirs_words(self):
        return WORDS

    def progress(self, *a, **k):
        pass

    def findings(self):
        return self.db.findings()

    def suppressed_rows(self):
        return self.db.suppressed()

    def close(self):
        self.db.close()


# --------------------------------------------------------------------------

class Results:
    def __init__(self):
        self.passed = 0
        self.failed = []

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            print("  [PASS] %s%s" % (name, (" — " + detail) if detail else ""))
        else:
            self.failed.append((name, detail))
            print("  [FAIL] %s%s" % (name, (" — " + detail) if detail else ""))

    def summary(self):
        print("\n%d passed, %d failed" % (self.passed, len(self.failed)))
        for name, detail in self.failed:
            print("   FAILED: %s — %s" % (name, detail))
        return 1 if self.failed else 0


def _start_fixtures(verbose=False):
    servers = []
    for mode, offset in fixtures.MODE_OFFSET.items():
        httpd = fixtures.serve(mode, BASE_PORT + offset, verbose)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        servers.append(httpd)
    return servers


def run_module_scan(url, tmpdir, verbose):
    """Run the two rewritten discovery modules against a target."""
    from modules.web import dir_buster, sensitive_files
    h = Harness(url, tmpdir, quiet=not verbose)
    for mod in (dir_buster, sensitive_files):
        try:
            mod.run(h)
        except Exception as exc:
            print("      module %s raised: %r" % (mod.__name__, exc))
            traceback.print_exc()
    out = (h.findings(), h.suppressed_rows(), h.log.suppressed())
    h.close()
    return out


def test_hostile_modes(res, tmpdir, verbose):
    """Servers that look vulnerable to a status-code scanner."""
    print("\n-- hostile fixtures: a correct engine reports nothing --")
    for mode in ("soft404", "wildcard403", "wildcard302", "json404"):
        url = "http://127.0.0.1:%d" % (BASE_PORT + fixtures.MODE_OFFSET[mode])
        findings, suppressed, _ = run_module_scan(url, tmpdir, verbose)
        titles = [f["title"] for f in findings]
        res.check("no findings against %s" % mode, not findings,
                  "reported: %s" % titles[:4] if findings else "")
        if verbose:
            for t in titles:
                print("      FINDING: %s" % t)
            for s in suppressed[:8]:
                print("      suppressed: %s — %s" % (s["title"][:60],
                                                     s["reason"][:80]))


def test_vulnerable_mode(res, tmpdir, verbose):
    """The genuine issues must survive: no over-suppression."""
    print("\n-- vulnerable fixture: real issues must still be found --")
    url = "http://127.0.0.1:%d" % (BASE_PORT + fixtures.MODE_OFFSET["vulnerable"])
    findings, suppressed, _ = run_module_scan(url, tmpdir, verbose)
    blob = "\n".join("%s\n%s\n%s" % (f["title"], f.get("detail") or "",
                                     f.get("evidence") or "")
                     for f in findings).lower()
    res.check("exposed .git reported", ".git" in blob)
    res.check(".env exposure reported", ".env" in blob)
    res.check("something was reported at all", bool(findings),
              "%d finding(s)" % len(findings))
    if verbose:
        for f in findings:
            print("      FINDING [%s/%s] %s" % (f["severity"], f["confidence"],
                                                f["title"]))


def test_proof_units(res):
    """The gate's own logic, including the two headline false positives."""
    print("\n-- proof gate units --")

    # 1. An HTML-escaped echo is not XSS. This was a primary FP source.
    payload = '<svg onload=alert(1)>'
    escaped = ("<html><body><p>Results for &lt;svg onload=alert(1)&gt;"
               "</p></body></html>")
    pr = P.xss_proof(escaped, payload)
    ok, _, reason = P.validate("xss", pr)
    res.check("escaped echo is not accepted as XSS", not ok, reason[:70])

    # 2. A payload reflected into a <script> body is XSS.
    live = ('<html><body><script>var q = "%s";</script></body></html>'
            % payload)
    pr = P.xss_proof(live, payload, control_body="<html><body></body></html>")
    ok, canon, reason = P.validate("xss", pr)
    res.check("script-body reflection is accepted as XSS", ok,
              "%s %s" % (canon, reason[:50]))

    # 3. A payload in an event handler is XSS.
    live = '<html><body><img src=x onerror="alert(1)"></body></html>'
    pr = P.xss_proof(live, 'alert(1)', control_body="<html></html>")
    ok, _, _ = P.validate("xss", pr)
    res.check("event-handler reflection is accepted as XSS", ok)

    # 4. LFI recognises its own base64 php://filter payload — previously it
    #    sent this payload but could not read the result.
    import base64
    b64 = base64.b64encode(fixtures.PASSWD.encode()).decode()
    pr = P.lfi_proof(b64, control_body="<html>nothing</html>")
    ok, canon, reason = P.validate("lfi", pr)
    res.check("base64 php://filter LFI is provable", ok,
              "%s %s" % (canon, reason[:50]))

    # 5. A page that merely mentions /etc/passwd is not LFI once a control
    #    shows the same string without the payload.
    dirty = "<html><p>See root:x:0:0:root in our docs</p></html>"
    pr = P.lfi_proof(dirty, control_body=dirty)
    ok, _, reason = P.validate("lfi", pr)
    res.check("dirty control blocks the LFI claim", not ok, reason[:70])

    # 5b. Not running a control at all is also not proof. Treating "no
    #     control" as "clean control" is the fail-open direction.
    pr = P.lfi_proof(dirty)
    ok, _, reason = P.validate("lfi", pr)
    res.check("missing control blocks the LFI claim", not ok, reason[:70])

    # 6. Missing proof never becomes a finding.
    ok, _, reason = P.validate("lfi", None)
    res.check("absent proof is rejected", not ok, reason[:60])

    # 7. An unregistered class is refused loudly rather than silently.
    ok, canon, reason = P.validate("no_such_class_xyz", P.marker("x"))
    res.check("unclassified finding is refused", not ok and canon is None,
              reason[:60])

    # 8. Confidence is derived, not declared, and caps follow the class.
    res.check("marker -> certain",
              P.confidence_for(P.marker("x")) == "certain")
    res.check("differential -> firm",
              P.confidence_for(P.differential("x")) == "firm")
    res.check("header class cannot exceed medium",
              P.cap_for("header", P.observation("x")) == 2)
    res.check("differential cannot exceed high",
              P.cap_for("lfi", P.differential("x")) == 3)


def test_evidence_units(res):
    """Baseline differencing, including the soft-404 the old signature
    comparison could not see."""
    print("\n-- evidence units --")

    class R:
        def __init__(self, status, body, ctype="text/html", loc=""):
            self.status = status
            self.body = body
            self.headers = {"content-type": ctype}
            if loc:
                self.headers["location"] = loc
            self.url = ""

    tpl = fixtures.SPA_TEMPLATE
    bl = E.Baseline("http://x", [
        E.Fingerprint(R(200, tpl.format(path="/%s.php" % ("a" * 12))),
                      "/%s.php" % ("a" * 12)),
        E.Fingerprint(R(200, tpl.format(path="/%s" % ("b" * 12))),
                      "/%s" % ("b" * 12)),
    ])
    # A soft-404 that echoes the path into <title> AND body — the exact case
    # a prefix-signature comparison misses.
    v, why = E.verdict(R(200, tpl.format(path="/admin")), bl, "/admin")
    res.check("path-echoing soft-404 recognised", v == E.WILDCARD, why[:70])

    # A genuinely different page must still come through.
    real = "<html><head><title>Admin</title></head><body><h1>Admin panel"\
           "</h1><form action=/login></form></body></html>"
    v, why = E.verdict(R(200, real), bl, "/admin")
    res.check("genuinely different page is REAL", v == E.REAL, why[:70])

    # Wildcard 403: same answer for everything.
    bl403 = E.Baseline("http://x", [
        E.Fingerprint(R(403, "<h1>403 Forbidden</h1>"), "/x1"),
        E.Fingerprint(R(403, "<h1>403 Forbidden</h1>"), "/x2"),
    ])
    v, why = E.verdict(R(403, "<h1>403 Forbidden</h1>"), bl403, "/admin")
    res.check("wildcard 403 is not evidence of existence",
              v == E.WILDCARD, why[:70])

    # ...but a 403 where absent paths give 404 IS evidence.
    bl404 = E.Baseline("http://x", [
        E.Fingerprint(R(404, "<h1>Not Found</h1>"), "/x1"),
    ])
    v, why = E.verdict(R(403, "<h1>403 Forbidden</h1>"), bl404, "/admin")
    res.check("403-vs-404 difference proves existence", v == E.REAL, why[:70])

    # JSON 200 error envelope.
    jb = '{"error":"not found","path":"%s"}'
    blj = E.Baseline("http://x", [
        E.Fingerprint(R(200, jb % ("/" + "c" * 20), "application/json"),
                      "/" + "c" * 20),
    ])
    v, why = E.verdict(R(200, jb % "/admin", "application/json"), blj, "/admin")
    res.check("JSON soft-404 recognised", v == E.WILDCARD, why[:70])

    # 404 is authoritative with no baseline at all.
    v, _ = E.verdict(R(404, "nope"), None, "/x")
    res.check("unbaselined 404 is ABSENT", v == E.ABSENT)

    # ...and an unbaselined 200 is NOT promoted to a finding.
    v, why = E.verdict(R(200, "hello"), None, "/x")
    res.check("unbaselined 200 is not REAL", v == E.WILDCARD, why[:60])


def test_live_injection(res, verbose):
    """The escaping vs executable distinction, against a live server."""
    print("\n-- live reflection: escaped vs executable --")
    url = "http://127.0.0.1:%d" % (BASE_PORT + fixtures.MODE_OFFSET["vulnerable"])
    http = HttpClient(timeout=6, follow=True)
    nonce = "vjr7f3a9c1"
    payload = '<svg onload=alert("%s")>' % nonce
    # A raw payload cannot go in a URL verbatim: HttpClient rejects spaces and
    # quoting ("URL can't contain control characters"), which would return an
    # error *text* as the body and both fail the real probe and fake the
    # escaping one. Encode for the wire; the fixture decodes before reflecting.
    enc = urllib.parse.quote(payload, safe="")

    # The escaping parameter: must NOT be accepted as XSS.
    try:
        r = http.get(url + "/?q=" + enc, allow_redirects=False)
        pr = P.xss_proof(r.body, payload, control_body="")
        ok, _, reason = P.validate("xss", pr)
        res.check("/?q= (escaping) is not XSS", not ok, reason[:70])
    except Exception as exc:
        res.check("/?q= (escaping) is not XSS", False, repr(exc))

    # The executable parameter: MUST be accepted.
    try:
        ctrl = http.get(url + "/search?x=benign", allow_redirects=False)
        r = http.get(url + "/search?x=" + enc, allow_redirects=False)
        pr = P.xss_proof(r.body, payload, control_body=ctrl.body)
        ok, _, reason = P.validate("xss", pr)
        res.check("/search?x= (script body) is XSS", ok, reason[:60])
    except Exception as exc:
        res.check("/search?x= (script body) is XSS", False, repr(exc))

    # A benign control for the LFI parameter must not yield a marker.
    try:
        r = http.get(url + "/index.php?file=index.php", allow_redirects=False)
        pr = P.lfi_proof(r.body, control_body="")
        ok, _, _ = P.validate("lfi", pr)
        res.check("benign include value is not LFI", not ok)
    except Exception as exc:
        res.check("benign include value is not LFI", False, repr(exc))

    # And the real traversal must be.
    try:
        r = http.get(url + "/index.php?file=../../../../etc/passwd",
                     allow_redirects=False)
        pr = P.lfi_proof(r.body, control_body="")
        ok, _, reason = P.validate("lfi", pr)
        res.check("traversal include IS LFI", ok, reason[:60])
    except Exception as exc:
        res.check("traversal include IS LFI", False, repr(exc))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    servers = _start_fixtures(args.verbose)
    res = Results()
    tmpdir = tempfile.mkdtemp(prefix="vajra-fp-test-")
    try:
        test_proof_units(res)
        test_evidence_units(res)
        test_hostile_modes(res, tmpdir, args.verbose)
        test_vulnerable_mode(res, tmpdir, args.verbose)
        test_live_injection(res, args.verbose)
    finally:
        for s in servers:
            s.shutdown()
    return res.summary()


if __name__ == "__main__":
    raise SystemExit(main())
