#!/usr/bin/env python3
"""Hostile web fixtures for VAJRA's false-positive regression tests.

Each mode is a tiny stdlib HTTP server reproducing one way a real server can
look vulnerable without being so — plus one that really is vulnerable, as a
control against over-suppression. Every "hostile" mode below was reported as
findings by this engine before the proof gate existed.

    python3 tests/fixtures/serve.py --mode soft404 --port 8800
    python3 tests/fixtures/serve.py --all --base 8800        # all five
    python3 tests/fixtures/serve.py --list

Modes
-----
soft404      every path -> 200 with the SPA shell, the path echoed into
             <title> *and* the body. Defeats prefix-signature soft-404
             detection while being indistinguishable from a real 404.
wildcard403  every path -> 403 Forbidden.
wildcard302  every path -> 302 to /login.
json404      every path -> 200 application/json {"error":"not found",...}
vulnerable   genuine issues, each of which a scanner must still find:
               - LFI, plain traversal and php://filter base64
               - reflected XSS in an executable context
               - an HTML-escaping parameter that must NOT be called XSS
               - exposed .git/HEAD, exposed .env, a real ZIP archive
               - /admin answering 403 while absent paths answer 404
               - a real directory listing

Stdlib only, no dependencies.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------
# Content the "vulnerable" target serves
# --------------------------------------------------------------------------

PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)
WININI = ("; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n")
ENVFILE = (
    "APP_ENV=production\n"
    "APP_DEBUG=false\n"
    "DB_HOST=127.0.0.1\n"
    "DB_PASSWORD=Sup3rS3cret-DoNotShip\n"
    "API_KEY=AKIAIOSFODNN7EXAMPLE\n"
)
GITHEAD = "ref: refs/heads/main\n"
ZIPBYTES = b"PK\x03\x04\x14\x00\x00\x00\x08\x00vajra-fixture-backup"

SPA_TEMPLATE = (
    "<!DOCTYPE html>\n<html><head><title>Acme Console — {path}</title>\n"
    "<meta charset=\"utf-8\">\n"
    "<link rel=\"stylesheet\" href=\"/static/app.css\">\n"
    "<link rel=\"icon\" href=\"/static/favicon.ico\">\n"
    "<script src=\"/static/app.js\"></script>\n"
    "</head>\n<body><div id=\"root\"></div>\n"
    "<noscript>Acme Console requires JavaScript.</noscript>\n"
    "<p>The page {path} could not be found.</p>\n"
    "<a href=\"/\">Return to the console</a>\n"
    "</body></html>\n"
)

LISTING = (
    "<!DOCTYPE html><html><head><title>Index of /uploads</title></head>"
    "<body><h1>Index of /uploads</h1><hr><pre>"
    "<a href=\"../\">../</a>\n"
    "<a href=\"q3-report.pdf\">q3-report.pdf</a>   12-Mar-2026 09:14   184320\n"
    "<a href=\"export.csv\">export.csv</a>        02-Feb-2026 17:41     9216\n"
    "</pre><hr></body></html>"
)


def _page(path, body, ctype="text/html; charset=utf-8", status=200,
          extra=None):
    return status, ctype, body.encode("utf-8", "replace"), (extra or {})


def _lfi_result(val):
    """Resolve an include parameter the way a vulnerable PHP app would."""
    v = urllib.parse.unquote(val or "")
    low = v.lower()
    if "php://filter" in low and "passwd" in low:
        if "base64" in low:
            return base64.b64encode(PASSWD.encode()).decode(), "php://filter base64"
        return PASSWD, "php://filter"
    if "etc/passwd" in low or low.rstrip("\x00").endswith("passwd"):
        return PASSWD, "path traversal"
    if "win.ini" in low:
        return WININI, "path traversal"
    if "proc/self/environ" in low:
        return "PATH=/usr/bin\nHOME=/root\n", "path traversal"
    return None, None


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------

class _Base(BaseHTTPRequestHandler):
    mode = "soft404"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if self.server.verbose:
            sys.stderr.write("[fixture:%s] %s\n"
                             % (self.mode, fmt % args))

    def _send(self, status, ctype, body, extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            status, ctype, body, extra = self.route(path, query)
        except Exception as exc:  # pragma: no cover - fixture robustness
            status, ctype, body, extra = _page(
                path, "fixture error: %r" % exc, status=500)
        self._send(status, ctype, body, extra)

    def route(self, path, query):
        return _page(path, "not implemented", status=500)


class Soft404(_Base):
    """Every path is 'found' — the classic SPA catch-all."""
    mode = "soft404"

    def route(self, path, query):
        return _page(path, SPA_TEMPLATE.format(path=path))


class Wildcard403(_Base):
    mode = "wildcard403"

    def route(self, path, query):
        return _page(path, "<html><body><h1>403 Forbidden</h1>"
                           "<p>You do not have permission to access this "
                           "resource.</p></body></html>", status=403)


class Wildcard302(_Base):
    """Everything redirects to the login page — a very common reverse-proxy
    behaviour that produced a mass of bogus 'auth endpoint' findings."""
    mode = "wildcard302"

    def route(self, path, query):
        return (302, "text/html", b"", {"Location": "/login?next=" + path})


class Json404(_Base):
    """A REST API that answers 200 with a JSON error envelope."""
    mode = "json404"

    def route(self, path, query):
        return _page(path, json.dumps({"status": "error",
                                       "error": "resource not found",
                                       "path": path,
                                       "requestId": "req_8f2a1c"}),
                     ctype="application/json")


class Vulnerable(_Base):
    """Genuinely vulnerable. Every real issue here must still be reported."""
    mode = "vulnerable"

    def route(self, path, query):
        # --- real directory listing -------------------------------------
        if path in ("/uploads", "/uploads/"):
            return _page(path, LISTING)
        if path.startswith("/uploads/"):
            return _page(path, "not found", status=404)

        # --- exposed VCS metadata ---------------------------------------
        if path == "/.git/HEAD":
            return (200, "text/plain", GITHEAD.encode(), {})
        if path == "/.git/config":
            return (200, "text/plain",
                    b"[core]\n\trepositoryformatversion = 0\n", {})

        # --- exposed secrets --------------------------------------------
        if path == "/.env":
            return (200, "text/plain", ENVFILE.encode(), {})
        if path == "/backup.zip":
            return (200, "application/zip", ZIPBYTES, {})

        # --- a real access-controlled path ------------------------------
        if path == "/admin":
            return _page(path, "<h1>403 Forbidden</h1>", status=403)

        # --- the dynamic endpoint ---------------------------------------
        if path in ("/index.php", "/search", "/"):
            return self.dynamic(path, query)

        # Everything else genuinely does not exist.
        return _page(path, "<html><head><title>404 Not Found</title></head>"
                           "<body><h1>Not Found</h1>"
                           "<p>The requested URL was not found on this "
                           "server.</p></body></html>", status=404)

    def dynamic(self, path, query):
        # LFI: ?file=
        if "file" in query:
            val = (query.get("file") or [""])[0]
            content, how = _lfi_result(val)
            if content:
                return (200, "text/plain", content.encode(), {})
            return _page(path, SPA_TEMPLATE.format(path=path))

        # XSS in an executable context: reflected verbatim inside a script.
        if path == "/search" and "x" in query:
            val = (query.get("x") or [""])[0]
            body = ("<!DOCTYPE html><html><head><title>Search</title></head>"
                    "<body><h1>Results</h1>\n"
                    "<script>var q = \"" + val + "\";\n"
                    "document.write('no results for ' + q);</script>\n"
                    "</body></html>")
            return _page(path, body)

        # A parameter that IS escaped. Reflecting it is not XSS, and
        # reporting it as such was a primary false-positive source.
        if "q" in query:
            val = (query.get("q") or [""])[0]
            esc = (val.replace("&", "&amp;").replace("<", "&lt;")
                   .replace(">", "&gt;").replace('"', "&quot;")
                   .replace("'", "&#39;"))
            body = ("<!DOCTYPE html><html><head><title>Search</title></head>"
                    "<body><h1>Results for " + esc + "</h1>\n"
                    "<p>Your search for <b>" + esc + "</b> returned no "
                    "results.</p></body></html>")
            return _page(path, body)

        return _page(path, SPA_TEMPLATE.format(path=path))


MODES = {
    "soft404": Soft404,
    "wildcard403": Wildcard403,
    "wildcard302": Wildcard302,
    "json404": Json404,
    "vulnerable": Vulnerable,
}

# Stable port offsets so tests can address a mode without parsing output.
MODE_OFFSET = {"soft404": 0, "wildcard403": 1, "wildcard302": 2,
               "json404": 3, "vulnerable": 4}

# What a correct engine must report for each mode. Used by tests/run.py.
EXPECTATIONS = {
    "soft404": {"max_findings": 0},
    "wildcard403": {"max_findings": 0},
    "wildcard302": {"max_findings": 0},
    "json404": {"max_findings": 0},
    "vulnerable": {"must_contain": ["lfi", "xss", "git", "env"],
                   "must_not_contain": ["search?q=", "&lt;"]},
}


def serve(mode, port, verbose=False):
    handler = MODES[mode]
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.verbose = verbose
    httpd.daemon_threads = True
    return httpd


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mode", choices=sorted(MODES), default=None)
    ap.add_argument("--all", action="store_true",
                    help="start every mode on consecutive ports")
    ap.add_argument("--base", type=int, default=8800,
                    help="base port for --all (default 8800)")
    ap.add_argument("--port", type=int, default=8800)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.list:
        for name in sorted(MODES):
            print("%-12s %s" % (name, (MODES[name].__doc__ or "").strip()
                                .split("\n")[0]))
        return 0

    if args.all:
        servers = []
        for name in sorted(MODES):
            s = serve(name, args.base + MODE_OFFSET[name], args.verbose)
            servers.append((name, s))
            threading.Thread(target=s.serve_forever, daemon=True).start()
            print("  %-12s http://127.0.0.1:%d" %
                  (name, args.base + MODE_OFFSET[name]), flush=True)
        print("\nfixtures running — Ctrl-C to stop", flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            for _, s in servers:
                s.shutdown()
        return 0

    mode = args.mode or "soft404"
    httpd = serve(mode, args.port, args.verbose)
    print("  %-12s http://127.0.0.1:%d" % (mode, args.port), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
