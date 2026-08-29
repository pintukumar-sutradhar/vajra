"""Vajra - out-of-band collaborator.

A tiny HTTP(and DNS-lite on IPv4 via raw UDP needs no deps; here we ship an
HTTP listener) callback recorder used to confirm BLIND vulnerabilities:

* blind SSRF  -> processor fetches http://<oob>/ssrf/<token>
* blind RCE   -> injected cmd runs  curl|wget|nslookup<ping>  to <oob>
* blind XSS   -> <script src=http://<oob>/xss/<token>>
* blind SQLi  -> DB outbound SELECT to <oob> (Oracle/BG) — best-effort

Usage:
    oob = OobListener(bind="0.0.0.0", port=0)   # port 0 -> ephemeral
    oob.start()
    print(oob.url(), oob.token())               # http://1.2.3.4:PORT/
    ...
    hits = oob.hits()                           # list of dicts
    oob.stop()

The listener is non-blocking (background thread), never serves content that
inspires command injection back at us, and is fully read-only.
"""
import base64
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_SESSION_KEY = "vajra_oob"


def _pick_token(size=6):
    return base64.urlsafe_b64encode(os.urandom(size)).decode().rstrip("=")


class _Handler(BaseHTTPRequestHandler):
    def _note(self):
        path = self.path or "/"
        try:
            ip, port = self.client_address[:2]
        except Exception:
            ip, port = "?", "?"
        rec = {
            "ts": time.time(),
            "path": path,
            "ip": str(ip),
            "port": int(port) if not isinstance(port, str) else port,
            "ua": self.headers.get("User-Agent", ""),
        }
        try:
            rec["referer"] = self.headers.get("Referer", "")
        except Exception:
            pass
        server = getattr(self.server, "app", None)
        if server is not None:
            server.record(rec)

    def do_GET(self):
        self._note()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    do_HEAD = do_POST = do_PUT = do_OPTIONS = do_UPDATE = do_PATCH \
        = do_DELETE = do_GET

    def log_message(self, *args):
        pass


class OobListener:
    def __init__(self, bind="0.0.0.0", port=0):
        self.bind = bind
        self.port = port
        self._hits = []
        self._lock = threading.Lock()
        self._srv = None
        self._thread = None

    @property
    def token(self):
        e = os.environ
        if _SESSION_KEY not in e:
            e[_SESSION_KEY] = _pick_token()
        return e[_SESSION_KEY]

    def start(self):
        if self._srv:
            return
        class App(ThreadingHTTPServer):
            app = None
        httpd = App((self.bind, self.port), _Handler)
        httpd.app = self
        self._srv = httpd
        self.port = httpd.server_address[1]
        self._thread = threading.Thread(target=httpd.serve_forever,
                                        daemon=True)
        self._thread.start()

    def record(self, rec):
        with self._lock:
            self._hits.append(rec)

    def hits(self, since=0.0):
        with self._lock:
            return [h for h in self._hits if h["ts"] >= since]

    def url(self, kind="", host=None):
        host = host or self.host()
        return "http://%s:%d/%s/%s" % (host, self.port, kind, self.token)

    def host(self):
        """Best-effort externally-reachable caller address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
            finally:
                s.close()
        except Exception:
            try:
                h = socket.gethostname()
                return socket.gethostbyname(h)
            except Exception:
                return "127.0.0.1"

    def is_self_address(self, addr):
        return addr in ("127.0.0.1", "::1", self.host())

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()
            self._srv = None


def load_hits_file(path):
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_hits_file(path, hits):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(hits, f, indent=1)
        return True
    except Exception:
        return False