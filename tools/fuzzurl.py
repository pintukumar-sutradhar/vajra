#!/usr/bin/env python3
"""fuzzurl — web content/path fuzzer with soft-404 templating and basic auth.

usage:  fuzzurl.py -u http://host/ -w wordlists/dirs_common.txt
        fuzzurl.py -u http://host/ -e php,txt
        fuzzurl.py -u http://host/ -H 'Cookie: x=1' --auth user:pass
"""
import argparse
import queue
import re
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener, HTTPSHandler

try:
    from _core import c, ok, err, hr
except ImportError:
    from tools._core import c, ok, err, hr

SOFT404 = re.compile(r"(?i)404|not found|page not found|no such file|"
                     r"does not exist|not exist")


def build_opener_args(proxy=None, insecure=True):
    ctx = None
    if insecure:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers = [HTTPSHandler(context=ctx)] if ctx else []
    if proxy:
        from urllib.request import ProxyHandler
        handlers.append(ProxyHandler({"http": proxy, "https": proxy}))
    return handlers


def normalize(base, path, ext=None):
    if not path.startswith(("http://", "https://")):
        path = urljoin(base, path)
    if ext:
        path = path.rstrip("/").rstrip(".") + "." + ext.lstrip(".")
    return path


class Fuzzer:
    def __init__(self, base, wordlist, threads=8, delay=0.0, headers=None,
                 auth=None, statuses=(200, 301, 302, 307, 401, 403),
                 exts=None, proxy=None, timeout=6):
        self.base = base.rstrip("/") + "/"
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.hdrs = dict(headers or {})
        if auth:
            import base64
            token = base64.b64encode(auth.encode()).decode()
            self.hdrs["Authorization"] = "Basic " + token
        self.statuses = set(statuses)
        self.exts = exts
        self.q = queue.Queue()
        self.hits = []
        self.lock = threading.Lock()
        self.opener = build_opener(proxy=proxy)
        self.prefix = self.base
        self._seed_baseline(wordlist)

    def _seed_baseline(self, wordlist):
        try:
            self._baseline = self._get_quiet(self.base)
        except Exception:
            self._baseline = None
        with open(wordlist, encoding="utf-8", errors="replace") as f:
            words = [ln.strip() for ln in f
                     if ln.strip() and not ln.startswith("#")]
        if self.exts:
            words = [w for w in words if "." in w or self._noext(w)]
        for w in words:
            self.q.put(w)

    def _noext(self, w):
        return not any(w.endswith(e) for e in (".php", ".asp", ".aspx",
                                               ".jsp", ".txt", ".html",
                                               ".json", ".zip", ".bak",
                                               ".xml"))

    def _get_quiet(self, url):
        req = Request(url, headers=self.hdrs)
        try:
            r = self.opener.open(req, timeout=self.timeout)
            body = r.read(2000)
            return r.status, r.geturl(), body
        except HTTPError as e:
            return e.code, e.geturl(), e.read(2000)
        except URLError:
            return 0, url, b""

    def _looks_404(self, st, body):
        if st == 404:
            return True
        if st == 0:
            return True
        base = self._baseline
        if base and base[0] == st and len(base[2]) > 0:
            if SELFDIVERGENCE and len(body) > 0:
                if base[2][:256].replace(b"\n", b"").replace(b"\r", b"") == \
                        body[:256].replace(b"\n", b"").replace(b"\r", b""):
                    return True
            if SOFT404.search(body[:1000]):
                return True
        if st in (200, 301, 302) and not body:
            return True
        return bool(SOFT404.search(body[:1000]) and st not in (401, 403))

    def run(self):
        self.alive = True
        workers = [threading.Thread(target=self._w, daemon=True)
                   for _ in range(self.threads)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        return sorted(self.hits, key=lambda h: h[2])

    def _w(self):
        while True:
            try:
                w = self.q.get_nowait()
            except queue.Empty:
                return
            for u in list(self._urls(w)):
                st, _rd, body = self._get_quiet(u)
                if st in self.statuses and not self._looks_404(st, body):
                    with self.lock:
                        self.hits.append((w, u, st, len(body)))
                if self.delay:
                    time.sleep(self.delay)

    def _urls(self, w):
        if self.exts:
            for e in self.exts:
                yield self.prefix + w + "." + e + "/" if False else \
                    self.base + w.rstrip("/") + "." + e
            if "." in w:
                yield self.base + w
        else:
            yield self.base + w.lstrip("/")


SELFDIVERGENCE = True


def main():
    ap = argparse.ArgumentParser(prog="fuzzurl")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-w", "--wordlist", required=True)
    ap.add_argument("-e", "--ext", default=None,
                    help="extensions to append, comma-separated")
    ap.add_argument("-t", "--threads", type=int, default=8)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("-H", "--header", action="append", default=[])
    ap.add_argument("--auth", help="user:pass for HTTP Basic")
    ap.add_argument("--proxy", help="http://host:port")
    ap.add_argument("--code", default="200,301,302,307,401,403")
    ap.add_argument("--timeout", type=float, default=6)
    args = ap.parse_args()

    hdrs = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()

    fz = Fuzzer(args.url, args.wordlist,
                threads=args.threads, delay=args.delay, headers=hdrs,
                auth=args.auth, statuses={int(x) for x in
                                          args.code.split(",")},
                exts=[x.strip() for x in args.ext.split(",")] if args.ext
                else None, proxy=args.proxy, timeout=args.timeout)
    t0 = time.time()
    hits = fz.run()
    hr()
    if not hits:
        err("no hits")
        return 0
    for w, u, st, size in hits:
        print("%s %-48s %s" % (c("[%d]" % st, color=GREEN_BY_CODE(st)),
                               u[:64], c("(%dB)" % size, dim=True)))
    ok("%d hit(s), %.1fs, %d threads" % (len(hits), time.time() - t0,
                                         args.threads))
    return 0


def GREEN_BY_CODE(st):
    return "\033[92m" if st == 200 else "\033[93m"


if __name__ == "__main__":
    sys.exit(main())