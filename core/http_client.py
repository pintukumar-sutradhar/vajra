"""Vajra - HTTP client abstraction (requests if available, else stdlib urllib)."""
import json as _json
import time
import base64
import threading
from urllib.parse import urlencode

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:
    requests = None
    _HAVE_REQUESTS = False

import ssl
import urllib.request
import urllib.error
import http.client

if _HAVE_REQUESTS:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass


class HttpResult:
    def __init__(self, url, status, headers, content, elapsed):
        self.url = url
        self.status = status
        self.headers = {str(k).lower(): str(v) for k, v in headers.items()}
        self.content = content if isinstance(content, bytes) else str(content).encode("utf-8", "replace")
        self.elapsed = elapsed

    @property
    def body(self):
        return self.content.decode("utf-8", "replace")

    text = body

    @property
    def ok(self):
        return 200 <= self.status < 400

    @property
    def json(self):
        try:
            return _json.loads(self.body)
        except Exception:
            return None

    @property
    def cookies_str(self):
        parts = []
        for k, v in self.headers.items():
            if k == "set-cookie":
                parts.append(v)
        return "; ".join(parts)


_UNVERIFIED_CTX = ssl.create_default_context()
_UNVERIFIED_CTX.check_hostname = False
_UNVERIFIED_CTX.verify_mode = ssl.CERT_NONE


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_multipart(fields=None, files=None):
    """Return (content_type, body_bytes) for a multipart/form-data request.
    fields: dict[str,str]; files: list of (name, filename, ctype, bytes)."""
    import uuid as _uuid
    boundary = "----vajra" + _uuid.uuid4().hex
    parts = []
    for k, v in (fields or {}).items():
        parts.append(("--%s\r\nContent-Disposition: form-data; "
                      'name="%s"\r\n\r\n%s\r\n' % (boundary, k, v)).encode())
    for name, fname, ctype, blob in (files or []):
        parts.append(("--%s\r\nContent-Disposition: form-data; "
                      'name="%s"; filename="%s"\r\n'
                      "Content-Type: %s\r\n\r\n"
                      % (boundary, name, fname, ctype)).encode())
        parts.append(blob)
        parts.append(b"\r\n")
    parts.append(("--%s--\r\n" % boundary).encode())
    return ("multipart/form-data; boundary=%s" % boundary), b"".join(parts)


def peer_cert(host, port=443, timeout=5.0):
    """Return decoded X.509 info dict for a TLS peer: subject, issuer,
    notBefore/notAfter, SAN list. None on failure."""
    try:
        import socket as _socket
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with _socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(der, default_backend())
        def _name(n):
            return ", ".join("=".join(x.rfc4514_string().split("=", 1))
                             for x in n.rdns)
        excepts = {}
        try:
            ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value
            san = [t for t in ext.get_values_for_type(x509.DNSName)]
            san += [t for t in ext.get_values_for_type(x509.IPAddress)]
        except Exception:
            san = []
        return {
            "subject": _name(cert.subject),
            "issuer": _name(cert.issuer),
            "not_before": cert.not_valid_before_utc,
            "not_after": cert.not_valid_after_utc,
            "san": san,
        }
    except Exception:
        return None


def raw_http(host, port, data, timeout=6.0, tls=True, read_limit=2 * 1024 * 1024,
             socks5=None):
    """Send raw request bytes over a fresh (optional TLS) connection and
    return the concatenated raw response bytes. Enables Host-header
    overrides, pipelined requests (smuggling probes) and WebSocket upgrades.
    socks5: 'host:port' routes the TCP connect through a SOCKS5 proxy."""
    import socket as _socket
    try:
        if socks5:
            s = socks5_connect(socks5, host, port, timeout=timeout)
        else:
            s = _socket.create_connection((host, port), timeout=timeout)
        if tls:
            s = _UNVERIFIED_CTX.wrap_socket(s, server_hostname=host)
        s.settimeout(timeout)
        if isinstance(data, str):
            data = data.encode()
        s.sendall(data)
        chunks = []
        try:
            while True:
                b = s.recv(65536)
                if not b:
                    break
                chunks.append(b)
                if sum(len(c) for c in chunks) > read_limit:
                    break
        except socket.timeout:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        return b"".join(chunks)
    except Exception:
        return b""


def socks5_connect(proxy, host, port, timeout=8.0):
    """Minimal SOCKS5 (RFC 1928) CONNECT. proxy='host:port'. Returns a
    connected socket. Raises on any failure."""
    import socket as _socket
    ph, _, pp = proxy.partition(":")
    pport = int(pp or 1080)
    s = _socket.create_connection((ph, pport), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")            # version, 1 method, no-auth
        ver, method = s.recv(2)
        if ver != 5 or method != 0:
            raise RuntimeError("SOCKS5 no-auth not accepted (%r)" %
                               (ver, method))
        if isinstance(host, str):
            host = host.encode("idna")
        req = b"\x05\x01\x00" + b"\x03" + bytes([len(host)]) + host + \
            ((port >> 8) & 0xFF).to_bytes(1, "big") + \
            (port & 0xFF).to_bytes(1, "big")
        s.sendall(req)
        hdr = s.recv(10)
        if not hdr or hdr[0] != 5 or hdr[1] != 0:
            raise RuntimeError("SOCKS5 connect refused (%r)" % hdr[:2])
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        raise


class _Socks5HTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port=None, proxy=None, timeout=...):
        super().__init__(host, port, timeout=None if timeout is ... else
                         timeout)
        self._sp = proxy

    def connect(self):
        self.sock = socks5_connect(self._sp, self.host, self.port,
                                   timeout=self.timeout or 8)


class _Socks5HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port=None, proxy=None, timeout=...,
                 context=None):
        super().__init__(host, port, timeout=None if timeout is ... else
                         timeout,
                         context=context or ssl._create_unverified_context())
        self._sp = proxy

    def connect(self):
        self.sock = socks5_connect(self._sp, self.host, self.port,
                                   timeout=self.timeout or 8)
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self._tunnel_host or self.host)


class _Socks5HTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, proxy, timeout=None):
        self._sp, self._to = proxy, timeout
        super().__init__()

    def http_open(self, req):
        return self.do_open(_Socks5HTTPConnection, req, proxy=self._sp)


class _Socks5HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, proxy, timeout=None):
        self._sp, self._to = proxy, timeout
        super().__init__()

    def https_open(self, req):
        return self.do_open(_Socks5HTTPSConnection, req, proxy=self._sp)


class _ConnectTunnelHTTPConnection(http.client.HTTPConnection):
    """Plain-HTTP transport dialed through an HTTP CONNECT proxy (RFC 7231)."""
    def __init__(self, host, port=None, proxy=None, timeout=...):
        super().__init__(host, port, timeout=None if timeout is ...
                         else timeout)
        self._prx = _split_proxy(proxy)

    def connect(self):
        self.sock = socket_create((self._prx[0], self._prx[1]),
                                  timeout=self.timeout or 8)
        _http_connect_tunnel(self.sock, self.host, self.port,
                             self.timeout or 8)


class _ConnectTunnelHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port=None, proxy=None, timeout=..., context=None):
        super().__init__(host, port, timeout=None if timeout is ...
                         else timeout,
                         context=context or ssl._create_unverified_context())
        self._prx = _split_proxy(proxy)

    def connect(self):
        self.sock = socket_create((self._prx[0], self._prx[1]),
                                  timeout=self.timeout or 8)
        _http_connect_tunnel(self.sock, self.host, self.port,
                             self.timeout or 8)
        self.sock = self._context.wrap_socket(self.sock,
                                              server_hostname=self.host)


def _split_proxy(proxy):
    ph, _, pp = proxy.partition(":")
    return ph, int(pp or 8080)


def _http_connect_tunnel(sock, host, port, timeout):
    import socket as _sock
    sock.settimeout(timeout)
    sock.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                  % (host, int(port), host, int(port))).encode("ascii"))
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = sock.recv(4096)
        if not d:
            raise OSError("CONNECT closed early")
        buf += d
        if len(buf) > 65536:
            raise OSError("CONNECT header overflow")
    try:
        code = int(buf.split(b"\r\n", 1)[0].split(b" ", 2)[1])
    except Exception:
        code = 0
    if code != 200:
        raise OSError("CONNECT refused (%d)" % code)


def socket_create(addr, timeout=8.0):
    import socket as _sock
    return _sock.create_connection(addr, timeout=timeout)


class _ConnectHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, proxy, timeout=None):
        self._prx, self._to = proxy, timeout
        super().__init__()

    def http_open(self, req):
        return self.do_open(_ConnectTunnelHTTPConnection, req,
                            proxy=self._prx)


class _ConnectHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, proxy, timeout=None):
        self._prx, self._to = proxy, timeout
        super().__init__()

    def https_open(self, req):
        return self.do_open(_ConnectTunnelHTTPSConnection, req,
                            proxy=self._prx)


class HttpClient:
    def __init__(self, timeout=6.0, user_agent=None, proxy=None, verify=False,
                 follow=True, delay=0.0, extra_headers=None, socks=None,
                 connect_prox=None):
        self.timeout = timeout
        self.ua = user_agent
        self.proxy = proxy
        self.socks = socks
        self.connect_prox = connect_prox
        self.verify = verify
        self.follow = follow and True
        self.delay = delay
        self.evade = False
        self.extra_headers = extra_headers or {}
        # ip -> hostname : when a URL's host is a plain IP with a mapping, use
        # the mapped hostname as the HTTP Host header while still connecting to
        # the IP. Enables offline vhost serving from /etc/hosts (no DNS).
        self.host_override = {}
        self._cookie = ""
        self._ua_i = 0
        self._lock = threading.Lock()
        # Global request-rate governor (token bucket). rps<=0 means unlimited,
        # preserving prior behaviour unless an ops governor explicitly caps it.
        self._rps = 0.0
        self._tokens = 1.0
        self._bucket_ts = time.time()
        self._rps_lock = threading.Lock()
        if not self.ua:
            from core.utils import USER_AGENTS
            self.ua_pool = list(USER_AGENTS)
        else:
            self.ua_pool = [self.ua]

    def set_host_override(self, ip, host):
        """Send 'Host: <host>' for subsequent HTTP requests to the given IP
        (vhost served from /etc/hosts when DNS is unavailable)."""
        if host:
            self.host_override[(ip or "").strip("[]")] = host

    def _apply_host_override(self, url, hdrs):
        if hdrs.get("Host") or not self.host_override:
            return
        try:
            from urllib.parse import urlparse
            from core.utils import is_ip
            uh = urlparse(url).hostname
            if uh and is_ip(uh) and uh.strip("[]") in self.host_override:
                hdrs["Host"] = self.host_override[uh.strip("[]")]
        except Exception:
            pass

    def apply_cookies(self, cookie_str, merge=True):
        """Adopt Set-Cookie value(s) (e.g. 'SID=abc; foo=bar') so every
        subsequent request carries the session. With merge=True only adds
        pairs that are not already present, so a re-login refreshes."""
        incoming = cookie_str or ""
        if not incoming:
            return
        pairs = {}
        for chunk in incoming.split(";"):
            chunk = chunk.strip()
            if not chunk or "=" not in chunk:
                continue
            k, _, v = chunk.partition("=")
            pairs[k.strip()] = v.strip()
        merged = {}
        for chunk in (self._cookie and self._cookie.split(";") or []):
            if ch := chunk.strip():
                if "=" in ch:
                    merged[ch.split("=", 1)[0].strip()] = \
                        ch.split("=", 1)[1].strip()
        for k, v in pairs.items():
            if merge and k in merged:
                continue
            merged[k] = v
        self._cookie = "; ".join("%s=%s" % (k, v) for k, v in merged.items())

    def clear_cookies(self):
        self._cookie = ""

    def next_ua(self):
        with self._lock:
            ua = self.ua_pool[self._ua_i % len(self.ua_pool)]
            self._ua_i += 1
        return ua

    def set_rate_limit(self, rps):
        """Cap the client's max throughput to `rps` requests/second (global,
        shared across all worker threads). rps<=0 removes the cap."""
        with self._rps_lock:
            self._rps = float(rps) if rps and rps > 0 else 0.0
            if self._rps:
                # start with a fresh full bucket so an already-running burst is
                # still first admitted, then conforms to the steady rate
                self._tokens = self._rps
                self._bucket_ts = time.time()

    def _pacethrottle(self):
        """Token-bucket admission gate: bounds GLOBAL request rate regardless of
        how many parallel scanners (dir-buster/injection/crawl) are sharing this
        client, so stealth/ops throttles actually hold under concurrency."""
        if not self._rps:
            return
        interval = 1.0 / self._rps
        while True:
            with self._rps_lock:
                now = time.time()
                self._tokens = min(self._rps,
                                   self._tokens + (now - self._bucket_ts) * self._rps)
                self._bucket_ts = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rps
            if wait > 0:
                time.sleep(wait)

    def request(self, method, url, params=None, data=None, json_body=None,
                headers=None, auth=None, allow_redirects=None, timeout=None):
        self._pacethrottle()
        t0 = time.time()
        hdrs = {"User-Agent": self.next_ua(), "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close"}
        hdrs.update(self.extra_headers)
        if headers:
            hdrs.update({k: v for k, v in headers.items()})
        self._apply_host_override(url, hdrs)
        if self.evade:
            _r = __import__("random")
            hdrs.setdefault("X-Forwarded-For", "%d.%d.%d.%d" % (
                _r.randint(11, 235), _r.randint(1, 254),
                _r.randint(1, 254), _r.randint(1, 254)))
            hdrs.setdefault("X-Real-IP", "%d.%d.%d.%d" % (
                _r.randint(11, 235), _r.randint(1, 254),
                _r.randint(1, 254), _r.randint(1, 254)))
        if self._cookie and not hdrs.get("Cookie"):
            hdrs["Cookie"] = self._cookie
        allow = self.follow if allow_redirects is None else allow_redirects
        to = timeout or self.timeout
        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urlencode(params)
        auth_header = None
        if auth:
            token = base64.b64encode(("%s:%s" % (auth[0], auth[1])).encode()).decode()
            auth_header = "Basic " + token
        last_err = None
        for attempt in range(2):
            try:
                if _HAVE_REQUESTS and not self.socks and not self.connect_prox:
                    proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
                    r = requests.request(method, url, params=None, data=data,
                                         json=json_body, headers=dict(hdrs, **({"Authorization": auth_header} if auth_header else {})),
                                         timeout=to, verify=self.verify,
                                         allow_redirects=allow, proxies=proxies)
                    all_headers = dict(r.headers.items())
                    if len(r.history) > 0:
                        pass
                    result = HttpResult(r.url, r.status_code, all_headers,
                                        r.content, time.time() - t0)
                else:
                    result = self._urllib_request(method, url, data, json_body,
                                                  hdrs, auth_header, allow, to)
                if self.delay:
                    time.sleep(self.delay)
                return result
            except urllib.error.HTTPError as e:
                body = b""
                try:
                    body = e.read()
                except Exception:
                    pass
                hdrs_resp = {k: v for k, v in (e.headers or {}).items()}
                res = HttpResult(getattr(e, "url", url), e.code, hdrs_resp, body, time.time() - t0)
                if self.delay:
                    time.sleep(self.delay)
                return res
            except Exception as e:
                last_err = e
                time.sleep(0.4 * (attempt + 1))
        return HttpResult(url, 0, {}, repr(last_err).encode(), time.time() - t0)

    def _urllib_request(self, method, url, data, json_body, hdrs, auth_header, allow, to):
        if json_body is not None:
            payload = _json.dumps(json_body).encode()
            hdrs = dict(hdrs)
            hdrs["Content-Type"] = "application/json"
        elif isinstance(data, dict):
            payload = urlencode(data).encode()
            hdrs = dict(hdrs)
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif isinstance(data, (bytes, bytearray)):
            payload = bytes(data)
        elif isinstance(data, str):
            payload = data.encode()
        else:
            payload = None if method in ("GET", "HEAD") else b""
        handlers = [urllib.request.HTTPSHandler(context=_UNVERIFIED_CTX)]
        if self.socks:
            handlers = [_Socks5HTTPSHandler(self.socks, self.timeout),
                        _Socks5HTTPHandler(self.socks, self.timeout)]
        elif self.connect_prox:
            handlers = [_ConnectHTTPSHandler(self.connect_prox, self.timeout),
                        _ConnectHTTPHandler(self.connect_prox, self.timeout)]
        elif self.proxy:
            handlers.append(urllib.request.ProxyHandler({
                "http": self.proxy, "https": self.proxy}))
        if not allow:
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        h = dict(hdrs)
        if auth_header:
            h["Authorization"] = auth_header
        req = urllib.request.Request(url, data=payload, method=method.upper(),
                                     headers=h)
        try:
            resp = opener.open(req, timeout=to)
            content = resp.read(5 * 1024 * 1024)
            final_url = resp.geturl()
            status = resp.status
            rh = {k: v for k, v in resp.headers.items()}
        except urllib.error.HTTPError:
            raise
        finally:
            pass
        return HttpResult(final_url, status, rh, content, 0)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def options(self, url, **kw):
        return self.request("OPTIONS", url, **kw)
