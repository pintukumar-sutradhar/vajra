"""VAJRA TCP pivot — route connections through SOCKS5 and/or HTTP CONNECT
proxy chains, and surface a local SOCKS5 pivot server whose outbound fan-out
goes through an upstream chain. Pure stdlib.

Chain hops (ordered, proxies first, target last):
    {"type": "socks5", "host": ..., "port": ...}
    {"type": "http",   "host": ..., "port": ..., "auth": (u, p)?}
    "direct" is implicit for the final target hop.

This is what lets a scan of an internal network run from your box through a
compromised DMZ host that only exposes a SOCKS port."""
import base64
import socket
import struct
import threading


def _split_endpoint(ep):
    if isinstance(ep, dict):
        host = ep.get("host") or ep.get("hostname") or ""
        port = int(ep.get("port", 1080))
        return host, port, ep.get("type"), ep.get("auth")
    host, _, port = str(ep).partition(":")
    return host.strip(), int(port or 1080), "socks5", None


def _atyp_host(host):
    try:
        socket.inet_aton(host)
        return b"\x01", socket.inet_aton(host)
    except OSError:
        pass
    h = host.encode("idna")
    return b"\x03", bytes([len(h)]) + h


def _socks5_connect_tunnel(s, host, port, timeout):
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    ver, method = s.recv(2)
    if ver != 5 or method != 0:
        raise RuntimeError("SOCKS5 no-auth not accepted (%r, %r)" % (ver, method))
    atyp, addr = _atyp_host(host)
    req = b"\x05\x01\x00" + atyp + addr + \
        struct.pack(">H", int(port) & 0xFFFF)
    s.sendall(req)
    hdr = s.recv(10)
    if len(hdr) < 2 or hdr[0] != 5 or hdr[1] != 0:
        raise RuntimeError("SOCKS5 connect refused (%r)" % hdr[:2])
    return s


def _http_connect_tunnel(s, host, port, timeout, auth=None):
    s.settimeout(timeout)
    lines = ["CONNECT %s:%d HTTP/1.1" % (host, int(port)),
             "Host: %s:%d" % (host, int(port))]
    if auth:
        token = base64.b64encode(("%s:%s" % auth).encode("ascii")).decode()
        lines.append("Proxy-Authorization: Basic " + token)
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            raise RuntimeError("HTTP CONNECT closed early")
        buf += d
        if len(buf) > 65536:
            raise RuntimeError("HTTP CONNECT header too large")
    head = buf.split(b"\r\n", 1)[0]
    try:
        code = int(head.split(b" ", 2)[1])
    except Exception:
        code = 0
    if code != 200:
        raise RuntimeError("HTTP CONNECT refused (%d)" % code)
    return s


def _tunnel(s, hop_type, host, port, timeout, auth=None):
    if hop_type in ("socks5", "socks4") or not hop_type:
        return _socks5_connect_tunnel(s, host, port, timeout)
    if hop_type == "http":
        return _http_connect_tunnel(s, host, port, timeout, auth=auth)
    raise RuntimeError("unknown hop type %r" % hop_type)


def connect_via_chain(target_host, target_port, chain, timeout=8.0):
    """Given an ordered list of proxy hops, establish a TCP connection to
    (target_host, target_port) hopping through each. The first hop is dialed
    directly. Returns the open socket. Raises on failure."""
    if not chain:
        return socket.create_connection((target_host, target_port),
                                        timeout=timeout)
    eps = [e if isinstance(e, dict)
           else {"type": "socks5", "host": e[0], "port": int(e[1])}
           for e in chain] + \
        [{"type": "direct", "host": target_host, "port": int(target_port)}]
    first = eps[0]
    s = socket.create_connection((first["host"], first["port"]),
                                 timeout=timeout)
    try:
        for i in range(len(eps) - 1):
            cur = eps[i]
            nxt = eps[i + 1]
            _tunnel(s, cur["type"], nxt["host"], nxt["port"], timeout,
                    auth=cur.get("auth"))
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        raise


class PivotProxy(threading.Thread):
    """Local SOCKS5 (RFC 1928 CONNECT) server. Each accepted client is
    connected via `upstream` (a chain as consumed by connect_via_chain, where
    the final hop is the client's requested target). With upstream=None behaves
    as a plain local SOCKS5 proxy. daemon thread; call stop() to exit."""

    def __init__(self, host="127.0.0.1", port=0, upstream=None,
                 timeout=10.0):
        super().__init__(daemon=True)
        self.bind_host = host
        self.requested_port = port
        self.port = None
        self.upstream = upstream
        self.timeout = timeout
        self._srv = None
        self._stop = threading.Event()
        self._active = []

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind_host, self.requested_port))
        srv.listen(32)
        srv.settimeout(1.0)
        self.port = srv.getsockname()[1]
        self._srv = srv
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            t = threading.Thread(target=self._handle_client, args=(conn,),
                                 daemon=True)
            t.start()
            self._active.append(t)
        try:
            srv.close()
        except Exception:
            pass

    def _handle_client(self, conn):
        try:
            conn.settimeout(8.0)
            hdr = conn.recv(2)
            if len(hdr) < 2 or hdr[0] != 5:
                return
            nmethods = hdr[1]
            methods = b""
            while len(methods) < nmethods:
                d = conn.recv(nmethods - len(methods))
                if not d:
                    return
                methods += d
            if 0 not in methods:
                conn.sendall(b"\x05\xff")
                return
            conn.sendall(b"\x05\x00")
            ver = conn.recv(1)
            if not ver or ver[0] != 5:
                return
            cmd = conn.recv(1)
            conn.recv(1)  # rsv
            atyp = conn.recv(1)
            host = self._read_host(conn, atyp)
            port = struct.unpack(">H", self._recv_exact(conn, 2))[0]
            if cmd[0] != 1:
                conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            if self.upstream:
                inner = connect_via_chain(host, port, self.upstream,
                                          timeout=self.timeout)
            else:
                inner = socket.create_connection((host, port),
                                                 timeout=self.timeout)
            bnd = inner.getsockname()
            resp = b"\x05\x00\x00\x01" + socket.inet_aton(bnd[0]) + \
                struct.pack(">H", bnd[1])
            conn.sendall(resp)
            _splice(conn, inner)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass

    def _read_host(self, conn, atyp):
        if atyp in (b"\x01", 1):
            return socket.inet_ntoa(self._recv_exact(conn, 4))
        if atyp in (b"\x04", 4):
            return socket.inet_ntop(socket.AF_INET6, self._recv_exact(conn, 16))
        if atyp in (b"\x03", 3):
            ln = self._recv_exact(conn, 1)[0]
            return self._recv_exact(conn, ln).decode("utf-8", "replace")
        raise RuntimeError("bad ATYP %r" % atyp)

    def _recv_exact(self, s, n):
        out = b""
        while len(out) < n:
            d = s.recv(n - len(out))
            if not d:
                raise RuntimeError("eof")
            out += d
        return out

    def stop(self):
        self._stop.set()
        try:
            if self._srv:
                self._srv.close()
        except Exception:
            pass


def _splice(a, b, chunk=65536, timeout=8.0):
    """Bidirectionally relay two sockets until either side closes. Each
    direction gets its own thread; join both."""
    def pump(src, dst):
        try:
            src.settimeout(timeout)
            while True:
                d = src.recv(chunk)
                if not d:
                    break
                dst.sendall(d)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    try:
        a.close()
    except Exception:
        pass
    try:
        b.close()
    except Exception:
        pass


def parse_chain(spec):
    """Parse 'socks5://h:p,http://h2:p2' into hop dicts for use as upstream."""
    hops = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        ptype = "socks5"
        body = part
        if "://" in part:
            ptype, _, body = part.partition("://")
        auth = None
        userinfo = None
        host, _, rest = body.partition("/") if "/" in body else \
            (body, "", "")
        if "@" in host:
            userinfo, _, host = host.rpartition("@")
            u, _, p = userinfo.partition(":")
            auth = (u, p)
        hh, _, pp = host.partition(":")
        if not hh:
            raise ValueError("empty hop host in %r" % part)
        hop = {"type": ptype.lower(), "host": hh,
               "port": int(pp or (8080 if ptype.lower() == "http" else 1080))}
        if auth:
            hop["auth"] = auth
        hops.append(hop)
    return hops