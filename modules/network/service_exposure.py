"""Vajra - service exposure sweeps.

Data-driven from intel/services.json: for every open port that maps to a known
service or matches a protocol hint, we send read-only probe payloads and check
for markers that reveal unauthenticated exposure / info disclosure /
weak config (e.g. Redis without AUTH, unauthenticated Docker API, ES cluster,
k8s read-only kubelet, open ZooKeeper, memcached stats, admin consoles).

Everything here is a read-only protocol/HTTP request; nothing destructive.
"""
import socket
import time

from core.database import Finding
from core.utils import load_json

CATALOG = load_json("intel/services.json", {}).get("services", {})

MAX_PROBES_PER_SERVICE = 3
MAX_SOCKET_READ = 4096


def _as_bytes(x):
    if isinstance(x, bytes):
        return x
    return str(x).encode("latin1", "replace")


def _raw(host, port, payload, timeout=4.0, tls=False):
    """Send bytes, return response bytes or None."""
    import ssl
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect((host, port))
        except Exception:
            return None
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                s = ctx.wrap_socket(s, server_hostname=host)
            except Exception:
                s.close()
                return None
        if payload:
            s.sendall(payload)
        chunks = []
        try:
            while True:
                b = s.recv(MAX_SOCKET_READ)
                if not b:
                    break
                chunks.append(b)
                if len(b) < MAX_SOCKET_READ:
                    break
        except socket.timeout:
            pass
        return b"".join(chunks)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def _banner_hint(buf, hint):
    if not hint:
        return True
    import re as _re
    try:
        if isinstance(buf, bytes):
            text = buf.decode("latin1", "replace")
        else:
            text = str(buf or "")
        return _re.search(hint, text, _re.I) is not None
    except Exception:
        return False


def run(engine):
    t = engine.target
    host = t.scan_host()
    services = engine.state.get("services", []) or []
    probes_seen = 0
    for svc in services:
        port = svc.get("port")
        if not port:
            continue
        matched = None
        for key, spec in CATALOG.items():
            if port in (spec.get("ports") or []):
                matched = (key, spec)
                break
        if not matched:
            continue
        key, spec = matched
        banner = svc.get("banner", "")
        if not _banner_hint(banner, spec.get("hint", "")):
            continue
        for probe in (spec.get("probes") or [])[:MAX_PROBES_PER_SERVICE]:
            if probes_seen >= MAX_PROBES_PER_SERVICE * 8:
                return
            probes_seen += 1
            payload = (probe.get("send") or "").encode("latin1")
            buf = _raw(host, port, payload, timeout=float(
                engine.cfg("http_timeout", 5)))
            if not buf:
                continue
            expect = probe.get("expect", [])
            if expect and expect != [""]:
                if not any(_as_bytes(e) in buf for e in expect):
                    continue
            not_expect = probe.get("not_expect", [])
            if not_expect and any(_as_bytes(x) in buf for x in not_expect):
                continue
            evidence = buf[:600]
            sev = probe.get("severity", "info")
            title = probe.get("label") or ("Exposed %s service on port %d"
                                           % (key, port))
            engine.db.add_finding(Finding(
                t.display, "network.service_exposure",
                probe.get("category", "exposure"), sev,
                "%s on %s:%d" % (title, host, port),
                detail="Service %s (%s) answered a read-only probe on port "
                       "%d.\n%s" % (
                           spec.get("name", key), key, port,
                           probe.get("note", "")),
                evidence=evidence.decode("latin1", "replace")[:800],
                remediation=probe.get("remediation", "Review the service "
                                      "configuration and exposure."),
                confidence="firm" if sev != "info" else "possible"))
            engine.log.finding("[%s] %s:%d -> %s" %
                               (key.upper(), host, port, title[:90]))
            break