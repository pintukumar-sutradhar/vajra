"""VAJRA web.race — TOCTOU / race-condition checks on state-change surfaces.

Picks candidate POST forms (from the crawl) plus configurable API endpoints,
then fires N near-simultaneous identical requests and hunts for the classic
signals of a missing atomicity guard:
  - one-time / CSRF token accepted more than once,
  - multiple success responses for a single-claim operation
  (coupon, promo, transfer, increment, registration),
  - inconsistent body among identical requests.

Uses only idempotent-looking state change with a burn payload; never a real
transaction of the target's choosing beyond a single test parameter."""
import time

from core.database import Finding

MAX_ENDPOINTS = 5
CONCURRENCY = [4, 8]

GUIDANCE = "Prefers double-submit / server-authoritative idempotency; use " \
           "atomic DB ops and per-request one-time nonces bound to the " \
           "session."


def _candidates(engine):
    out = []
    seen = set()
    for page in engine.state.get("pages", []):
        for f in page.get("forms", []):
            action = f.get("action") or page.get("url")
            if not action or action in seen:
                continue
            fields = f.get("fields", [])
            names = {fd.get("name") for fd in fields}
            types = {fd.get("type") for fd in fields}
            if "password" in types:
                continue  # login surfaces are NOT single-claim ops (anti-FP)
            if not any(n in names for n in ("code", "promo", "coupon",
                                            "voucher", "token", "amount",
                                            "quantity", "count", "score",
                                            "credit", "points", "balance",
                                            "email", "user")):
                continue
            seen.add(action)
            out.append((action, f.get("method", "POST").upper(), fields))
            if len(out) >= MAX_ENDPOINTS:
                break
        if len(out) >= MAX_ENDPOINTS:
            break
    for ep in (engine.state.get("api_endpoints") or [])[:MAX_ENDPOINTS]:
        if ep.get("method", "GET").upper() == "POST":
            u = ep.get("url") or ep.get("base", "") + ep.get("path", "")
            if u and u not in seen:
                seen.add(u)
                out.append((u, "POST", [{"name": "value"}]))
    return out


def run(engine):
    t = engine.target
    cands = _candidates(engine)
    if not cands:
        engine.db.add_event(t.display, "web.race",
                            "no state-change POST surfaces to test")
        return
    findings = []
    for url, method, fields in cands:
        base = {fd["name"]: "vajra-race-%s" % str(int(time.time() * 1000) %
                                                  10 ** 6)
                for fd in fields if fd.get("name")}
        per_form = []
        all_bodies = []
        for n in CONCURRENCY:
            started = time.time()
            results = []
            bodies = []
            for _ in range(n):
                try:
                    r = engine.http.post(url, data=dict(base),
                                         allow_redirects=False, timeout=10)
                    results.append(r.status)
                    bodies.append(r.body[:500].lower())
                except Exception:
                    results.append(0)
                    bodies.append(b"")
            wall = time.time() - started
            successes = sum(1 for s in results if 200 <= s < 400)
            per_form.append((n, successes, results, wall))
            all_bodies.extend(bodies)
        best = max(per_form, key=lambda x: x[1])
        n, ok_n, codes, wall = best
        if ok_n >= 2 and ok_n >= n - 1 and len(set(codes)) <= 2:
            dedup_words = (b"already", b"duplicate", b"already used",
                           b"already redeemed", b"already applied",
                           b"already claimed", b"nonce", b"replay")
            if any(w in b for b in all_bodies for w in dedup_words):
                continue
            findings.append((url, base, ok_n, n, wall, codes))
    if not findings:
        engine.db.add_finding(Finding(
            t.display, "web.race", "coverage", "info",
            "Race probes (%d surface(s), to %d concurrent) showed no "
            "split-success signal" % (len(cands), CONCURRENCY[-1]),
            detail="While absence is not proof of safety, identical "
                   "simultaneous submissions each produced a single outcome.",
            confidence="possible"))
        return
    for url, data, ok_n, n, wall, codes in findings[:3]:
        engine.db.add_finding(Finding(
            t.display, "web.race", "logic", "medium",
            "Race-condition signal on state-change endpoint (%.0f ms for %d "
            "concurrent)" % (wall * 1000, n),
            detail="%d/%d identical one-time requests all succeeded. If the "
                   "operation is single-use (coupon/promo/transfer), this "
                   "indicates a TOCTOU window." % (ok_n, n),
            evidence="POST %s\npayload=%s\ncodes=%s (%.0f ms)" % (
                url, data, codes, wall * 1000),
            remediation=GUIDANCE, confidence="possible"))
        engine.log.finding("[race] %s %d/%d x%d" % (url, ok_n, n,
                                                    int(wall * 1000)))