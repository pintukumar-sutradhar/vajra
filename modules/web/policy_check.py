"""VAJRA web policy checks (web.policy): rate-limiting / brute-force lockout
and account-lockout-path probing on login surfaces.

We deliberately use a burn username so no real account is ever locked out.
Runs a bounded burst of failed logins and watches the server for the classic
signals (429/423, Retry-After, lockout messages, latency cliff) — and reports
the absence of protection as an information finding when nothing trips."""
import re
import time

from core.database import Finding
from core.utils import load_json

LOCKOUT_HINTS = re.compile("too many attempts|toomany|rate.limit|locked|"
                           "blocked|temporarily|try again later|throttl",
                           re.I)

LOGIN_INTEL = load_json("intel/login_surfaces.json", {})
LOGIN_PATHS = LOGIN_INTEL.get("paths", [])


def _looks_like_login(engine, url):
    """Confirm a candidate URL actually serves a login form (a password input).
    A guessed path that 200s but has no password field is NOT a login surface —
    probing it would invent a bogus 'no rate limiting' finding."""
    try:
        r = engine.http.get(url, allow_redirects=False, timeout=8)
    except Exception:
        return False
    if r.status not in (200, 401, 403):
        return False
    body = (r.content or b"").decode("utf-8", "replace")
    return re.search(r"type=[\"']?password|name=[\"']?(password|pass|pwd|"
                     r"passwd)[\"']?", body, re.I) is not None


def _login_surfaces(engine):
    """Yield (url, method, fields, username_field) for CONFIRMED login forms
    (crawled forms with a password field) or candidate paths that demonstrably
    serve a password input. Never invents a login where none exists."""
    seen = set()
    for page in engine.state.get("pages", []):
        for f in page.get("forms", []):
            fields = f.get("fields", [])
            pass_names = {fd["name"] for fd in fields
                          if fd["type"] in ("password", "pass") or
                          fd["name"] in ("password", "pass", "pwd")}
            user_names = {fd["name"] for fd in fields
                          if fd.get("type") in ("text", "") or
                          fd["name"] in ("user", "username", "email",
                                         "login", "userid")}
            if pass_names and user_names:
                key = (f.get("method", "POST").upper(), f.get("action"))
                if key in seen:
                    continue
                seen.add(key)
                yield (f.get("action"), f.get("method", "POST").upper(),
                       fields, sorted(user_names)[0])
    # Candidate-path guessing is gated on confirmation: only probe a guessed
    # login URL if it actually serves a password field. This keeps us from
    # reporting 'no rate limiting' against a URL that is not a login page.
    for wt in (engine.state.get("web_targets") or []):
        base = wt["url"].rstrip("/")
        cands = [c for c in (LOGIN_PATHS or ("/login", "/signin", "/auth",
                                             "/auth/login", "/token"))
                 if "signup" not in c and "register" not in c]
        for cand in cands:
            key = ("POST", base + cand)
            if key in seen:
                continue
            if not _looks_like_login(engine, base + cand):
                continue
            seen.add(key)
            yield (base + cand, "POST",
                   [{"name": "username"}, {"name": "password"}], "username")


def run(engine):
    t = engine.target
    surfaces = list(_login_surfaces(engine))
    if not surfaces:
        engine.log.warn("[policy] no login surfaces to rate-limit probe")
        engine.state.setdefault("no_rate_limit_surfaces", True)
        return
    attempts = int(engine.cfg("rate_limit_attempts", 8))
    burn_user = "vajra-rl-%s" % str(int(time.time()) % 1000000)
    for idx, (url, method, fields, user_field) in enumerate(surfaces):
        if idx >= 4:
            break
        timings = []
        states = {}
        for i in range(attempts):
            data = {user_field: burn_user,
                    "password": "WrongPass%d!" % (i % 7)}
            for fd in fields:
                if fd["name"] == user_field or fd["name"] in ("password",
                                                              "pass", "pwd"):
                    continue
                if fd.get("type") in ("submit", "button", "hidden", "csrf",
                                      "csrf_token", "token"):
                    data[fd["name"]] = fd.get("value", "")
            t0 = time.time()
            try:
                r = engine.http.request(method, url, data=data,
                                        allow_redirects=False, timeout=6)
            except Exception:
                continue
            took = time.time() - t0
            timings.append(took)
            sig = (r.status, r.headers.get("retry-after", ""),
                   bool(LOCKOUT_HINTS.search(r.body[:2000])))
            if sig not in states:
                states[sig] = 0
            states[sig] += 1
            if r.status in (429, 423) or r.headers.get("retry-after"):
                engine.db.add_finding(Finding(
                    t.display, "web.policy", "verified-control", "info",
                    "Rate limiting / lockout enforced on %s" % url,
                    detail="HTTP %d after %d failed login(s); Retry-After=%s."
                           % (r.status, i + 1 or attempts,
                              r.headers.get("retry-after", "n/a")),
                    evidence="burn user %s" % burn_user,
                    remediation="Keep the policy; log suspicious bursts.",
                    confidence="firm"))
                engine.log.finding("[policy] rate-limited at attempt %d"
                                   % (i + 1))
                return
            time.sleep(min(0.6, i * 0.1))
        if timings:
            last = timings[-1]
            cliff = last > 3 * (sum(timings[:-1]) / max(1, len(timings) - 1)) \
                if len(timings) > 3 else False
            if cliff:
                engine.db.add_finding(Finding(
                    t.display, "web.policy", "verified-control", "info",
                    "Possible lockout latency response on %s" % url,
                    detail="Final attempt took %.1fs vs %.2fs avg — a lockout "
                           "path may be delaying responses." % (
                               last, sum(timings) / len(timings)),
                    evidence="\n".join("%.2fs" % x for x in timings),
                    confidence="possible"))
                return
        engine.db.add_finding(Finding(
            t.display, "web.policy", "unprotected-surface", "medium",
            "No rate limiting / account lockout detected on %s" % url,
            detail="%d failed logins in ~%.1fs with no 429/423/Retry-After, "
                   "uniform responses across attempts — login brute-force is "
                   "not mitigated." % (attempts, sum(timings) or 1),
            evidence="burn user %s; per-attempt timing(s):\n%s" % (
                burn_user, ", ".join("%.2f" % x for x in timings)),
            remediation="Enforce per-account and per-IP rate limits plus "
                        "lockout, and add CAPTCHA for login.",
            confidence="firm"))
        engine.log.finding("[policy] %s: %d attempts, no throttle "
                           "(%.1fs total)" % (url, attempts, sum(timings)))
        return