"""Vajra - HTTP security header & cookie hardening audit."""
import http.cookies
import re

from core.database import Finding

CHECKS = [
    ("strict-transport-security", "HSTS not set",
     "Add Strict-Transport-Security to force HTTPS (e.g. max-age=63072000).",
     "medium", True),
    ("content-security-policy", "Content-Security-Policy missing",
     "Deploy a CSP restricting script/style/object sources.",
     "medium", False),
    ("x-frame-options", "X-Frame-Options missing (clickjacking)",
     "Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.",
     "low", False),
    ("x-content-type-options", "X-Content-Type-Options missing",
     "Set X-Content-Type-Options: nosniff.", "low", False),
    ("referrer-policy", "Referrer-Policy missing",
     "Set Referrer-Policy: strict-origin-when-cross-origin.", "low", False),
    ("permissions-policy", "Permissions-Policy missing",
     "Restrict powerful browser features via Permissions-Policy.", "info", False),
]


def _parse_cookies(headers):
    jar = []
    raw = headers.get("set-cookie", "")
    for part in raw.split(","):
        if "=" in part and ";" in part:
            try:
                c = http.cookies.SimpleCookie()
                c.load(part.strip())
                for k, morsel in c.items():
                    attrs = {"secure": bool(morsel["secure"]),
                             "httponly": "httponly" in part.lower(),
                             "samesite": morsel["samesite"] or ""}
                    if k and k not in [j[0] for j in jar]:
                        jar.append((k, attrs))
            except Exception:
                continue
    return jar


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    for wt in targets:
        url = wt["url"].rstrip("/")
        r = engine.http.get(url)
        if r.status == 0:
            continue
        missing = []
        for header, title, fix, sev, https_only in CHECKS:
            if header in r.headers:
                continue
            if https_only and not url.lower().startswith("https"):
                continue
            missing.append((title, fix, sev))
        server_hdr = r.headers.get("server", "")
        powered = r.headers.get("x-powered-by", "")
        disclosers = []
        if server_hdr and any(c.isdigit() for c in server_hdr):
            disclosers.append("Server: %s" % server_hdr)
        if powered:
            disclosers.append("X-Powered-By: %s" % powered)
        if disclosers:
            engine.db.add_finding(Finding(
                t.display, "web.headers", "hardening", "info",
                "Server version disclosure on %s" % url,
                detail="Attackers use version banners to pick matching exploits.",
                evidence="\n".join(disclosers),
                remediation="Suppress or genericize Server/X-Powered-By headers.",
                confidence="firm"))
        _cors_matrix(engine, url)
        cookies = _parse_cookies(r.headers)
        bad_cookie = []
        for name, attrs in cookies:
            problems = []
            if not attrs["httponly"]:
                problems.append("HttpOnly")
            if not attrs["secure"] and url.startswith("https"):
                problems.append("Secure")
            if not attrs["samesite"]:
                problems.append("SameSite")
            if attrs["samesite"] == "none" and not attrs["secure"]:
                problems.append("SameSite=None without Secure (cross-site "
                                "cookies sent over cleartext)")
            if problems:
                bad_cookie.append("%s missing [%s]" % (name, ", ".join(problems)))
        if bad_cookie:
            engine.db.add_finding(Finding(
                t.display, "web.headers", "hardening", "medium",
                "Cookies without hardening flags (%d)" % len(bad_cookie),
                detail="Session cookies are exposed to XSS/network interception "
                       "without these flags.", evidence="\n".join(bad_cookie[:12]),
                confidence="firm"))
        hsts = r.headers.get("strict-transport-security", "")
        if hsts:
            _hsts_audit(engine, url, hsts)
        if missing:
            worst = max(m[2] for m in missing)
            engine.db.add_finding(Finding(
                t.display, "web.headers", "hardening", worst,
                "%d security header(s) missing at %s" % (len(missing), url),
                detail="\n".join("- %s\n  Fix: %s" % (m[0], m[1]) for m in missing),
                confidence="firm"))


_CORS_ORIGINS = [
    ("null", "null"),
    ("pwn domain suffix", "https://vajra-evil.example.com.attacker.net"),
    ("prefix allowlist bypass", "https://vajra-evil.example.attacker.net"),
    ("mirror subdomain", "https://sub.vajra-evil.example"),
    ("scheme trick", "https://vajra-evil.example:443"),
    ("dot trick", "https://vajra-evil.example."),
    ("parent mirror", "https://attacker.net.vajra-evil.example"),
    ("plain cross-origin", "https://attacker.example.net"),
]


def _cors_matrix(engine, url):
    """Depth CORS: reflect/prefix/substring/null/preflight cases."""
    worst = None
    for label, origin in _CORS_ORIGINS:
        r = engine.http.get(url, headers={"Origin": origin},
                            allow_redirects=False)
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "").lower()
        reflected = True
        if not acao:
            reflected = False
        elif not ("*" == acao or origin.lower() in acao.replace("https://", "")
                  .replace("http://", "")):
            reflected = False
        if not reflected:
            continue
        sev = "low"
        sig = label
        if acac == "true":
            sev = "high" if label in ("null", "pwn domain suffix",
                                      "prefix allowlist bypass", "parent mirror",
                                      "scheme trick") else "medium"
        elif label in ("null", "prefix allowlist bypass", "dot trick"):
            sev = "medium"
        cand = (sev, sig, acao, acac, origin)
        if worst is None or _sev_rank(cand[0]) > _sev_rank(worst[0]):
            worst = cand
        if label == "plain cross-origin" and acao == "*":
            worst = (sev, sig, acao, acac, origin)
    if worst is None:
        return
    sev, sig, acao, acac, origin = worst
    pre = ""
    try:
        pr = engine.http.request("OPTIONS", url,
                                 headers={"Origin": "https://attacker.example.net",
                                          "Access-Control-Request-Method": "POST"},
                                 allow_redirects=False)
        if pr.headers.get("access-control-allow-origin"):
            pre = "; preflight ACAO=%s" % pr.headers.get(
                "access-control-allow-origin")
    except Exception:
        pass
    engine.db.add_finding(Finding(
        engine.target.display, "web.headers", "misconfiguration", sev,
        "CORS misconfiguration (%s) on %s" % (sig, url),
        detail="Origin '%s' -> ACAO=%s ACAC=%s%s. %s" % (
            origin, acao, acac or "(absent)", pre,
            "Credentials-carrying cross-origin reads are possible."
            if acac == "true" else "Announces reflect policy beyond a strict "
                                    "allowlist."),
        evidence="test origins: " + "; ".join(l for l, _ in _CORS_ORIGINS),
        remediation="Whitelist exact trusted origins (no substring/prefix "
                    "match); never reflect untrusted input into ACAO.",
        confidence="firm"))
    engine.log.finding("[CORS] %s (%s) at %s" % (sig, sev, url))


def _sev_rank(s):
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[s]


def _hsts_audit(engine, url, hsts):
    m = re.search(r"max-age=(\d+)", hsts, re.I)
    if not m:
        return
    ma = int(m.group(1))
    if ma < 10886400:
        engine.db.add_finding(Finding(
            engine.target.display, "web.headers", "hardening", "low",
            "Short HSTS max-age on %s (%ds)" % (url, ma),
            evidence=hsts, confidence="firm"))
    sub = re.search(r"\bincludeSubDomains\b", hsts, re.I)
    if sub:
        engine.state.setdefault("hsts", {})[url] = hsts
    if not sub and ma >= 10886400:
        engine.db.add_finding(Finding(
            engine.target.display, "web.headers", "hardening", "info",
            "HSTS without includeSubDomains/preload on %s" % url,
            evidence=hsts, confidence="firm"))
