"""Vajra - static JavaScript analysis for secrets, endpoints and DOM sinks.

Only SAME-ORIGIN scripts are analyzed: a third-party library fetched from a
CDN (cdn.jsdelivr.net, unpkg.com, …) tells you nothing about the target, so
its strings/sinks must never become findings on the scanned domain. That
single rule removes the classic false-positive class where `cdn.jsdelivr.net/
npm/rasa-webchat@…` produces a DOM-XSS or a localhost "internal URL leak" on
a site that merely embeds the library."""
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin

from core.database import Finding
from core.utils import load_json

ENDPOINT_RE = re.compile(r"""["'](/[A-Za-z0-9_\-./]{2,40})["']""")
INTERNAL_URL_RE = re.compile(r"https?://(?:localhost|127\.0\.0\.1|10\.[\d.]+|"
                             r"192\.168\.[\d.]+|172\.(?:1[6-9]|2\d|3[01])\.[\d.]+)"
                             r"[^\s\"'<>]*")
DOM_SINK_RE = re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write"
                         r"\s*\(|document\.writeln\s*\(|insertAdjacentHTML\s*\("
                         r"|\beval\s*\(|new\s+Function\s*\(|"
                         r"\.location\s*=\s*|location\.href\s*=|"
                         r"location\.replace\s*\(|\.setAttribute\(\s*['\"]?(src|href)")
DOM_SOURCE_RE = re.compile(r"location\.search|location\.hash|document\.referrer|"
                           r"URLSearchParams|location\.href|document\.cookie|"
                           r"\.value\b|postMessage\s*\(|name\b|"
                           r"localStorage|sessionStorage")


def _host_of(url, default=""):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return default


def same_origin_hosts(engine):
    """Hosts that count as 'the domain': the scanned target plus every
    web-target the crawler discovered from it. Anything else (CDNs, analytics,
    external APIs) is out of scope for client-side findings."""
    hosts = set()
    t = engine.target
    hn = getattr(t, "hostname", "") or ""
    if hn:
        hosts.add(hn.rstrip(".").lower())
    for w in engine.state.get("web_targets", []) or []:
        h = _host_of(w.get("url", ""))
        if h:
            hosts.add(h)
    return hosts


def _in_scope(url, hosts):
    """Apply the strict-domain rule: same host, or a subdomain of one of the
    in-scope hosts (the crawler runs from the given domain, so subdomains of
    it, e.g. api.bracnet.net, stay in scope)."""
    h = _host_of(url)
    if not h:
        return False
    if h in hosts:
        return True
    return any(h.endswith("." + base) for base in hosts if "." in base)


def run(engine):
    t = engine.target
    js_urls = engine.state.get("js", [])[:30]
    if not js_urls:
        pages = engine.state.get("pages", [])
        for p in pages:
            js_urls.extend(p.get("js", []))
        js_urls = sorted(set(js_urls))[:30]
    if not js_urls:
        return
    in_scope = same_origin_hosts(engine)
    js_urls = [u for u in js_urls if _in_scope(u, in_scope)]
    if not js_urls:
        engine.db.add_event(t.display, "web.js",
                            "only out-of-scope (CDN/external) scripts "
                            "present — skipped")
        return
    try:
        secrets = load_json("intel/signatures.json").get("secret_patterns", [])
    except Exception:
        secrets = []

    def fetch(u):
        r = engine.http.get(u)
        return u, r.body if r.status == 200 else ""

    findings_secret = []
    findings_internal = []
    findings_sourcemap = []
    findings_domsink = []
    endpoints = set()

    with ThreadPoolExecutor(max_workers=8) as ex:
        for u, code in ex.map(fetch, js_urls):
            if not code:
                continue
            for sp in secrets:
                try:
                    m = re.search(sp["re"], code)
                except re.error:
                    continue
                if m:
                    findings_secret.append((u, sp["name"], m.group(0)[:80]))
            for m in INTERNAL_URL_RE.finditer(code):
                findings_internal.append((u, m.group(0)[:120]))
            if "# sourceMappingURL=" in code:
                findings_sourcemap.append(u)
            if DOM_SINK_RE.search(code) and DOM_SOURCE_RE.search(code):
                findings_domsink.append((u, DOM_SINK_RE.search(code).group(0)[:48]))
            base = "{uri.scheme}://{uri.netloc}/".format(uri=urlparse(u))
            for m in ENDPOINT_RE.finditer(code):
                ep = m.group(1)
                if any(ep.endswith(x) for x in (".js", ".css", ".png")):
                    continue
                if len(ep) > 3:
                    endpoints.add(urljoin(base, ep))

    if findings_secret:
        ev = "\n".join("%s :: %s" % (u, m) for u, _, m in findings_secret[:15])
        engine.db.add_finding(Finding(
            t.display, "web.js", "secrets", "critical",
            "Hardcoded secrets found in client-side JavaScript (%d)" % len(findings_secret),
            detail="Secrets shipped to browsers are considered public. Tied to "
                   "a SAME-ORIGIN script of %s.\n" % t.display + ev,
            evidence=ev,
            remediation="Rotate the exposed keys immediately; move secrets to "
                        "server-side env config.", confidence="firm"))
    if findings_internal:
        uniq = []
        seen_iv = set()
        for src, raw in ((f[0], f[1]) for f in findings_internal):
            k = raw.split("?")[0]
            if k in seen_iv or len(uniq) >= 15:
                continue
            seen_iv.add(k)
            uniq.append("%s\n  in %s" % (k, src))
        engine.db.add_finding(Finding(
            t.display, "web.js", "info-disclosure", "low",
            "Internal infrastructure URL string inside first-party JS",
            detail="The string below appears in a SAME-ORIGIN script of %s. "
                   "If it is only a dev default (config template), it is not "
                   "an exposure; confirm whether any endpoint actually "
                   "listens there." % t.display,
            evidence="\n".join(uniq), confidence="possible"))
    if findings_sourcemap:
        engine.db.add_finding(Finding(
            t.display, "web.js", "info-disclosure", "low",
            "Source maps referenced in production bundles",
            evidence="\n".join(sorted(set(findings_sourcemap))[:10]),
            detail="Source maps expose original source logic to attackers "
                   "(delete from production).",
            confidence="firm"))
    if findings_domsink:
        ev = "\n".join("%s :: %s..." % f for f in findings_domsink[:10])
        engine.db.add_finding(Finding(
            t.display, "web.js", "potential-xss", "medium",
            "Potential DOM-XSS: dangerous sink with tainted source in JS (%d)" %
            len(findings_domsink),
            detail="Static sink+source co-occurrence in a SAME-ORIGIN script "
                   "of %s — needs browser-level confirmation for a real "
                   "unescaped flow.\n" % t.display + ev,
            evidence=ev,
            remediation="Avoid innerHTML/document.write with taint; use "
                        "textContent; audit with a DOM renderer.",
            confidence="possible"))
    engine.state.setdefault("js_endpoints", sorted(endpoints)[:200])
    if endpoints:
        engine.db.add_finding(Finding(
            t.display, "web.js", "recon", "info",
            "API endpoints extracted from JS: %d" % len(endpoints),
            evidence="\n".join(sorted(endpoints)[:80]), confidence="firm"))
