"""Vajra - static JavaScript analysis for secrets, endpoints and DOM sinks."""
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
        detail = "\n".join("%s :: %s :: %s..." % f for f in findings_secret[:15])
        engine.db.add_finding(Finding(
            t.display, "web.js", "secrets", "critical" if len(findings_secret) < 4 else "critical",
            "Hardcoded secrets found in client-side JavaScript (%d)" % len(findings_secret),
            detail="Secrets shipped to browsers are considered public.\n" + detail,
            remediation="Rotate the exposed keys immediately; move secrets to "
                        "server-side env config.", confidence="firm"))
    if findings_internal:
        uniq = sorted({f[1].split("?")[0] for f in findings_internal})[:15]
        engine.db.add_finding(Finding(
            t.display, "web.js", "info-disclosure", "medium",
            "Internal infrastructure URLs leaked in JavaScript",
            evidence=uniq and "\n".join(uniq), confidence="firm"))
    if findings_sourcemap:
        engine.db.add_finding(Finding(
            t.display, "web.js", "info-disclosure", "low",
            "Source maps referenced in production bundles",
            evidence="\n".join(sorted(set(findings_sourcemap))[:10]),
            detail="Source maps expose original source logic to attackers.",
            confidence="firm"))
    if findings_domsink:
        engine.db.add_finding(Finding(
            t.display, "web.js", "potential-xss", "medium",
            "Potential DOM-XSS: dangerous sink with tainted source in JS (%d)" %
            len(findings_domsink),
            detail="Static sink+source co-occurrence — needs browser-level "
                   "confirmation for a real unescaped flow.\n" +
                   "\n".join("%s :: %s..." % f for f in findings_domsink[:10]),
            remediation="Avoid innerHTML/document.write with taint; use "
                        "textContent; audit with a DOM renderer.",
            confidence="possible"))
    engine.state.setdefault("js_endpoints", sorted(endpoints)[:200])
    if endpoints:
        engine.db.add_finding(Finding(
            t.display, "web.js", "recon", "info",
            "API endpoints extracted from JS: %d" % len(endpoints),
            evidence="\n".join(sorted(endpoints)[:80]), confidence="firm"))
