"""Vajra - WAF / edge-protection fingerprinting."""
from core.database import Finding
from core.utils import load_json, rand_path


def match_waf(signatures, resp):
    body = resp.body[:4000].lower()
    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
    cookie_str = ";".join(v for k, v in headers.items() if k == "set-cookie").lower()
    for name, sig in signatures.items():
        for hk, needle in sig.get("headers", {}).items():
            if hk in headers and (not needle or needle in headers[hk]):
                return name
        for ck in sig.get("cookies", []):
            if ck in cookie_str:
                return name
        for frag in sig.get("body", []):
            if frag in body:
                return name
    return None


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    try:
        sigs = load_json("intel/signatures.json").get("waf_signatures", {})
    except Exception:
        sigs = {}
    probes = ["/" + rand_path(4) + ".php?q=<script>alert(1)</script>",
              "/" + rand_path(4) + ".php?id=1 UNION SELECT NULL",
              "/../../../../etc/passwd"]
    for wt in targets:
        base = wt["url"].rstrip("/")
        detected = {}
        for suffix in probes:
            r = engine.http.get(base + suffix, allow_redirects=False)
            waf = match_waf(sigs, r)
            if waf:
                detected[waf] = True
            if r.status in (403, 406, 429, 501) and not waf:
                detected["Unknown (blocks malicious probes)"] = True
        if not detected:
            r0 = engine.http.get(base + "/", allow_redirects=True)
            waf = match_waf(sigs, r0)
            if waf:
                detected[waf] = True
        if detected:
            names = ", ".join(sorted(detected))
            engine.db.add_finding(Finding(
                t.display, "web.waf", "defense", "info",
                "WAF/edge protection identified: %s" % names,
                detail="Attacks may be blocked or logged by this device. "
                       "Consider evasion testing during authorized engagements.",
                confidence="possible"))
            engine.state.setdefault("waf", names)
            engine.http.evade = True
            engine.log.warn("[waf] %s — auto evasion armed" % names)
        else:
            engine.db.add_finding(Finding(
                t.display, "web.waf", "defense", "info",
                "No WAF detected at %s" % base,
                detail="Probes were not blocked; direct-to-app attacks are viable.",
                confidence="possible"))
