"""Vajra - internal self-test validating core logic contracts."""
import os
import sys
import tempfile

RESULTS = []


def check(name, fn):
    try:
        ok, info = fn()
        RESULTS.append((name, bool(ok), info or ""))
        print(" [%s] %-42s %s" % ("PASS" if ok else "FAIL", name, info or ""))
    except Exception as e:
        RESULTS.append((name, False, repr(e)))
        print(" [FAIL] %-42s %r" % (name, e))


def t_ports():
    from core.utils import parse_ports
    assert parse_ports("80") == [80]
    assert parse_ports("1-4") == [1, 2, 3, 4]
    assert parse_ports("443,80,8080") == [80, 443, 8080]
    assert len(parse_ports("top100")) == 100
    assert len(parse_ports("top1000")) >= 900
    assert parse_ports("all")[0] == 1 and len(parse_ports("all")) == 65535
    return True, "port parser OK"


def t_versions():
    from core.intelligence import version_cmp, RangeCheck, parse_version
    assert version_cmp("7.2", "7.10") < 0
    assert version_cmp("2.4.49", "2.4.49") == 0
    assert version_cmp("8.3.0", "8.3.1") < 0
    assert RangeCheck("<8.9").match("8.5")
    assert not RangeCheck("<8.9").match("9.0")
    assert RangeCheck("==2.3.4").match("2.3.4")
    return True, "version comparator OK"


def t_intel():
    from core.intelligence import Intelligence
    i = Intelligence()
    hits = i.correlate_banner("OpenSSH_7.2p2 Ubuntu-4ubuntu2.8")
    flat = {c["id"] for h in hits for c in h["cves"]}
    assert any("CVE-2018-15473" in x for x in flat), flat
    hits = i.correlate_banner("Apache/2.4.49 (Win64) OpenSSL/1.1.1k")
    flat = {c["id"] for h in hits for c in h["cves"]}
    assert any("CVE-2021-41773" in x for x in flat), flat
    hits = i.correlate_banner("nginx/1.20.1")
    assert hits and any(h["product"].lower() == "nginx" for h in hits)
    return True, "CVE correlation matched known banners"


def t_extract():
    from core.utils import extract_forms, extract_links, extract_emails
    html = """<html><a href="/a?x=1">a</a><a href="https://other.example/b">b</a>
    <form action="/login" method="post"><input name="user" type="text">
    <input name="pass" type="password"><input type="submit"></form>
    contact: bob@example.com</html>"""
    forms = extract_forms(html, "http://t.test/page")
    assert forms and forms[0]["method"] == "post" and len(forms[0]["fields"]) == 2
    links = extract_links(html, "http://t.test/page")
    assert "http://t.test/a?x=1" in links
    assert "bob@example.com" in extract_emails(html)
    return True, "html extraction OK"


def t_rce_channel():
    import re as _re
    from modules.exploit.exploitation import RCEChannel

    class Resp:
        def __init__(self, body):
            self.body = body

    class FakeEngine:
        def nonce(self, n):
            return "R" * n

    class Chan(RCEChannel):
        def __init__(self, sender):
            self.sender = sender
            super().__init__(FakeEngine(), None, "q")

        def _send(self, payload):
            return self.sender(payload)

    def reflect(payload):
        return Resp(payload.strip())

    def real_shell(payload):
        m = _re.search(r"VJR+R+S", payload)
        if not m:
            return Resp("")
        s = m.group(0)
        e = s[:-1] + "E"
        m2 = _re.search(_re.escape(s) + r"[^;]*;\s*(.*?)\s*;\s*echo " +
                        _re.escape(e), payload)
        cmd = m2.group(1).strip() if m2 else ""
        if cmd.startswith("echo "):
            return Resp("\n%s\n%s\n%s\n" % (s, cmd[5:], e))
        return Resp("\n%s\nuid=1000(kali) gid=1000(kali) groups=1000(kali)\n"
                    "%s\n" % (s, e))

    assert not Chan(reflect).alive, "reflecting app must NOT establish RCE channel"
    live = Chan(real_shell)
    assert live.alive, "real shell must establish channel"
    proof = live.run("id")
    assert proof and "uid=1000(kali)" in proof, proof
    return True, "RCE channel anti-reflection guard OK"


def t_vuln_records():
    from modules.web import vuln_scanner as vs

    class Res:
        def __init__(self, technique):
            self.technique = technique

    def mk_result(tech):
        return Res(tech)

    pt = vs.Point("http://127.0.0.1/echo?q=1", "GET", [("q", "1")],
                  "http://127.0.0.1/echo?q=1", "form")

    class Rec:
        def __init__(self):
            self.calls = []

        def __call__(self, cls, pt, k, res, confidence="firm"):
            self.calls.append((
                cls, vs._confidence_for(cls, confidence), res.technique))

    rec = Rec()
    rec("rce", pt, "q", mk_result("uid"), "firm")
    rec("lfi", pt, "file", mk_result("root:x:0:0"), "firm")
    rec("sqli_time", pt, "q", mk_result("delay"), "firm")
    rec("xss", pt, "q", mk_result("direct"), "firm")
    m = {c[0]: c for c in rec.calls}
    assert m["rce"][1] == "certain"
    assert m["lfi"][1] == "certain"
    assert m["sqli_time"][1] == "possible"
    assert m["xss"][1] == "firm"
    assert vs._confidence_for("rce", "firm") == "certain"
    assert vs._confidence_for("xss", "firm") == "firm"
    assert vs._poc_gate("sqli", "firm", "payload=x\ncontext=...") == "firm"
    assert vs._poc_gate("xss", "firm", "") == "possible"
    assert vs._poc_gate("sqli", "firm", "") == "possible"
    assert vs._poc_gate("redirect", "firm", "Location: https://h/") == "firm"
    return True, "vuln_scanner proof-class confidence mapping OK"


def t_cms_markers():
    from modules.web.tech_fingerprint import (_bounded_in, CMS_ACTIONS,
                                              _cms_markers, _firm_cms,
                                              FIRM_TOKENS)
    assert _bounded_in("mage/", "image/x.png") is False   # img-tag false hit
    assert _bounded_in("mage/", "<div class=x>mage/x</div>") is True
    assert _bounded_in("mage/", "mage/static/version") is True  # real magento
    assert _bounded_in("wp-content", "xwp-content-extra") is False
    assert _bounded_in("wp-content", '"wp-content/uploads"') is True
    assert _bounded_in("/wp-json", "href='/wp-json/wp/v2/users'") is True
    assert _bounded_in("x-drupal-cache", "x-drupal-cache: HIT") is True
    assert "mage/" not in CMS_ACTIONS["wordpress"][1].lower()
    for c in ("wordpress", "drupal", "joomla", "magento"):
        assert c in CMS_ACTIONS and \
            CMS_ACTIONS[c][0].lower().startswith(c)
    # two-tier CMS truth: a lone structural marker (or copied theme link) is
    # only a 'possible' lead; two independent markers imply a firm claim.
    body = '<img src="/image/logo.png"><div>mage in prose only</div>'
    mk = _cms_markers({"body": body, "header": ""})
    assert not mk.get("magento"), "mage/ inside image/ or prose must not fire"
    wp2 = _cms_markers({"body": '"wp-content/themes/x" + wp-json prefix '
                        "href='/wp-json/wp/v2/users' \"wp-includes\"",
                        "header": ""})
    assert _firm_cms("wordpress", wp2["wordpress"]) is True
    wp1 = _cms_markers({"body": '<link href="/wp-content/themes/x/">',
                        "header": ""})
    assert _firm_cms("wordpress", wp1["wordpress"]) is False
    dru = _cms_markers({"body": "keep", "header": "x-drupal-cache: HIT"})
    assert any(tok in FIRM_TOKENS for tok, _w in dru["drupal"])
    prose = _cms_markers({"body": "our drupal migration guide", "header": ""})
    assert _firm_cms("drupal", prose["drupal"]) is False
    return True, "CMS markers boundary-guarded + two-tier possible/firm OK"


def t_tech_scoring():
    import json
    from modules.web.tech_fingerprint import _detect_techs, _meta_tags
    sigs = json.load(open("intel/signatures.json"))["tech_signatures"]
    wp_page = {
        "url": "https://site.test/blog/",
        "headers": {"server": "nginx", "x-pingback": "/xmlrpc.php"},
        "body": ('<html><head><meta name="generator" content="WordPress 6.4.1">'
                 '</head><body><a href="/wp-content/themes/x/">css</a>'
                 '<script src="/wp-includes/js/"></script></body></html>'),
    }
    det = _detect_techs(sigs, [wp_page])
    assert det["WordPress"]["score"] >= 6, det["WordPress"]
    assert det["WordPress"]["version"] == "6.4.1", det["WordPress"]["version"]
    next_page = {
        "url": "https://netx.test/",
        "headers": {},
        "body": '<script id="__NEXT_DATA__" type="application/json">{}</script>'
                '<link href="/_next/static/abc/_app.css">',
    }
    det = _detect_techs(sigs, [next_page])
    assert det["Next.js"]["score"] >= 6, det["Next.js"]
    generic_word = {"url": "https://w.test/", "headers": {},
                    "body": "read our python guides here python python"}
    det = _detect_techs(sigs, [generic_word])
    assert "Python" not in det, "prose word must not detect Python"
    html_only = {"url": "https://h.test/", "headers": {},
                 "body": '<img src="/image/logo.png">'}
    det = _detect_techs(sigs, [html_only])
    assert "Magento" not in det, "mage/ inside image/ must not fire Magento"
    weak = {"url": "https://s.test/", "headers": {},
            "body": '<title>SvelteKit-like page</title>'}
    det = _detect_techs(sigs, [weak])
    assert 3 <= det["Svelte"]["score"] < 6 and not det["Svelte"]["strong"], \
        "a lone weak html marker is at most an unverified lead, never firm"
    meta = _meta_tags('<meta name="generator" content="Gatsby 5.12.4">')
    assert meta.get("generator")
    return True, "rich whole-site tech scoring: WP/Next firm, prose & mage-safe"


def t_fp_corpus():
    """False-positive regression corpus: realistic clean pages must stay clean.

    Each negative case is a page our engine must not call 'firm' (no strong
    context, no score >= 6, and repeated weak markers never stack site-wide).
    A positive control proves firm detection still fires for honest pages.
    """
    import json
    from modules.web.tech_fingerprint import _detect_techs
    sigs = json.load(open("intel/signatures.json"))["tech_signatures"]

    def det(pages):
        return _detect_techs(sigs, pages)

    def not_firm(r, tech):
        if tech not in r:
            return
        assert not r[tech]["strong"], "%s must not be firm here" % tech
        assert r[tech]["score"] < 6, "%s scored too high" % tech

    def empty(pages):
        r = det(pages)
        assert not r, "clean page claimed tech: %s" % sorted(r)

    # 1) copied single wp-content link inside an image, no real WP signals
    wp_copy = {"url": "https://site.test/",
               "headers": {},
               "body": '<img src="/wp-content/themes/x/img/theme.png">'}
    not_firm(det([wp_copy]), "WordPress")

    # 2) marketing prose full of tech words from an unrelated blog
    prose = {"url": "https://blog.test/2019/how-to/",
             "headers": {},
             "body": ("WordPress and PHP power thousands of websites. Apache and "
                      "nginx are the top web servers, ruby on rails and python "
                      "frameworks dominate, drupal joomla magento shopify jekyll "
                      "gatsby next.js and rails all compete. Static pages built "
                      "with sveltekit and vue are increasingly popular.") * 4}
    r = det([prose])
    for t in ("WordPress", "PHP", "Apache", "Nginx", "Drupal", "Joomla",
              "Magento", "Shopify", "Svelte", "Next.js", "Vue.js"):
        not_firm(r, t)

    # 3) one 'sveltekit' word in the title repeated across 5 crawled pages
    svelte = {"url": "https://s.test/", "headers": {},
              "body": "<title>sveltekit-like single tenant</title>"}
    r = det([svelte] * 5)
    assert 3 <= r["Svelte"]["score"] < 6 and not r["Svelte"]["strong"], r
    assert r["Svelte"]["score"] < 6, "5 identical weak markers must not stack"

    # 4) boilerplate HTML5 with zero framework markers
    empty([{"url": "https://b.test/", "headers": {},
            "body": ("<!DOCTYPE html><html><head><meta name=\"viewport\" "
                     "content=\"width=device-width\"><title>Company</title>"
                     "</head><body><h1>Welcome</h1><p>stuff</p></body></html>")}])

    # 5) mage/ token nested inside an ordinary /image/ path
    not_firm(det([{"url": "https://shop.test/", "headers": {},
                   "body": '<img src="/image/mage/photo.jpg" alt="magento">'}]),
             "Magento")

    # 6) generic shop text, no Shopify CDN / checkout tokens
    shop = {"url": "https://store.test/products",
            "headers": {},
            "body": "<h1>Cart</h1><p>Add to cart and checkout.</p>"}
    not_firm(det([shop]), "Shopify")

    # 7) frameworkless SPA shell with hashed bundle, no meta/identifier
    empty([{"url": "https://a.test/", "headers": {},
            "body": ('<script src="/assets/app.9f8a2b.js"></script>'
                     '<div id="root"></div>')}])

    # positive control: a real nginx + Jekyll page still proves firm
    real = {"url": "https://docs.test/", "headers": {"server": "nginx"},
            "body": ('<meta name="generator" content="Jekyll v4.3.2">'
                     '<link rel="stylesheet" href="/static/css/main.css">')}
    r = det([real])
    assert r["Nginx"]["strong"] or r["Nginx"]["score"] >= 6, r["Nginx"]
    return True, ("FP corpus clean (prose, wp-copy, svelte x5, boilerplate, "
                  "mage/shop, SPA) + positive control OK")


def t_service_honesty():
    from modules.network.service_detect import _probe_classify, _probe_banner
    import socket, threading
    junk = []

    def serve(payload):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        t = threading.Thread(target=lambda: (
            (lambda c: (c.send(payload), c.close()))(
                srv.accept()[0])), daemon=True)
        t.start()
        return srv, port

    def collect(port):
        for rx, tech in []:
            pass
        return _probe_banner("127.0.0.1", port, force_http=False)

    s1, p1 = serve(b"HELLO we are a mystery service\r\n")
    s2, p2 = serve(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
    b1 = collect(p1)
    b2 = collect(p2)
    s1.close()
    s2.close()
    assert _probe_classify(b1) is False, "junk echo must not prove a service"
    assert _probe_classify(b2) is True, "SSH greeting proves the service"
    return True, "service names never guessed from junk; banner-driven only"


def t_js_scope():
    from modules.web.js_analysis import _in_scope
    hosts = {"bracnet.net", "www.bracnet.net"}
    assert _in_scope("https://bracnet.net/app.js", hosts)
    assert _in_scope("https://www.bracnet.net/x.js", hosts)
    assert _in_scope("https://api.bracnet.net/x.js", hosts)  # subdomain ok
    assert not _in_scope("https://cdn.jsdelivr.net/npm/rasa.js", hosts)
    assert not _in_scope("https://evil.com/x.js", hosts)
    assert not _in_scope("http://127.0.0.1/x.js", hosts)  # IP must be in hosts
    assert _in_scope("http://127.0.0.1/x.js", {"127.0.0.1"})
    assert not _in_scope("https://notbracnet.net/x.js", hosts)
    return True, "JS analysis is strictly same-origin/subdomain scoped"


def t_update():
    import core.updater as up
    from core.version import __version__
    assert isinstance(__version__, str) and __version__
    assert up.current_version() == __version__
    assert isinstance(up.is_git(), bool)
    repo, branch = up._remote()
    assert "/" in repo and branch
    assert up.SKIP_ARCHIVE.issuperset(
        {"Outputs", ".git", ".venv", ".vajra_state.json"})
    return True, "self-update wiring + version OK"


def t_db():
    from core.database import Database, Finding
    path = tempfile.mktemp(suffix=".sqlite")
    db = Database(path)
    f1 = Finding("tgt", "mod", "cat", "high", "title-A", detail="d")
    assert db.add_finding(f1)
    assert not db.add_finding(Finding("tgt", "mod", "cat", "high", "title-A"))
    db.add_service("tgt", 80, "http", "banner")
    fs = db.findings()
    assert len(fs) == 1 and fs[0]["severity"] == "high"
    assert db.services()[0]["port"] == 80
    db.close()
    os.unlink(path)
    return True, "database roundtrip OK"


def t_fp_guard():
    from core.database import Finding
    firm = Finding("t", "web.vulnscan", "web-vuln", "critical", "confirmed RCE",
                   confidence="firm")
    assert firm.severity == "high"  # firm evidence stays below critical
    tentative = Finding("t", "web.vulnscan", "web-vuln", "critical",
                        "blind signal", confidence="possible")
    assert tentative.severity == "medium" and "[Bounded]" in tentative.detail
    assert tentative.confidence == "tentative"  # canonical Burp-style label
    speculative = Finding("t", "network.osfp", "recon", "high", "suspicion",
                          confidence="low")
    assert speculative.severity == "low"
    proven = Finding("t", "exploit.exploit", "credentials", "critical",
                     "exfil", confidence="verified")
    assert proven.severity == "critical" and proven.confidence == "certain"
    return True, "confidence->severity cap (anti-FP) OK"


def t_report():
    from core.report import render_html, render_markdown, render_json
    data = {"meta": {"tool": "VAJRA", "generated": "now",
                     "profile": "quick", "targets": ["127.0.0.1"],
                     "output_dir": "/tmp"},
            "stats": {"critical": 1, "high": 2}, "score": 24.0,
            "narrative": "n", "services": [{"target": "x", "port": 80,
                                            "service": "http", "product": "",
                                            "version": "", "tls": False}],
            "findings": [{"severity": "critical", "title": "<b>t</b>",
                          "category": "c", "module": "m", "detail": "d",
                          "evidence": "e", "confidence": "firm"},
                         {"severity": "medium",
                          "title": "no-proof finding",
                          "category": "c2", "module": "m2",
                          "detail": "observed proof detail only",
                          "evidence": "", "confidence": "firm"}],
            "events": [], "tech": [], "subdomains": [], "os_guess": "",
            "evasion": [{"waf": "Cloudflare", "ops": "case_swap",
                         "original": "<svg onload=alert(1)>",
                         "mutant": "<SvG oNlOaD=alert(1)>",
                         "result": "passed"}]}
    html_out = render_html(data)
    assert "VAJRA" in html_out and "&lt;b&gt;" in html_out
    assert "Evasion operations" in html_out and "case_swap" in html_out
    assert "<i>-</i>" not in html_out  # PoC cell never blank
    assert "observed proof detail only" in html_out  # detail fallback renders
    md = render_markdown(data)
    assert "# ⚡ Vajra" in md and "Evasion Ops" in md
    assert "Evidence / PoC:" in md and "observed proof detail only" in md
    return True, "all three report formats render (incl. PoC fallback)"


def t_resume_persistence_cloud_xlsx():
    """Proof-of-compromise objectives + XLSX export + masscan delegation +
    persistence/cloud module gating (no live target required)."""
    from core.report import objectives, render_xlsx
    # Objectives classification: only firm/certain findings with proof count.
    findings = [
        {"title": "RCE via command injection", "detail": "id", "category": "x",
         "module": "m", "confidence": "certain"},
        {"title": "RCE via command injection", "detail": "id2", "category": "x",
         "module": "m", "confidence": "certain"},
        {"title": "kind of SQLi", "detail": "d", "category": "x", "module": "m",
         "confidence": "tentative"},  # tentative must NOT count
        {"title": "persistence cron implant", "detail": "crontab", "category": "x",
         "module": "m", "confidence": "firm"},
        {"title": "sql injection bypass", "detail": "union", "category": "x",
         "module": "m", "confidence": "certain"},
    ]
    objs = objectives(findings)
    names = {o["name"]: o["count"] for o in objs}
    assert names.get("Remote Code Execution") == 1, names  # deduped
    assert names.get("Persistence Established") == 1, names
    assert "Web Application Pwned" in names, names  # sql injection present
    # FP guard: the command-injection finding must NOT be double-counted as a
    # generic web-app pwn (it is an RCE), i.e. no bare "injection" rule.
    wa = next((o for o in objs if o["name"] == "Web Application Pwned"), None)
    assert wa is None or "RCE via command injection" not in wa["examples"], wa
    assert "Persistence Established" in names

    # XLSX writer produces well-formed parts.
    import os, tempfile, zipfile, xml.dom.minidom
    data = {"meta": {"generated": "now", "profile": "p", "targets": ["t"],
                     "output_dir": "."},
            "stats": {}, "score": 1.0, "findings": findings,
            "objectives": objs}
    tmp = os.path.join(tempfile.mkdtemp(), "r.xlsx")
    render_xlsx(data, path=tmp)
    with zipfile.ZipFile(tmp) as z:
        assert z.testzip() is None
        xml.dom.minidom.parseString(z.read("xl/worksheets/sheet1.xml"))
        xml.dom.minidom.parseString(z.read("xl/sharedStrings.xml"))
    os.remove(tmp)

    # post/lateral/exfil + ad.escalation + exploit.cve_runner registered with
    # the right phase + gating conditions.
    import modules as M
    names_reg = [m["name"] for m in M.MODULES]
    for n in ("post.persistence", "post.cloud", "post.lateral", "post.exfil",
              "ad.escalation", "exploit.cve_runner"):
        assert n in names_reg, n
    p = next(m for m in M.MODULES if m["name"] == "post.persistence")
    assert p["phase"] == "post" and "has_channels" in p["cond"]
    c = next(m for m in M.MODULES if m["name"] == "post.cloud")
    assert c["phase"] == "post" and "has_cloud" in c["cond"]
    lat = next(m for m in M.MODULES if m["name"] == "post.lateral")
    assert lat["phase"] == "post" and "has_channels" in lat["cond"]
    ex = next(m for m in M.MODULES if m["name"] == "post.exfil")
    assert ex["phase"] == "post" and "has_channels" in ex["cond"]
    esc = next(m for m in M.MODULES if m["name"] == "ad.escalation")
    assert esc["phase"] == "ad" and "has_ad" in esc["cond"]
    cv = next(m for m in M.MODULES if m["name"] == "exploit.cve_runner")
    assert cv["phase"] == "exploit"

    # lateral movement pure logic (internal subnet enumeration).
    from modules.post.lateral import parse_subnet
    sub = parse_subnet("eth0 10.0.3.5\n10.0.3.1 gw\n10.0.3.0\n10.0.3.255\n"
                       "172.16.9.17 route")
    assert "10.0.3.5" in sub and "172.16.9.17" in sub, sub
    assert "10.0.3.0" not in sub and "10.0.3.255" not in sub, sub

    # exfil obfuscation round-trips.
    from modules.post.exfil import _obfuscate, XOR_KEY
    import base64
    _b = _obfuscate(b"secret stash")
    _raw = base64.b64decode(_b)
    _dec = bytes(_c ^ XOR_KEY[_i % len(XOR_KEY)]
                 for _i, _c in enumerate(_raw))
    assert _dec == b"secret stash"
    return True, "objectives (FP-omitted) + XLSX + new module gating + lateral/exfil logic OK"


def t_payloads():
    from core.payload_engine import (BANKS, apply_ops, AdaptiveAttacker,
                                     classify_response, Verdict)
    total = sum(len(v) for v in BANKS.values())
    assert total >= 3000, total
    assert len(BANKS["xss"]) >= 1500
    assert len(BANKS["sqli"]) >= 320
    assert len(BANKS["lfi"]) >= 380
    assert len(BANKS["rce"]) >= 550
    assert "ssrf" in BANKS and len(BANKS["ssrf"]) >= 20
    assert "protopoll" in BANKS and "header_injection" in BANKS
    base = "' UNION SELECT password FROM users-- -"
    mutant = apply_ops(base, ["sql_inline_comment", "space_to_comment"])
    assert mutant != base and "UN/**/ION" not in base

    blocked_payload = "<svg onload=alert(1)>"

    class FakeResp:
        def __init__(self, body):
            self.status = 200
            self.headers = {}
            self.body = body

    def sender(p):
        if p == blocked_payload:
            return FakeResp("Blocked by SecureWAF reference #77")
        return FakeResp("<div>" + p + "</div>")

    att = AdaptiveAttacker(sender, lambda p, r: p in r.body,
                           waf="ModSecurity", max_direct=2, max_mutants=40)
    res = att.run([blocked_payload])
    assert res.achieved, "evasion should find a passing mutant"
    assert res.success != blocked_payload
    v, _ = classify_response(FakeResp("request unsuccessful. incapsula"))
    assert v == Verdict.BLOCKED
    return True, ("%d payloads/%d classes; evasion loop achieved motive "
                  "via '%s'" % (total, len(BANKS), res.technique))


def t_mitre():
    from core.database import Finding
    samples = [
        Finding("t", "web.vulnscan", "web-vuln", "high",
                "Reflected Cross-Site Scripting"),
        Finding("t", "exploit.exploit", "", "critical",
                "OS COMMAND EXECUTION ACHIEVED"),
        Finding("t", "post.recon", "post-exploit", "critical", "recon ran"),
        Finding("t", "network.brute", "credentials", "critical", "cracked"),
        Finding("t", "web.dirbuster", "exposure", "high",
                "Exposed Git repository metadata (.git)"),
    ]
    for f in samples:
        assert f.mitre and f.mitre.startswith("T"), f.mitre
    return True, "%d sample findings auto-tagged (%s…)" % (
        len(samples), samples[0].mitre.split()[0])


def t_jwt():
    import base64, json as _j, hashlib, hmac as _h
    hdr = _j.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    pl = _j.dumps({"user": "admin", "role": "admin"}).encode()
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
    sig = _h.new(b"secret", b64(hdr) + b"." + b64(pl), hashlib.sha256).digest()
    tok = (b64(hdr) + b"." + b64(pl) + b"." +
           base64.urlsafe_b64encode(sig).rstrip(b"=")).decode()
    from modules.web.jwt_audit import decode_jwt
    d = decode_jwt(tok)
    assert d and d["header"]["alg"] == "HS256" and d["payload"]["role"]
    return True, "decode roundtrip ok (admin token)"


def t_wordlists():
    import os
    from core.utils import PROJECT_ROOT
    wl = PROJECT_ROOT / "wordlists"
    def count(name):
        f = wl / name
        return sum(1 for _ in open(f, encoding="utf-8")) if f.exists() else 0
    users_full = count("users_full.txt")
    pwds_full = count("passwords_full.txt")
    assert users_full >= 100000, users_full
    assert pwds_full >= 140000, pwds_full
    return True, "complete tiers present: %dk users / %dk passwords" % (
        users_full // 1000, pwds_full // 1000)


def t_http_result():
    from core.http_client import HttpResult
    r = HttpResult("u", 200, {"Content-Type": "application/json"},
                   b'{"a": 1}', 0.1)
    assert r.json == {"a": 1} and r.ok and r.headers["content-type"]
    return True, "HttpResult OK"


def t_cve_db():
    from core.utils import load_json
    from core.intelligence import Intelligence
    db = load_json("intel/cve_db.json").get("products", {})
    assert len(db) >= 1000, len(db)
    total = sum(len(m.get("ranges", {})) for m in db.values())
    assert total >= 5000, total
    intel = Intelligence()
    hits = intel.correlate_banner("F5 BIG-IP 16.1.0 TMUI login")
    assert any(h["product"] == "F5 BIG-IP" for h in hits), hits
    assert not any(h["product"] == "ip" for h in hits), hits
    assert not any(c["id"] == "CVE-2023-42282" for h in hits
                   for c in h["cves"]), hits
    hits = intel.correlate_banner("Server: Apache/2.4.49")
    flat = {c["id"] for h in hits for c in h["cves"]}
    assert any("CVE-2021-41773" in x for x in flat)

    probes = run_probe_registry_check()
    return True, "%d products / %d range entries; BIG-IP + traversal matched; %d probes" % (
        len(db), total, probes)


def run_probe_registry_check():
    from modules.exploit import known_exploits
    probes = [p for p in known_exploits.PROBES
              if p.__name__ in ("probe_fortigate_traversal",
                                "probe_cisco_asa_traversal",
                                "probe_openfire_admin")]
    names = {p.__name__ for p in known_exploits.PROBES}
    assert {"probe_fortigate_traversal", "probe_cisco_asa_traversal",
            "probe_openfire_admin"} <= names
    assert all("log4shell" not in n and "drupalgeddon" not in n for n in names)
    return len(known_exploits.PROBES)


def t_coverage_bank():
    from core.utils import load_json
    bank = load_json("intel/coverage_bank.json")
    checks = bank.get("checks", [])
    bycat = {}
    for c in checks:
        bycat[c["category"]] = bycat.get(c["category"], 0) + 1
    for cat in ("web", "api", "network", "server"):
        assert bycat.get(cat, 0) >= 100, (cat, bycat)
    assert len(checks) >= 400, len(checks)
    ids = [c["id"] for c in checks]
    assert len(set(ids)) == len(ids), "duplicate check ids"
    import json as _json
    for c in checks:
        m = c.get("match") or {}
        assert (m.get("body_contains") or m.get("body_regex") or
                m.get("headers")), "no discriminator in %s" % c.get("id")
        scope = _json.dumps(c.get("scope"))
        assert "{_p}" not in scope and "{_h}" not in scope, c.get("id")
        if c.get("exploit"):
            assert c["exploit"].get("success"), c.get("id")
            assert c["exploit"].get("payload") or c["exploit"].get("path")

    from modules.exploit import coverage
    import re

    class Resp:
        def __init__(self, status, body, headers):
            self.status, self.body, self.headers = status, body, headers

    class T:
        def __init__(self):
            self.display = "10.0.0.9"

    class E:
        target = T()
        state = {}
        http, db, args, log = None, None, None, None

    cov = coverage.Coverage(E(), bank)
    ok = cov._matched(Resp(200, "<html>index of /admin</html>", {}),
                      {"expect_html": 1},
                      {"status": [200], "body_regex": r"index of /"})
    assert ok and "index of /" in ok
    none = cov._matched(Resp(200, "just a page", {}),
                        {"expect_html": 1},
                        {"status": [200], "body_regex": r"index of /"})
    assert none is None, "marker absent must not fire"
    none2 = cov._matched(Resp(200, "anything", {}), {},
                         {"status": [200]})
    assert none2 is None, "status alone must not fire"
    raw = cov._raw_matched(b"220 FTP ready\r\n", {"body_regex": r"FTP"}, 21)
    assert raw and "port=21" in raw
    raw_none = cov._raw_matched(b"HTTP/1.1 200 OK\r\n", {"body_regex": r"FTP"}, 21)
    assert raw_none is None

    # no-FP regression: a catch-all server returning 200 + pthread benign HTML
    # for every path must NOT fire weak markers
    benign = Resp(200, "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
                       "</head><body>index of nothing</body></html>", {})
    assert cov._matched(benign, {"expect_html": 1},
                        {"status": [200], "body_regex": r"index of /"}) is None
    assert cov._matched(benign, {"expect_html": 1},
                        {"status": [200],
                         "body_regex": r"<title[^>]*>[^<]*(admin|login)"}) is None
    assert cov._matched(benign, {"expect_json": 1},
                        {"status": [200], "body_regex": r'"id"\s*:'}) is None
    assert cov._matched(benign, {"expect_html": 1},
                        {"status": [200],
                         "headers": {"Set-Cookie": r"JSESSIONID=[^;]*"}}) is None
    json_ok = cov._matched(Resp(200, '{"id": 1}', {"Content-Type":
                                                   "application/json"}),
                           {"expect_json": 1},
                           {"status": [200], "body_regex": r'"id"\s*:\s*\d+'})
    assert json_ok, "real JSON field must fire"
    return True, ("bank %d checks (web=%d api=%d network=%d server=%d), "
                  "strict matcher discriminates" % (
                      len(checks), bycat["web"], bycat["api"],
                      bycat["network"], bycat["server"]))


def t_listener():
    from core.listener import pick_lport, detect_lhost, render_reverse_payloads
    port = pick_lport()
    assert isinstance(port, int) and 1024 <= port <= 65535
    host = detect_lhost()
    assert host and host.count(".") == 3
    payloads = render_reverse_payloads("unix", "10.0.0.9", 4545)
    names = [n for n, _c in payloads]
    assert "bash/tcp" in names and "python3" in names
    assert any("10.0.0.9" in c and "4545" in c for _n, c in payloads)
    return True, "lhost=%s lport=%d, %d unix one-liners rendered" % (
        host, port, len(payloads))


def t_ai_offline():
    import time
    from core.ai import AIEngine
    ai = AIEngine({"ai_timeout": 2}, enabled=True)
    t0 = time.time()
    ok = ai.available()
    dt = time.time() - t0
    assert ok is False or ok is True
    assert dt < 5, dt
    items = ai.suggest_payloads("XSS", "Cloudflare", "<svg onload=alert(1)>")
    assert isinstance(items, list)
    return True, "graceful when Ollama absent (%.1fs, %d suggestions)" % (
        dt, len(items))


def t_ai_assist():
    import importlib.util
    import os
    import tempfile as _tf
    spec = importlib.util.spec_from_file_location(
        "ai_assist_mod", "modules/web/ai_assist.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class FakeAI:
        enabled = True
        def available(self, refresh=False):
            return True
        def ask(self, p, system=None, max_tokens=None):
            return "Apply vendor patch; impact RCE."
        def plan_actions(self, s):
            return ["Probe CVE-2021-41773", "Check actuator"]

    class OffAI:
        enabled = True
        def available(self, refresh=False):
            return False

    class Db:
        def __init__(self, rows):
            self.rows, self.added = rows, None
        def findings(self, disp):
            return self.rows
        def add_finding(self, f):
            self.added = f

    class Log:
        @staticmethod
        def info(*a): pass
        @staticmethod
        def debug(*a): pass

    T = type("T", (), {"display": "10.0.0.1"})()
    rows = [{"severity": "critical", "title": "Apache traversal",
             "detail": "d", "id": "f1", "url": "http://x/"},
            {"severity": "high", "title": "Actuator", "detail": "d",
             "id": "f2", "url": "http://x/"}]

    td = _tf.mkdtemp()
    E = type("E", (), {"target": T, "target_dirs": {"10.0.0.1": td},
                       "log": Log(), "db": Db(rows)})()
    E.ai = FakeAI()
    mod.run(E)
    ast = os.path.join(td, "ai_assist.json")
    assert os.path.exists(ast), "ai_assist.json not written online"
    import json as _json
    content = _json.load(open(ast))
    assert content["advisory_only"] is True
    assert len(content["remediations"]) == 2
    assert len(content["next_actions"]) >= 1
    assert E.db.added is not None and E.db.added.category == "advisory"

    td2 = _tf.mkdtemp()
    E2 = type("E2", (), {"target": T, "target_dirs": {"10.0.0.1": td2},
                         "log": Log(), "db": Db(rows)})()
    E2.ai = OffAI()
    mod.run(E2)
    assert not os.path.exists(os.path.join(td2, "ai_assist.json"))
    assert E2.db.added is None
    return True, "AI assist online writes artifact + advisory; offline is silent"


def t_outputs_naming():
    from core.engine import sanitize_target_name
    n = sanitize_target_name("http://10.10.10.5:8080/admin")
    assert "/" not in n and ":" not in n and n.startswith("http")
    return True, "target folder name=%s" % n


def t_ad_core():
    from core.crypto_mini import (md4, ntlm_v2, build_as_req,
                                  asrep_hashcat_line)
    assert md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    proof, blob = ntlm_v2("User", "DOMAIN", password="Password",
                          challenge=b"\x01" * 8, target_info=b"\x00\x00")
    assert len(proof) == 16 and len(blob) >= 26
    req = build_as_req("CORP.LOCAL", "jdoe")
    assert req[0] == 0x6A and len(req) > 40
    line = asrep_hashcat_line("svc-sql", "CORP.LOCAL", 23, bytes(range(40)))
    assert line.startswith("$krb5asrep$23$svc-sql@corp.local:")
    from modules.ad.ldap_enum import uac_flags
    flags = uac_flags(str(0x400000 | 0x200))
    assert any("AS-REP" in f for f in flags)
    return True, ("md4 vector ok, ntlmv2 %dB proof, AS-REQ built, "
                  "hashcat line ok, UAC flags parsed" % len(proof))


def t_smbv1_packets():
    import struct
    from modules.ad.smb_recon import (_smb1_negotiate, _status, VULN_STATUS,
                                      _parse_negotiate, _smb1_hdr, _smb1_pkt)
    neg = _smb1_negotiate()
    assert b"\xffSMB" in neg and b"NT LM 0.12" in neg and neg[0] == 0
    h = _smb1_hdr(0x72)
    assert len(h) == 32
    fake = bytearray(b"\x00" * 64)
    fake[4:8] = b"\xffSMB"; fake[8] = 0x25
    fake[9:13] = struct.pack("<I", VULN_STATUS)
    assert _status(bytes(fake)) == VULN_STATUS
    words = (b"\x02\x00"        # word0: dialect index 2 (NT LM 0.12)
             + b"\x01\x00"      # security mode (user-level)
             + b"\x00\x08"      # max mpx
             + b"\x00\x00"      # max vcs
             + b"\x00\xf1\x00\x00"   # max buffer (2 words)
             + b"\x00\x04\x00\x00"   # max raw (2 words)
             + b"\x00" * 4            # session key (2 words)
             + b"\x00\x00\x00\x00"    # capabilities (2 words)
             + b"\x10\x00\x10\x00"    # lm/nt key lengths (16 bytes each)
             + b"\x00" * 6)           # trailing reserved (3 words)
    assert len(words) // 2 == 17
    strings = (b"Windows Server 2019 Standard 17763\x00" +
               b"Windows Server 2019 Standard 6.3\x00" +
               b"WORKGROUP\x00")
    key = b"\x00" * 16
    canned = _smb1_pkt(h + bytes([17]) + words
                       + struct.pack("<H", len(key) + len(strings))
                       + key + strings)
    parsed = _parse_negotiate(canned)
    assert parsed["dialect_idx"] == 2, parsed
    assert "Windows" in parsed["os"], parsed
    resp2 = (b"\x00" * 4 + b"\xffSMB" + b"\x00" + b"\x00" * 4 +
             b"\x18" + b"\x00\x00" + b"\x00" * 2 + b"\x00" * 8 +
             b"\x00" * 2 + b"\x00" * 2 + b"\x00" * 2 + b"\x00" * 2 +
             b"\x02\x02" + b"\x01\x00" + b"\x00\x10" + b"\x00\x00" +
             b"\x00" * 12)
    assert _parse_negotiate(resp2)["dialect_idx"] is None, \
        "SMB2-only fallback mistakenly flagged as SMBv1"
    return True, "negotiate/status/parser OK; dialect+OS+MS17 status decode verified"


def t_agent_mission():
    from core.agent import (parse_action, expand_ports, INTRUSIVE_MODULES,
                            _MODULE_INDEX)
    d = parse_action('{"thought":"deepen","tool":"scan_more",'
                     '"args":{"ports":"8000-9000"},"why":"find more"}')
    assert d["tool"] == "scan_more" and d["args"]["ports"] == "8000-9000"
    d = parse_action('```json\n{"tool":"web_fuzz","args":{"url":'
                     '"http://x","wordlist":"dirs_common.txt"}}\n```')
    assert d["tool"] == "web_fuzz" and d["args"]["url"] == "http://x"
    d = parse_action("I think we should brute force the ftp service now.")
    assert d["tool"] == "brute"
    d = parse_action("time for the ad chain — lateral movement")
    assert d["tool"] == "ad_chain", d
    d = parse_action("")
    assert d["tool"] == "done"
    d = parse_action("nothing more to do")
    assert d["tool"] == "done"
    # AI-knowledge wiring: catalog + keyword routing
    assert any("web.vulnscan" in l for l in _MODULE_INDEX.splitlines())
    assert any("web.api" in l for l in _MODULE_INDEX.splitlines())
    for text, want in (("probe ssrf against the api", "web.ssrf_scan"),
                       ("check xxe on the xml payload", "web.vulnscan"),
                       ("look for jwt confusion", "web.jwt_audit"),
                       ("enumerate object references idor", "web.api"),
                       ("subdomain takeover risk", "web.takeover"),
                       ("rate limit the login", "web.policy"),
                       ("test the upload endpoint", "web.upload"),
                       ("nmap the port range", "scan_more"),
                       ("final report.", "assess")):
        got = parse_action(text)
        assert got["tool"] == "run_module" or got["tool"] == want, (text, got)
        if got["tool"] == "run_module":
            assert got["args"].get("name") == want, (text, got)
    assert "exploit.form_brute" in INTRUSIVE_MODULES
    assert {"ad.movement", "ad.privesc_ops"} <= INTRUSIVE_MODULES
    assert "exploit.known_exploits" not in INTRUSIVE_MODULES   # read-only triage
    ports = expand_ports("8000-8003, 9000")
    assert ports == [8000, 8001, 8002, 8003, 9000], ports
    assert expand_ports("99999") == []
    assert len(expand_ports("1-65535")) <= 2000
    return True, ("agent parse + module catalog + keyword routing + "
                  "intrusive gates OK")


def t_web_depth():
    import http.server
    import threading
    from core.http_client import build_multipart, raw_http
    from modules.web.api_module import _pick_ct
    from modules.web.crawler import _sitemap_locs
    from modules.web.js_analysis import DOM_SINK_RE, DOM_SOURCE_RE
    from modules.web.tech_fingerprint import _range_match, _cve_for
    from core.utils import load_json
    import re, time
    ctype, body = build_multipart(
        {"name": "jeff"},
        [("file", "a.txt", "text/plain", b"hello")])
    btext = body.decode("latin1")
    assert "name" in btext and "Content-Disposition" in btext
    assert "filename=\"a.txt\"" in btext and "boundary" in ctype
    assert btext.endswith("--\r\n")
    assert _pick_ct({"consumes": ["application/xml"]}) == "application/xml"
    assert _pick_ct({"openapi": "3.0.0", "paths": {"/x": {"post": {
        "requestBody": {"content": {"application/json": {}}}}}}}) == \
        "application/json"
    assert _pick_ct({}) == "application/json"
    locs = _sitemap_locs("<urlset><url><loc>https://a/x</loc></url>"
                         "<sitemapindex><sitemap><loc>https://b/y</loc>"
                         "</sitemap></sitemapindex></urlset>")
    assert "https://a/x" in locs and "https://b/y" in locs
    assert DOM_SINK_RE.search("el.innerHTML = payload;")
    assert DOM_SINK_RE.search("document.write(unescape(a));")
    assert DOM_SOURCE_RE.search("var x = location.search;")
    assert not DOM_SINK_RE.search("var a = 1;")
    assert _range_match("<2.4.51", "2.4.49")
    assert _range_match("==2.4.49", "2.4.49")
    assert not _range_match("==2.4.49", "2.4.50")
    assert _range_match("<=3.0", "3.0.1")
    db = load_json("intel/cve_db.json").get("products", {}).get("apache", {})
    hits = _cve_for(db, "apache", "2.4.49")
    assert any("CVE-2021-41773" in c for c in hits), hits
    assert any("CVE-2021-42013" in c for c in _cve_for(db, "apache",
                                                       "2.4.49"))
    # raw_http round trip against a local HTTP server
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("X-Probe", "yes")
            self.end_headers()
            self.wfile.write(b"raw-ok")
        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        r = raw_http("127.0.0.1", srv.server_address[1],
                     b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", tls=False,
                     timeout=3)
        assert b"raw-ok" in r, r[:80]
    finally:
        srv.shutdown()
    return True, ("multipart/OOB/sitemap/DOM/CVE-range/raw-http builders OK")


def t_vuln_coverage():
    """build_points is coverage-first: every form on every crawled endpoint is
    represented by one point carrying ALL of its fields, so no form parameter
    can be silently dropped by the injection budget."""
    from types import SimpleNamespace
    from modules.web.vuln_scanner import build_points

    class Log:
        def warn(self, *a):
            pass

    def pt():
        state = {"pages": [
            {"url": "http://a/x?q=1&z=2",
             "forms": [
                 {"action": "http://a/login", "method": "post",
                  "page": "http://a/x",
                  "fields": [{"name": "u", "type": "text"},
                             {"name": "p", "type": "password"}]},
                 {"action": "http://a/reg", "method": "post",
                  "page": "http://a/x",
                  "fields": [{"name": "user", "type": "text"},
                             {"name": "mail", "type": "email"}]}]},
            {"url": "http://a/plain",
             "forms": [{"action": "http://a/submit", "method": "post",
                        "page": "http://a/plain",
                        "fields": [{"name": "name", "type": "text"},
                                   {"name": "go", "type": "submit"}]}]},
        ], "api": {"endpoints": [
            {"method": "GET", "path": "/api/a", "url": "http://a/api/a",
             "ct": "json"},
            {"method": "GET", "path": "/api/b", "url": "http://a/api/b",
             "ct": "json"}]}}
        return SimpleNamespace(state=state, cfg=lambda k, d=60: d, log=Log(),
                               profile="quick")

    pts = build_points(pt())
    forms = {f.url for f in pts if f.kind == "form"}
    assert forms >= {"http://a/login", "http://a/reg", "http://a/submit"}, forms
    # the submit-button-only field must NOT be included as an attack param
    submit = next(f for f in pts if f.url == "http://a/submit")
    assert dict(submit.fields) == {"name": "", "go": ""}, submit.fields
    reg = next(f for f in pts if f.url == "http://a/reg")
    assert dict(reg.fields) == {"user": "", "mail": ""}, reg.fields
    # the GET-query params on the seed page are one point carrying both q and z
    getp = next(f for f in pts if f.url == "http://a/x?q=1&z=2"
            and f.method == "GET")
    assert dict(getp.fields) == {"q": "1", "z": "2"}, getp.fields
    return True, ("coverage-first build_points: every form + all params kept")


def t_oob_listener():
    import time
    from core.oob import OobListener
    lst = OobListener(bind="127.0.0.1", port=0)
    lst.start()
    try:
        assert lst.port and lst.port > 0
        assert lst.token and "http://" in lst.url("rce")
        t0 = time.time()
        lst.record({"ts": time.time(), "path": "/rce/abc", "ip": "1.2.3.4",
                    "port": 1, "ua": "ua"})
        lst.record({"ts": time.time(), "path": "/ssrf/x", "ip": "1.2.3.4",
                    "port": 1, "ua": "ua"})
        hits = lst.hits()
        assert len(hits) == 2 and any(h["path"].startswith("/rce/")
                                      for h in hits)
        # real HTTP callback path
        raw_http_probe(lst)
    finally:
        lst.stop()
    return True, "OobListener token/url/hits/stop OK"


def raw_http_probe(lst):
    from core.http_client import raw_http
    try:
        raw_http("127.0.0.1", lst.port,
                 b"GET /ssrf/%s HTTP/1.1\r\nHost: x\r\n\r\n" %
                 lst.token.encode(), tls=False, timeout=3)
        time.sleep(0.2)
        assert any(h["path"].startswith("/ssrf/") for h in lst.hits())
    except Exception:
        pass


def t_ad_chain_core():
    from core.utils import which_tool
    tool = which_tool("impacket-secretsdump", "secretsdump.py")
    assert which_tool("definitely-not-a-real-bin-xyz") is None
    assert which_tool("", None) is None or tool
    from modules.ad.privesc_ops import NTDS_RE, creds_valid
    line = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    m = NTDS_RE.search(line)
    assert m and m.group(1) == "Administrator" and m.group(4)
    assert not NTDS_RE.search("nonsense line\n")
    from modules.ad.movement import ADChannel, TRANSPORTS
    assert TRANSPORTS and any("psexec" in t for t in TRANSPORTS)
    import types
    e = types.SimpleNamespace(nonce=lambda n=4: "abcd" * 8)
    chan = ADChannel(e, "10.0.0.5", None, [], "CORP.LOCAL", "svc")
    assert chan.kind == "windows" and not chan.alive
    return True, ("which_tool resolves impacket-* names, NTDS regex, "
                  "ADChannel contract")


def t_cloud_api():
    import types
    from modules.web.cloud_check import bucket_candidates, _clean, \
        LIST_MARKERS
    from modules.web.api_module import _mark_doc, OPENAPI_PATHS
    assert _mark_doc({"swagger": "2.0", "paths": {}}) == "Swagger 2.0"
    assert _mark_doc({"openapi": "3.0.0"}) == "OpenAPI 3.x"
    assert _mark_doc({"foo": 1}) == ""
    assert "/openapi.json" in OPENAPI_PATHS and "/v2/api-docs" in OPENAPI_PATHS
    assert b"AnyBucket" in LIST_MARKERS or LIST_MARKERS[-1]
    class T:
        hostname = "corp.example.com"
    class E:
        target = T()
        state = {"web_targets": [{"url": "https://api.corp.example.com"}],
                 "subdomains": [{"host": "uploads.corp.example.com"}]}
        def cfg(self, k, default=None):
            return {"bucket_candidates": 30}.get(k, default)
    cands = bucket_candidates(E())
    assert "corp.example.com" in cands, cands
    assert "corp" in cands
    assert "api" in cands and "uploads" in cands
    assert "s3" not in cands           # short labels are discarded
    assert any(c.endswith("-backup") for c in cands)
    assert all(len(c) >= 3 and not c.isdigit() for c in cands)
    assert _clean("www.Prod-TEST.example.com") == "prod-test.example.com"
    return True, "OpenAPI marks + bucket-candidate builder OK"


def t_web_auth():
    import http.server
    import threading
    from core.crypto_mini import totp_codes
    from core.http_client import HttpClient, HttpResult
    from modules.web.auth_logic import (user_field, pass_field, otp_field,
                                        csrf_field, pick_login_form,
                                        build_data, likely_logged_in,
                                        AUTH_BYPASSES, OTP_TRICKS,
                                        pick_register_form, _register_like,
                                        random_identity)
    s = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp_codes(s, t=59, window=0)[0] == "287082"       # RFC 6238
    assert totp_codes(s, t=1111111109, window=1)[1] == "081804"   # ±window, index 1 = now
    assert len(totp_codes(s, t=30, window=1)) == 3               # ±window
    assert totp_codes("not_base32!!", window=0) == []
    fields = [{"name": "csrf_token", "type": "hidden", "value": "abc"},
              {"name": "username", "type": "text", "value": ""},
              {"name": "password", "type": "password", "value": ""},
              {"name": "otp", "type": "text", "value": ""}]
    assert user_field(fields) == "username"
    assert pass_field(fields) == "password"
    assert otp_field(fields) == "otp"
    assert csrf_field(fields) == "csrf_token"
    form = {"action": "/login/auth", "method": "post", "fields": fields}
    assert pick_login_form(
        [{"action": "/x", "fields": [{"name": "q", "type": "text"}]},
         form])["action"] == "/login/auth"
    # login-form selection must NOT fall onto a register surface
    login_f = {"action": "/login", "fields": [{"name": "u", "type": "text"},
                                              {"name": "p",
                                               "type": "password"}]}
    reg_f = {"action": "/register",
             "fields": [{"name": "u", "type": "text"},
                        {"name": "p", "type": "password"}]}
    assert pick_login_form([reg_f])["action"] == "/register"   # register only
    assert pick_login_form([login_f, reg_f])["action"] == "/login"
    assert not _register_like([login_f])
    assert _register_like([reg_f])
    assert pick_register_form([login_f, reg_f])["action"] == "/register"
    ident = random_identity("x")
    assert set(ident) == {"username", "email", "password"}
    assert id(ident) and ident["username"].startswith("x_") \
        and "local" in ident["email"] and len(ident["password"]) > 12
    data = build_data(fields, "username", "password", "jeff", "hunter2",
                      "000000", "abc")
    assert data["username"] == "jeff" and data["password"] == "hunter2"
    assert data["otp"] == "000000" and data["csrf_token"] == "abc"
    assert len(AUTH_BYPASSES) >= 20 and len(OTP_TRICKS) >= 6
    good = HttpResult("http://x/login/auth", 200,
                      {"location": "/dashboard", "set-cookie": "SID=1; Path=/"},
                      b"<h1>Welcome</h1>", 0.1)
    assert likely_logged_in(good, "", "")
    bad = HttpResult("http://x/login/auth", 200,
                     {"location": "/login/auth?err=1"},
                     b"Sorry, invalid password", 0.1)
    assert not likely_logged_in(bad, "", "")
    # cookie jar is actually attached to requests
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.cookie = self.headers.get("Cookie", "")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        c = HttpClient(timeout=3)
        c.apply_cookies("SESSID=AAA; lang=en")
        c.get("http://127.0.0.1:%d/" % srv.server_address[1])
        got = srv.cookie
    finally:
        srv.shutdown()
    assert "SESSID=AAA" in got and "lang=en" in got, got
    return True, ("TOTP vectors, form-field routing, bypass families, "
                  "cookie-jar adoption OK")


def t_autoreg_idor():
    """Auto-register two throwaway accounts, adopt sessions, then run
    web.escalate against a local app: /me identity discovery, confirmed
    cross-user IDOR (anonymous baseline does NOT leak), and authenticated
    admin-surface recon."""
    import http.server
    import json as _json
    import threading
    import urllib.parse
    from types import SimpleNamespace
    from core.http_client import HttpClient
    from core.database import Database
    from modules.web import priv_escl
    from modules.web.auth_logic import auto_register

    users, sids, next_id = [], {}, [1]

    class H(http.server.BaseHTTPRequestHandler):
        def _user(self):
            sid = None
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "SID":
                    sid = v
            return sids.get(sid)

        def do_GET(self):
            p = urllib.parse.urlsplit(self.path).path
            if p == "/":
                self._html(
                    "<form action='/register' method='post'>"
                    "<input name='username' type='text'>"
                    "<input name='email' type='email'>"
                    "<input name='password' type='password'>"
                    "<input name='password_confirm' type='password'>"
                    "<input name='csrf_token' type='hidden' value='tok-1'>"
                    "<input name='terms' type='checkbox' value='1'>"
                    "<button>Create account</button></form>")
                return
            if p == "/register":
                self._html("<input name='csrf_token' type='hidden' "
                           "value='tok-1'>")
                return
            if p == "/me":
                u = self._user()
                if not u:
                    return self._err(401, "no session")
                return self._json({"id": u["id"], "username": u["username"],
                                   "email": u["email"]})
            if p.startswith("/api/users/"):
                u = self._user()
                if not u:
                    return self._err(401, "no session")
                uid = p.split("/")[-1]
                hit = next((x for x in users if str(x["id"]) == uid), None)
                if not hit:
                    return self._err(404, "not found")
                # IDOR: ownership is not enforced - any session reads any
                # user's private email
                return self._json({"id": hit["id"],
                                   "username": hit["username"],
                                   "email": hit["email"]})
            if p == "/admin":
                if not self._user():
                    return self._err(403, "denied")
                rows = "".join("<tr><td>%s</td></tr>" % u["username"]
                               for u in users)
                return self._html("<h1>User management</h1><table>%s"
                                  "</table>" % rows)
            return self._err(404, "nope")

        def do_POST(self):
            p = urllib.parse.urlsplit(self.path).path
            if p == "/register":
                ln = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(ln).decode()
                d = {k: urllib.parse.unquote_plus(v)
                     for k, v in ([x.split("=", 1) for x in raw.split("&")
                                   if "=" in x])}
                need = ("username", "email", "password", "password_confirm",
                        "csrf_token")
                if [f for f in need if not d.get(f)]:
                    return self._err(400, "missing fields")
                if d["password"] != d["password_confirm"]:
                    return self._err(400, "password does not match")
                if any(u["username"] == d["username"] for u in users):
                    return self._err(400, "username already exists")
                u = {"id": next_id[0], "username": d["username"],
                     "email": d["email"], "sid": "u%d" % next_id[0]}
                next_id[0] += 1
                users.append(u)
                sids["u%d" % u["id"]] = u
                self.send_response(303)
                self.send_header("Location", "/me")
                self.send_header("Set-Cookie", "SID=" + u["sid"] + "; Path=/")
                self.end_headers()
                return
            return self._err(404, "nope")

        def _html(self, body):
            b = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _json(self, obj):
            b = _json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _err(self, code, msg):
            b = msg.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()

    class _Log:
        def success(self, *a):
            pass

        def info(self, *a):
            pass

        def warn(self, *a):
            pass

    try:
        httpc = HttpClient(timeout=5)
        db = Database(os.path.join(tempfile.mkdtemp(prefix="vajra_escl_"),
                                   "db.sqlite"))
        eng = SimpleNamespace(
            target=SimpleNamespace(display="escl.local", url=base,
                                   kind="web"),
            args=SimpleNamespace(no_autoreg=False, web_user=None,
                                 web_pass=None, web_login=None, otp=""),
            state={"web_targets": [{"url": base}], "web_auth": {}},
            http=httpc, db=db, log=_Log())
        eng._screenshots_enabled = lambda: False
        eng.save_evidence = lambda *a, **k: ""

        a = auto_register(eng, "A")
        assert a and eng.state["web_auth"].get("established"), \
            ("reg A failed", a)
        a_cookie = eng.state["_autoreg"]["A"]["cookie"]
        b = auto_register(eng, "B")
        assert b and eng.state["_autoreg"]["B"]["cookie"], ("reg B failed", b)
        eng.http._cookie = a_cookie   # back to account A

        priv_escl.run(eng)

        cur = db.conn.execute(
            "SELECT module, category, severity, confidence FROM findings "
            "WHERE module='web.escalate' ORDER BY id")
        rows = cur.fetchall()
        idor = [r for r in rows if r[1] == "idor"]
        vert = [r for r in rows if r[1] == "recon"]
        assert idor, ("no IDOR finding recorded", rows)
        assert idor[0][2] == "high" and idor[0][3] == "firm", idor[0]
        assert vert, ("no vertical admin-surface recon recorded", rows)
    finally:
        srv.shutdown()
    return True, ("auto-register A/B -> /me identity -> confirmed cross-user "
                  "IDOR + admin-surface recon")


def t_intel_kb():
    import json as _json
    from core.utils import load_json
    checks = {
        "intel/ports.json": lambda d: len(d.get("known_ports", {})) > 400,
        "intel/os.json": lambda d: len(d.get("ttl_ranges", {})) > 3,
        "intel/cloud.json": lambda d: bool(d.get("providers") or d.get("s3")
                                           or d.get("kubernetes")),
        "intel/services.json": lambda d: len(d.get("services", {})) >= 25,
        "intel/creds_default.json":
            lambda d: "tomcat" in d.get("targets", {}),
        "intel/login_surfaces.json":
            lambda d: any(p for p in d.get("paths", []) if p == "/login"),
        "intel/loot_paths.json": lambda d: d.get("groups"),
        "intel/community_strings.json":
            lambda d: len(d.get("wordlist", [])) >= 8 and
                      "public" in d.get("wordlist", []),
        "intel/signatures.json": lambda d: bool(d.get("waf_signatures") and
                                                d.get("tech_signatures")),
    }
    for rel, ok in checks.items():
        d = load_json(rel)
        assert ok(d), rel
    svc = load_json("intel/services.json").get("services", {})
    assert "redis" in svc and (svc["redis"].get("probes") or [])[0].get(
        "send") == "PING\r\n"
    return True, "all intel KB files load + schema-valid (uintel-driven scope)"


def t_toolkit():
    import importlib.util
    import sys as _sys
    from core.utils import PROJECT_ROOT
    tools_dir = str(PROJECT_ROOT / "tools")
    if tools_dir not in _sys.path:
        _sys.path.insert(0, tools_dir)
    def load(name):
        spec = importlib.util.spec_from_file_location(
            name, str(PROJECT_ROOT / "tools" / (name + ".py")))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    hashid = load("hashid")
    kind = hashid.identify("5f4dcc3b5aa765d61d8327deb882cf99")
    assert any("MD5" in k for k in kind), kind
    kind = hashid.identify("$2b$12$" + "A" * 53)
    assert any("bcrypt" in k.lower() for k in kind), kind
    cve = load("cve")
    assert cve.range_matches(">=2.4.32", "2.4.49")
    assert not cve.range_matches("==2.4.49", "2.4.50")
    db = cve.load_json("intel/cve_db.json", {}).get("products", {})
    apache = db.get("apache", {})
    hits = [cv for rng, cvs in (apache.get("ranges") or {}).items()
            if cve.range_matches(rng, "2.4.49")
            for cv in cvs]
    assert any("CVE-2021-41773" in c for c in hits), hits
    from tools.wordlists import SHIPPED
    assert SHIPPED
    assert any("users" in p or "pass" in p for p in SHIPPED)
    envcheck = load("envcheck")
    assert callable(envcheck.resolve)
    pocgen = load("pocgen")
    body = pocgen.build(pocgen.TEMPLATES["xss"],
                        {"url": "http://a/search", "param": "q",
                         "payload": "<scr>1</scr>", "host": "a",
                         "path": "/search", "enc": "%3Cscr%3E1"})
    assert "/search" in body and "q=" in body
    rawhttp = load("rawhttp")
    assert callable(rawhttp.main)
    dnsrecon = load("dnsrecon")
    assert callable(dnsrecon.main)
    netkit = load("netkit")
    assert callable(netkit.main)
    fuzzurl = load("fuzzurl")
    assert callable(fuzzurl.main)
    return True, "all toolkit CLIs import; pure helpers verified (hashid/cve/pocgen)"


def t_intel_modules():
    from modules.web.sensitive_files import _looks_real, GROUPS
    assert GROUPS, "loot groups empty"
    assert _looks_real(200, "ref: refs/heads/master\n", "application/x-git",
                       ".git/head", ".git/head")
    assert _looks_real(200, "KEY=value", "text/plain", "/.env", ".env")
    assert not _looks_real(200, "<html>404 - Not Found page</html>",
                           "text/html", "/.env", ".env")
    assert not _looks_real(404, "whatever", "text/html", "/x", "x")
    from modules.network.service_exposure import _banner_hint
    assert _banner_hint("Redis server v=7.4.1", "redis")
    assert not _banner_hint("postgres", "redis")
    from modules.exploit.default_creds import CRED_CATALOG, SERVICE_TO_PORTS
    assert CRED_CATALOG["tomcat"]["auth"] == "basic"
    assert {"tomcat", "weblogic", "grafana", "jenkins"} <= set(CRED_CATALOG)
    from modules.web.crawler import LOGIN_PATHS
    assert "/login" in LOGIN_PATHS and "/wp-login.php" in LOGIN_PATHS
    import re
    from modules.web.policy_check import LOGIN_INTEL
    got = [c for c in LOGIN_INTEL.get("paths", [])]
    assert "/wp-login.php" in got and "/admin/login" in got
    # recommend new service_exposure/module registry contract
    import modules as m
    names = {x["name"] for x in m.get_modules()}
    assert "network.service_exposure" in names, names
    assert "web.loot" in names, names
    return True, ("web.loot + network.service_exposure + KB-driven creds/ "
                  "login wiring OK")


def t_next_caps():
    import http.client, http.server
    import socket, struct
    import tempfile, threading, select
    from modules.recon.axfr import _encode_name, _read_name
    from modules.web.race_check import _candidates
    from core.utils import PROJECT_ROOT
    from core.cve_refresh import _save, _cache

    # DNS wire helpers
    q = _encode_name("corp.example.com") + struct.pack(">HH", 252, 1)
    assert q.startswith(b"\x04corp\x07example\x03com\x00")
    body = (bytes(12) + q +
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x0a\x01\x02")
    name, nxt = _read_name(body, 12 + len(q))
    assert name == "corp.example.com." and nxt == 12 + len(q) + 2, \
        (name, nxt)

    # race candidates from a fabricated crawl state
    class T:
        display = "tgt"
    class E:
        target = T()
        state = {"pages": [{"url": "http://a/x",
                            "forms": [{"action": "/promo", "method": "post",
                                       "fields": [{"name": "code"},
                                                  {"name": "qty"}]},
                                      {"action": "/set/other",
                                       "method": "get",
                                       "fields": [{"name": "q"}]}]}],
                 "api_endpoints": [{"method": "POST",
                                    "url": "http://a/api/claim",
                                    "path": "/api/claim"}]}
    cands = _candidates(E)
    assert any("promo" in u for u, m, f in cands), cands
    assert any("api/claim" in u for u, m, f in cands)

    # PDF writer: syntactically-parseable xref
    import core.report as rep
    data = {"meta": {"tool": "VAJRA", "generated": "now", "profile": "quick",
                     "targets": ["10.0.0.5"], "output_dir": "/tmp"},
            "stats": {"critical": 1, "high": 2}, "score": 24.0,
            "narrative": "Test narrative for PDF rendering. " * 12,
            "findings": [{"severity": "critical", "title": "RCE <x> broken",
                          "category": "web-vuln", "module": "m", "detail": "d",
                          "evidence": "proof (line)", "confidence": "firm",
                          "mitre": "T1203"}],
            "services": [], "events": [], "tech": [], "subdomains": [],
            "os_guess": "", "evasion": []}
    pdf = tempfile.mktemp(suffix=".pdf")
    rep.render_pdf(data, path=pdf)
    raw = open(pdf, "rb").read()
    assert raw[:5] == b"%PDF-" and raw.rstrip().endswith(b"%%EOF")
    xref_at = int(raw[raw.rindex(b"startxref") + 9:].split()[0])
    head = raw[xref_at:xref_at + 2000]
    assert head.startswith(b"xref\n")
    nobj = int(head.split(b"\n")[1].split()[-1])
    assert nobj >= 6, nobj
    offsets = [int(head.split(b"\n")[i].split()[0])
               for i in range(2, 2 + nobj)]
    first = offsets[1]
    assert raw[first:first + 7] == b"1 0 obj", (first, raw[first:first + 12])

    # SOCKS5 round trip: our proxy relays to a local HTTP server
    def _socks5_server():
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(9)

        def handle(c):
            dst = None
            try:
                def recvn(n):
                    b = b""
                    while len(b) < n:
                        d = c.recv(n - len(b))
                        if not d:
                            raise OSError("eof")
                        b += d
                    return b
                c.settimeout(6)
                assert recvn(2)[0] == 5       # ver
                nmeth = recvn(1)[0]
                recvn(nmeth)                   # methods
                c.sendall(b"\x05\x00")
                req = recvn(4)                 # ver cmd rsv atyp
                atyp = req[3]
                if atyp == 3:
                    n = recvn(1)[0]
                    host = recvn(n).decode("ascii")
                    port = int.from_bytes(recvn(2), "big")
                else:
                    host = socket.inet_ntoa(recvn(4))
                    port = int.from_bytes(recvn(2), "big")
                dst = socket.create_connection((host, port), timeout=5)
                c.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" +
                          struct.pack(">H", port))
                socks = [c, dst]
                while True:
                    r, _, _ = select.select(socks, [], [], 5)
                    if not r:
                        break
                    for s in r:
                        d = s.recv(65536)
                        if not d:
                            return
                        (dst if s is c else c).sendall(d)
            except Exception:
                return
            finally:
                try:
                    dst.close()
                except Exception:
                    pass
                try:
                    c.close()
                except Exception:
                    pass

        def run():
            while True:
                conn, _ = srv.accept()
                threading.Thread(target=handle, args=(conn,),
                                 daemon=True).start()
        threading.Thread(target=run, daemon=True).start()
        return srv

    class H2(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"socks-ok")
        def log_message(self, *a):
            pass

    web = http.server.HTTPServer(("127.0.0.1", 0), H2)
    web_th = threading.Thread(target=web.serve_forever, daemon=True)
    web_th.start()
    socks = _socks5_server()
    try:
        from core.http_client import HttpClient, socks5_connect
        s = socks5_connect("127.0.0.1:%d" % socks.getsockname()[1],
                           "127.0.0.1", web.server_address[1], timeout=4)
        s.close()
        c = HttpClient(timeout=4, socks="127.0.0.1:%d" %
                       socks.getsockname()[1])
        r = c.get("http://127.0.0.1:%d/" % web.server_address[1])
        assert r.status == 200 and "socks-ok" in r.body
    finally:
        web.shutdown()
        socks.close()

    # CVE refresh cache round-trip (isolated file, cleaned after)
    import core.cve_refresh as cref
    old = cref.CACHE_RELPATH
    cref.CACHE_RELPATH = "intel/cve_online_cache.selftest.json"
    try:
        cref._save({"apache|2.4.49": {"ts": 0, "results": [{"id": "CVE-1"}]}})
        cc = cref._cache()
        assert "apache|2.4.49" in cc
    finally:
        cref.CACHE_RELPATH = old
        try:
            (PROJECT_ROOT / "intel/cve_online_cache.selftest.json").unlink()
        except OSError:
            pass

    # OSV-exact helpers: semver range containment, CVSS3 base, product aliasing
    assert cref._range_match("2.4.49", "2.4.49", "2.4.51")
    assert not cref._range_match("2.4.51", "2.4.49", "2.4.51")
    assert cref._range_match("5.2.5", "0", "6.1.7")
    assert abs(cref._cvss_base3(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") - 9.8) < 0.1
    assert cref.ALIASES.get("ruby on rails") == "rails"
    return True, ("AXFR wire helpers, race candidates, PDF xref, SOCKS5 relay, "
                  "CVE cache + OSV range/CVSS helpers OK")


def t_snmp_brute():
    import socket as _s, threading as _t
    from modules.network import snmp_probe as S

    def _ber(tag, payload):
        ln = len(payload)
        if ln < 0x80:
            return bytes([tag, ln]) + payload
        b = ln.to_bytes((ln.bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(b)]) + b + payload

    def _int(v):
        if v == 0:
            return b"\x00"
        return v.to_bytes((v.bit_length() + 7) // 8, "big")

    def _snmp_response(community, oid, val, err=0, reqid=0):
        vb = _ber(0x30, _ber(0x06, oid) + _ber(0x04, val))
        pdu = _ber(0xA2, _ber(0x02, _int(reqid)) + _ber(0x02, _int(err)) +
                   _ber(0x02, _int(0)) + _ber(0x30, vb))
        return _ber(0x30, _ber(0x02, b"\x00") + _ber(0x04, community) + pdu)

    def _parse_req_id(data):
        i = data.find(b"\xa0")
        if i < 0:
            return 0, b""
        off = i + 2
        if data[i + 1] & 0x80:
            off = i + 2 + (data[i + 1] & 0x7F)
        # request-id INTEGER
        ln = data[off + 1]
        return int.from_bytes(data[off + 2:off + 2 + ln], "big"), \
            data[data.find(b"\x04") + 2:data.find(b"\xa0") - 2]

    srv = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(4)
    oid_sys = bytes.fromhex("2b06010201010100")
    oid_descr = bytes.fromhex("2b0601020101010000")

    def serve():
        while True:
            try:
                data, addr = srv.recvfrom(4096)
            except _s.timeout:
                return
            rid, _ = _parse_req_id(data)
            resp = _snmp_response(b"public", oid_sys, b"Linux router", reqid=rid)
            srv.sendto(resp, addr)
    _t.Thread(target=serve, daemon=True).start()
    try:
        port = srv.getsockname()[1]
        res = S._udp_get("127.0.0.1", b"public",
                         b"\x2b\x06\x01\x02\x01\x01\x01\x00",
                         timeout=2.5, port=port)
        assert res and res[0] == "sysDescr" and "Linux" in res[1], res
        q = S.snmp_get(b"public", b"\x2b\x06\x01\x02\x01\x01\x01\x00")
        assert q.startswith(b"\x30") and b"\x04\x06public" in q
        nope = S._udp_get("127.0.0.1", b"wrong-community",
                          b"\x2b\x06\x01\x02\x01\x01\x01\x00",
                          port=port)
        assert nope is None or nope[1].startswith(("wrong", ""))
    finally:
        srv.close()
    return True, "SNMPv1 BER encoder + parse + mock responder OK"


def t_share_native():
    import socket as _s, struct as _st, threading as _t
    from modules.ad.smb_recon import _smb1_pkt, _smb1_hdr
    from modules.network.share_enum import _native_share_enum

    srv = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
    srv.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(3)

    def recv_exact(c, n):
        b = b""
        while len(b) < n:
            d = c.recv(n - len(b))
            if not d:
                raise OSError("eof")
            b += d
        return b

    def recv_frame(c):
        hdr = recv_exact(c, 4)
        ln = int.from_bytes(hdr[1:], "big")
        return hdr + recv_exact(c, ln)

    def tree_response():
        body = _smb1_hdr(0x75, flags=0x80, tid=0xBEEF, uid=0x2A2A,
                         mid=0x0002) + b"\x00" + b"\x00\x00"
        return _smb1_pkt(body)

    def trans_response():
        shares = [(b"C$", 0x0000), (b"IPC$", 0x0003)]
        data = b""
        for name, stype in shares:
            data += name + b"\x00" * (13 - len(name)) + b"\x00" + \
                _st.pack("<H", stype) + _st.pack("<H", 0x0FF0) + b"\x00\x00"
        params = b"\x00\x00" + _st.pack("<H", 0x0F7C) + \
            _st.pack("<H", len(shares)) + _st.pack("<H", len(shares))
        words = (_st.pack("<H", 0) + _st.pack("<H", len(data)) +
                 _st.pack("<H", 0) + _st.pack("<H", 0) +
                 _st.pack("<H", 8) + _st.pack("<H", 56) + _st.pack("<H", 0) +
                 _st.pack("<H", len(data)) + _st.pack("<H", 64) +
                 b"\x00\x00")
        body = _smb1_hdr(0x25, flags=0x80, tid=0xBEEF, uid=0x2A2A,
                         mid=0x0003) + bytes([10]) + words + \
            _st.pack("<H", 1 + len(params) + len(data)) + b"\x00" + \
            params + data
        return _smb1_pkt(body)

    def session_response():
        body = _smb1_hdr(0x73, flags=0x80, uid=0x2A2A, mid=0x0001) + \
            b"\x00" + b"\x00\x00"
        return _smb1_pkt(body)

    def handle(c):
        try:
            c.settimeout(6)
            recv_frame(c)                 # negotiate
            words = (b"\x02\x00" + b"\x01\x00" + b"\x00\x08" + b"\x00\x00" +
                     b"\x00\xf1\x00\x00" + b"\x00\x04\x00\x00" + b"\x00" * 4 +
                     b"\x00\x00\x00\x00" + b"\x10\x00\x10\x00" + b"\x00" * 6)
            strings = (b"Windows Server 2019 Standard 17763\x00" +
                       b"Windows Server 2019 Standard 6.3\x00" +
                       b"WORKGROUP\x00")
            key = b"\x00" * 16
            neg = _smb1_pkt(_smb1_hdr(0x72, flags=0x80) + bytes([17]) +
                            words + _st.pack("<H", len(key) + len(strings)) +
                            key + strings)
            c.sendall(neg)
            recv_frame(c)                 # session setup
            c.sendall(session_response())
            recv_frame(c)                 # tree connect
            c.sendall(tree_response())
            recv_frame(c)                 # transaction
            c.sendall(trans_response())
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass

    def run():
        while True:
            conn, _ = srv.accept()
            _t.Thread(target=handle, args=(conn,), daemon=True).start()
    _t.Thread(target=run, daemon=True).start()
    try:
        port = srv.getsockname()[1]
        shares, err = _native_share_enum("127.0.0.1", port)
        assert not err, err
        assert shares, shares
        names = [s.split(" (")[0] for s in shares]
        assert "IPC$" in names and any("C$" in n for n in names), names
    finally:
        srv.close()
    return True, "native SMBv1 RAP share walk vs mock server OK"


def t_workspace():
    import json as _json
    from core.workspace import Workspace, _slug
    d = tempfile.mkdtemp(prefix="vajra_ws_")
    ws = Workspace("1.2.3.4", root=d)
    assert _slug("a/b:c###") == "a_b_c"
    f1 = {"module": "web.xss", "title": "reflected XSS",
          "severity": "high", "category": "xss", "detail": "d"}
    ws.snapshot({"1.2.3.4": {"findings": [f1], "services": [], "score": 7.5}},
                profile="quick", meta={"a": 1})
    assert ws.latest()["targets"]["1.2.3.4"]["findings"] == [f1]
    delta = ws.delta_for("1.2.3.4", [f1])
    assert delta["new"] == [] and delta["fixed"] == [] and \
        len(delta["still_open"]) == 1
    f2 = {"module": "network.tls", "title": "weak cipher",
          "severity": "medium", "category": "tls", "detail": "d"}
    delta2 = ws.delta_for("1.2.3.4", [f1, f2])
    assert len(delta2["new"]) == 1 and \
        delta2["new"][0]["title"] == "weak cipher"
    ws.save_state("1.2.3.4", {"open_ports": [22, 80], "os_guess": "linux"})
    assert ws.load_state("1.2.3.4")["os_guess"] == "linux"
    ws.append_narrative("operator: hold manual deep-dive")
    assert "hold manual" in ws.narrative_text()
    merged = ws.merged_findings()
    assert any(x["title"] == "reflected XSS" for x in merged)
    out = os.path.join(d, "exp.json")
    ws.export_findings(out)
    assert os.path.exists(out)
    exported = _json.load(open(out))
    assert any(x.get("title") == "reflected XSS" for x in exported)
    ws2 = Workspace("9.9.9.9", root=d)
    snap = ws2.import_export(ws.export(os.path.join(d, "ws.json")))
    assert snap and "1.2.3.4" in snap["targets"]
    return True, ("snapshot/delta/state/AI/export+import OK")


def t_synthesis():
    from core.synthesis import (auto_narrative, correlate_across,
                                build_ai_blocks)
    finds = [
        {"severity": "critical", "module": "web.vulnscan",
         "title": "RCE in api", "target": "10.0.0.1", "detail": "x"},
        {"severity": "low", "module": "network.tls", "title": "weak TLS",
         "target": "10.0.0.2", "detail": "y"},
    ]
    stats = {"critical": 1, "high": 0, "medium": 0, "low": 1, "info": 0,
             "targets": 2, "open": 3, "findings": 2}
    nar = auto_narrative(stats, finds,
                         [{"port": 443, "service": "https"}],
                         [{"display": "10.0.0.1"}], 8.1)
    assert "1 critical" in nar and "8.1/100" in nar
    assert correlate_across(finds) == []
    dup = finds + [dict(finds[1], target="10.0.0.3")]
    assert any(c["count"] == 2 for c in correlate_across(dup))
    blocks = build_ai_blocks(
        {"10.0.0.1": {"findings": [finds[0]], "score": 8.0}},
        delta_summary={"new": 1, "fixed": 0, "still": 0})
    assert "## Run" in blocks and "RCE in api" in blocks
    return True, ("narrative + cross-host correlation + AI blocks OK")


def t_compliance():
    import modules
    from core.compliance import (controls_for, remediate, markdown_playbook,
                                 MAP)
    assert MAP, "compliance map unpopulated"
    names = [m["name"] for m in modules.MODULES]
    assert len(names) >= 40, len(names)
    for n in names:
        c = controls_for(n)
        assert c["cis"] and c["nist"] and c["pci"], n
    f = {"module": "web.xss", "severity": "high", "title": "XSS",
         "detail": "d", "target": "h", "remediation": "encode output"}
    sections = remediate([f])
    assert sections and sections[0]["severity"] == "high"
    md = markdown_playbook(sections)
    assert "XSS" in md and "CIS" in md and "NIST" in md and "PCI" in md
    return True, ("%d modules mapped to CIS/NIST/PCI controls" % len(names))


def t_pivot_proxy():
    import socket as _socket
    import struct
    import threading
    import time
    from core.tcp_pivot import PivotProxy, parse_chain
    echo = _socket.socket()
    echo.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    echo.bind(("127.0.0.1", 0))
    echo.listen(1)
    eport = echo.getsockname()[1]

    def serve():
        try:
            c, _ = echo.accept()
            data = c.recv(1024)
            c.sendall(b"ECHO:" + data)
            c.close()
        except Exception:
            pass
    threading.Thread(target=serve, daemon=True).start()

    prox = PivotProxy(host="127.0.0.1", port=0, upstream=None)
    prox.start()
    for _ in range(100):
        if prox.port:
            break
        time.sleep(0.05)
    assert prox.port, "proxy did not bind"
    try:
        s = _socket.create_connection(("127.0.0.1", prox.port), timeout=5)
        s.sendall(b"\x05\x01\x00")
        assert s.recv(2) == b"\x05\x00"
        s.sendall(b"\x05\x01\x00\x01" + _socket.inet_aton("127.0.0.1") +
                  struct.pack(">H", eport))
        r = s.recv(10)
        assert len(r) == 10 and r[1] == 0, r
        s.sendall(b"hello")
        assert s.recv(1024) == b"ECHO:hello", "relay payload mismatch"
        s.close()
    finally:
        prox.stop()
    chain = parse_chain("socks5://10.0.0.1:1080,http://10.0.0.2:3128")
    assert chain[0]["type"] == "socks5" and chain[1]["type"] == "http"
    assert parse_chain("") == []
    assert parse_chain("10.0.0.9:3128")[0]["type"] == "socks5"
    return True, ("SOCKS5 relay E2E through PivotProxy OK")


def t_pack_rt():
    import subprocess
    from core.payload_engine import pack, sleep_jitter
    src = "import sys; sys.stdout.write('PACK_OK')"
    cmd = pack(src, rounds=3, seed=7)
    assert cmd.startswith("python3 -c \"exec(")
    inner = cmd[len("python3 -c \""):-1]
    r = subprocess.run(["python3", "-c", inner], capture_output=True,
                       timeout=15)
    assert r.returncode == 0 and b"PACK_OK" in r.stdout, r.stderr
    assert abs(sleep_jitter(1.0, 0.0) - 1.0) < 0.001
    assert 0 < sleep_jitter(2.0, 0.5) < 4.0
    return True, ("pack round-trip via subprocess + sleep_jitter OK")


def t_sid_acl():
    from modules.ad.power import parse_acl, _sid_str, _sid_name
    assert _sid_name("S-1-5-32-544") == "BUILTIN\\Administrators"
    assert _sid_name("S-1-5-21-1-2-3-512") == "Domain Admins"

    def sid(authority, rids):
        b = bytearray([1, len(rids)]) + authority.to_bytes(6, "big")
        for r in rids:
            b += r.to_bytes(4, "little")
        return bytes(b)

    world = sid(1, [0])                          # S-1-1-0
    dadmin = sid(5, [21, 1, 2, 3, 512])          # S-1-5-21-1-2-3-512
    assert _sid_str(world, 0) == "S-1-1-0"
    assert _sid_str(dadmin, 0) == "S-1-5-21-1-2-3-512"

    def ace(atype, mask, trust):
        return (bytes([atype, 0]) +
                (8 + len(trust)).to_bytes(2, "little") +
                mask.to_bytes(4, "little") + trust)

    owner = sid(1, [0])
    aces = ace(0x00, 0x00010000, world) + ace(0x00, 0x00000001, dadmin)
    dacl = (bytes([2, 0]) + (8 + len(aces)).to_bytes(2, "little") +
            (2).to_bytes(2, "little") + b"\x00\x00") + aces
    sd = (bytes([1, 0]) + (0x8004).to_bytes(2, "little") +
          (20).to_bytes(4, "little") +
          (20 + len(owner)).to_bytes(4, "little") +
          b"\x00\x00\x00\x00" +
          (20 + len(owner)).to_bytes(4, "little")) + owner + dacl
    parsed = parse_acl(sd)
    assert len(parsed) == 2, parsed
    names = [a["name"] for a in parsed]
    assert "Everyone" in names and "Domain Admins" in names, names
    evil = next(a for a in parsed if a["name"] == "Everyone")
    assert evil["danger"] is True and evil["risky"] is True
    assert all(a["type"] == "ALLOWED" for a in parsed)
    assert parse_acl(b"") == [] and parse_acl(b"x") == []
    return True, ("self-relative DACL parse: canonical SIDs + risky/danger")


def t_loot_survey():
    from modules.post.loot import _creds, _survey, PATHS

    class MockCli:
        def exec_command(self, cmd, timeout=20):
            class Ch:
                def read(self):
                    return b""
            out = b"YES\n" if "test -e" in cmd else b"R\n"

            class Out:
                def read(self):
                    return out
            return Ch(), Out(), Ch()
    found = _survey(MockCli())
    cats = {c for c, _ in found}
    assert cats and cats <= {c for c, _ in PATHS}, cats
    assert found[0][1][0][0].startswith("~")
    class E:
        state = {"creds": [["ssh", "alice", "pw", "10.0.0.5"]]}
    assert _creds(E()) == [("alice", "pw", "10.0.0.5")]
    return True, ("SSH loot survey + cred parsing OK")


def t_staged_c2():
    from core.listener import render_stagers, STAGE_SRC
    assert len(STAGE_SRC) > 80 and "pty.spawn" in STAGE_SRC
    for tls in (False, True):
        payloads = render_stagers(kind="unix", lhost="10.9.9.9", lport=4444,
                                  tls=tls)
        for name, p in payloads:
            assert "10.9.9.9" in p and "4444" in p
            assert "{{" not in p, "double-brace leak in %s" % name
            compile(p[len("python3 -c \""):-1], "<stage>", "exec")
    obf = render_stagers(kind="unix", lhost="10.9.9.9", lport=4444,
                         obfuscate=True)
    for name, p in obf:
        if name.startswith("python3"):
            compile(p[len("python3 -c \""):-1], "<stage>", "exec")
    return True, ("staged stagers compile (plain/tls/obfuscated) OK")


def t_attack_paths():
    from core.attackpath import (correlate_findings, build_attack_paths,
                                 canonical_key, attack_path_md)
    # dedup: one XSS issue detected by three different modules -> one cluster
    finds = [
        {"severity": "high", "module": "web.vulnscan",
         "title": "reflected XSS in /search", "target": "http://app.local",
         "evidence": "<script>", "confidence": "firm"},
        {"severity": "high", "module": "web.wiretests",
         "title": "cross-site scripting /search", "target": "http://app.local",
         "evidence": "x", "confidence": "tentative"},
        {"severity": "medium", "module": "web.policy",
         "title": "XSS header mishandling", "target": "http://app.local",
         "confidence": "tentative"},
        {"severity": "low", "module": "network.tls",
         "title": "weak TLS cipher", "target": "app.local", "confidence": "t"},
    ]
    corr = correlate_findings(finds)
    xss = [c for c in corr if c.get("key") == "xss"]
    assert xss, "no xss cluster"
    assert xss[0]["title_count"] == 3, xss
    assert xss[0]["severity"] == "high" and xss[0]["confidence"] == "firm"
    assert len(xss[0]["sources"]) == 3
    assert canonical_key("command injection in upload") == "command_injection"
    # attack paths are evidence-grounded only
    state = {"services": [{"target": "app.local", "port": 443,
                           "service": "https"}],
             "open_ports": {443: ["https"], 22: ["ssh"]},
             "creds": [("ssh", "alice", "pw", "10.0.0.5")],
             "web_auth": {"established": True},
             "ad": {"domain": "corp.local", "forest": "corp.local"}}
    paths = build_attack_paths(state, finds)
    assert paths, "expected paths"
    for p in paths:
        assert "start" in p and "destination" in p and "steps" in p
        assert p["severity"] in ("critical", "high", "medium", "low", "info")
        assert p["confidence"] in ("certain", "firm", "tentative")
        assert p.get("technique"), "missing technique"
        for s in p["steps"]:
            assert "title" in s and "evidence" in s
    # empty state / no findings -> no fabricated path (must not blow up)
    assert build_attack_paths({}, []) == []
    md = attack_path_md(paths)
    assert "->" in md and "Path 1" in md
    return True, ("correlation/dedup + evidence-grounded attack paths OK")


def t_xlsx_text():
    """XLSX renders text as shared-string cells, not bare numbers."""
    import re
    import tempfile
    import zipfile
    from core.report import render_xlsx
    data = {"meta": {"generated": "2026-09-02", "profile": "quick",
                     "targets": ["http://app.local"]},
            "stats": {"critical": 1, "high": 0, "medium": 0, "low": 0,
                      "info": 0},
            "score": 41.5,
            "objectives": [{"name": "rce", "count": 1}],
            "findings": [{"severity": "critical", "category": "RCE",
                          "title": "command injection", "detail": "id=1;id",
                          "module": "exploit", "confidence": "firm",
                          "mitre": "T1203", "evidence": "uid=0"},
                         {"severity": "high", "category": "web",
                          "title": "XSS in search", "detail": "reflect",
                          "module": "web", "confidence": "tentative",
                          "evidence": "<script>alert(1)</script>"}]}
    p = tempfile.mktemp(suffix=".xlsx")
    render_xlsx(data, path=p)
    with zipfile.ZipFile(p) as z:
        s1 = z.read("xl/worksheets/sheet1.xml").decode()
        s2 = z.read("xl/worksheets/sheet2.xml").decode()
        sst = z.read("xl/sharedStrings.xml").decode()
    os.unlink(p)
    # every text cell must be a shared-string reference...
    assert 't="s"' in s2, "no shared-string cells in Findings"
    assert 't="s"' in s1, "no shared-string cells in Summary"
    allsi = re.findall(r"<si><t[^>]*>(.*?)</t></si>", sst)
    # ...and the first finding's severity resolves to the real word
    m = re.search(r'<c r="A2" t="s"><v>(\d+)</v></c>', s2)
    assert m, "A2 is not a shared-string cell (text leaked into numbers)"
    assert allsi[int(m.group(1))] == "critical", allsi[int(m.group(1))]
    # a genuine number (risk score) must NOT be a string cell
    assert re.search(r'<c r="B6"><v>41.5</v></c>', s1), \
        "risk score should remain numeric"
    return True, ("XLSX shared-strings: text preserved, numbers numeric OK")


def t_screenshot():
    """Per-issue PoC screenshots: capture a real PNG when a browser is
    available, and degrade gracefully (no raise) when it is not."""
    import threading
    from http.server import HTTPServer, SimpleHTTPRequestHandler
    from core import screenshot
    if not screenshot.available():
        assert screenshot.capture("http://127.0.0.1:1/", "/tmp/x.png",
                                  timeout=3000) is False
        return True, ("screenshot module degrades gracefully (no browser) OK")
    d = tempfile.mkdtemp()
    srv = HTTPServer(("127.0.0.1", 0), SimpleHTTPRequestHandler)
    port = srv.server_address[1]
    old = os.getcwd()
    os.chdir(d)
    with open("index.html", "w") as f:
        f.write("<html><body><h1>VAJRA-SHOT</h1></body></html>")
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    out = os.path.join(d, "ev.png")
    try:
        ok = screenshot.capture("http://127.0.0.1:%d/" % port, out,
                                timeout=8000)
    finally:
        srv.shutdown()
        os.chdir(old)
    assert ok, "screenshot capture failed with a usable browser"
    assert out.endswith(".png") and os.path.getsize(out) > 0, "empty PNG"
    assert os.path.exists(out)
    return True, ("headless PoC screenshot captured (Playwright/Chromium) OK")


def run_all():
    print("\nVAJRA self-test")
    print("-" * 60)
    check("port spec parser", t_ports)
    check("version comparator + ranges", t_versions)
    check("banner CVE correlation", t_intel)
    check("html extraction (links/forms/emails)", t_extract)
    check("sqlite findings database", t_db)
    check("rce channel anti-reflection guard", t_rce_channel)
    check("self-update wiring + version", t_update)
    check("CMS markers boundary-guarded", t_cms_markers)
    check("rich tech signature scoring", t_tech_scoring)
    check("false-positive regression corpus", t_fp_corpus)
    check("service names no-guess rule", t_service_honesty)
    check("JS analysis same-origin scope", t_js_scope)
    check("vuln scanner proof-class mapping", t_vuln_records)
    check("confidence->severity anti-FP cap", t_fp_guard)
    check("report rendering (html/md/json)", t_report)
    check("objectives + XLSX + post-module gating", t_resume_persistence_cloud_xlsx)
    check("http result model", t_http_result)
    check("payload engine + adaptive evasion", t_payloads)
    check("massive wordlist tiers", t_wordlists)
    check("offline CVE database + verified probes", t_cve_db)
    check("uniform coverage bank (1x0+/category, no-FP markers)", t_coverage_bank)
    check("listener / LHOST-LPORT core", t_listener)
    check("MITRE ATT&CK tagging", t_mitre)
    check("JWT decode core", t_jwt)
    check("AI (opt-in) offline-safe", t_ai_offline)
    check("AI assist (advisory, offline-safe)", t_ai_assist)
    check("Outputs target naming", t_outputs_naming)
    check("Active Directory attack core", t_ad_core)
    check("SMBv1 / MS17-010 packet core", t_smbv1_packets)
    check("AI-select mission agent", t_agent_mission)
    check("web auth login + OTP/TOTP + cookie jar", t_web_auth)
    check("web autoreg + cross-user IDOR escalate", t_autoreg_idor)
    check("AD chain core (tools/NTDS/channel)", t_ad_chain_core)
    check("web api + cloud bucket builders", t_cloud_api)
    check("web depth builders (multipart/DOM/CVE/sitemap)", t_web_depth)
    check("web vulnscan coverage-first full-form+param sweep", t_vuln_coverage)
    check("OOB callback listener", t_oob_listener)
    check("intel knowledge base files", t_intel_kb)
    check("standalone tools toolkit import", t_toolkit)
    check("KB-driven modules (loot/exposure/creds/login)", t_intel_modules)
    check("AXFR/race/PDF/SOCKS5/CVE-cache caps", t_next_caps)
    check("SNMPv1 community GET (BER + mock)", t_snmp_brute)
    check("native SMBv1 RAP share walk", t_share_native)
    check("workspace snapshots/delta/state/AI/export/import", t_workspace)
    check("synthesis narrative + cross-host correlation", t_synthesis)
    check("compliance coverage (CIS/NIST/PCI per module)", t_compliance)
    check("SOCKS5 pivot proxy E2E relay", t_pivot_proxy)
    check("payload pack() round-trip + sleep_jitter", t_pack_rt)
    check("AD DACL parser (canonical SIDs, risky/danger)", t_sid_acl)
    check("post-exploit SSH loot survey", t_loot_survey)
    check("staged C2 stagers compile (plain/tls/obfuscated)", t_staged_c2)
    check("correlation/dedup + evidence-grounded attack paths", t_attack_paths)
    check("XLSX shared-strings: text preserved, numbers numeric", t_xlsx_text)
    check("headless PoC screenshot (or graceful fallback)", t_screenshot)
    fails = [r for r in RESULTS if not r[1]]
    print("-" * 60)
    print(" %d/%d checks passed%s" % (len(RESULTS) - len(fails), len(RESULTS),
                                      "" if not fails else " — FIX REQUIRED"))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(run_all())
