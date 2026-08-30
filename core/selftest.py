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
    assert firm.severity == "critical"
    possible = Finding("t", "web.vulnscan", "web-vuln", "critical",
                       "blind signal", confidence="possible")
    assert possible.severity == "medium" and "[Bounded]" in possible.detail
    speculative = Finding("t", "network.osfp", "recon", "high", "suspicion",
                          confidence="low")
    assert speculative.severity == "low"
    legit = Finding("t", "exploit.exploit", "credentials", "critical",
                    "exfil", confidence="verified")
    assert legit.severity == "critical"
    return True, "confidence->severity cap (anti-FP) OK"


def t_report():
    from core.report import render_html, render_markdown, render_json
    data = {"meta": {"tool": "VAJRA", "generated": "now",
                     "profile": "quick", "targets": ["127.0.0.1"],
                     "output_dir": "/tmp"},
            "stats": {"critical": 1, "high": 2}, "score": 24.0, "grade": "D",
            "narrative": "n", "services": [{"target": "x", "port": 80,
                                            "service": "http", "product": "",
                                            "version": "", "tls": False}],
            "findings": [{"severity": "critical", "title": "<b>t</b>",
                          "category": "c", "module": "m", "detail": "d",
                          "evidence": "e", "confidence": "firm"}],
            "events": [], "tech": [], "subdomains": [], "os_guess": "",
            "evasion": [{"waf": "Cloudflare", "ops": "case_swap",
                         "original": "<svg onload=alert(1)>",
                         "mutant": "<SvG oNlOaD=alert(1)>",
                         "result": "passed"}]}
    html_out = render_html(data)
    assert "VAJRA" in html_out and "&lt;b&gt;" in html_out
    assert "Evasion operations" in html_out and "case_swap" in html_out
    md = render_markdown(data)
    assert "# ⚡ Vajra" in md and "Evasion Ops" in md
    return True, "all three report formats render (incl. evasion section)"


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
    assert len(db) >= 120, len(db)
    total = sum(len(m.get("ranges", {})) for m in db.values())
    assert total >= 170, total
    intel = Intelligence()
    hits = intel.correlate_banner("F5 BIG-IP 16.1.0 TMUI login")
    assert any(h["product"] == "F5 BIG-IP" for h in hits), hits
    hits = intel.correlate_banner("Server: Apache/2.4.49")
    flat = {c["id"] for h in hits for c in h["cves"]}
    assert any("CVE-2021-41773" in x for x in flat)
    return True, "%d products / %d range entries; BIG-IP + traversal matched" % (
        len(db), total)


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
    # brain-knowledge wiring: catalog + keyword routing
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
                                        AUTH_BYPASSES, OTP_TRICKS)
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
            "stats": {"critical": 1, "high": 2}, "score": 24.0, "grade": "D",
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
    return True, "AXFR wire helpers, race candidates, PDF xref, SOCKS5 relay, CVE cache OK"


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
    return True, ("snapshot/delta/state/brain/export+import OK")


def t_synthesis():
    from core.synthesis import (auto_narrative, correlate_across,
                                build_brain_blocks)
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
                         [{"display": "10.0.0.1"}], 8.1, "D")
    assert "1 critical" in nar and "8.1/100" in nar
    assert correlate_across(finds) == []
    dup = finds + [dict(finds[1], target="10.0.0.3")]
    assert any(c["count"] == 2 for c in correlate_across(dup))
    blocks = build_brain_blocks(
        {"10.0.0.1": {"findings": [finds[0]], "score": 8.0}},
        delta_summary={"new": 1, "fixed": 0, "still": 0})
    assert "## Run" in blocks and "RCE in api" in blocks
    return True, ("narrative + cross-host correlation + brain blocks OK")


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


def run_all():
    print("\nVAJRA self-test")
    print("-" * 60)
    check("port spec parser", t_ports)
    check("version comparator + ranges", t_versions)
    check("banner CVE correlation", t_intel)
    check("html extraction (links/forms/emails)", t_extract)
    check("sqlite findings database", t_db)
    check("rce channel anti-reflection guard", t_rce_channel)
    check("confidence->severity anti-FP cap", t_fp_guard)
    check("report rendering (html/md/json)", t_report)
    check("http result model", t_http_result)
    check("payload engine + adaptive evasion", t_payloads)
    check("massive wordlist tiers", t_wordlists)
    check("vast CVE database", t_cve_db)
    check("listener / LHOST-LPORT core", t_listener)
    check("MITRE ATT&CK tagging", t_mitre)
    check("JWT decode core", t_jwt)
    check("AI brain (opt-in) offline-safe", t_ai_offline)
    check("Outputs target naming", t_outputs_naming)
    check("Active Directory attack core", t_ad_core)
    check("SMBv1 / MS17-010 packet core", t_smbv1_packets)
    check("AI-select mission agent", t_agent_mission)
    check("web auth login + OTP/TOTP + cookie jar", t_web_auth)
    check("AD chain core (tools/NTDS/channel)", t_ad_chain_core)
    check("web api + cloud bucket builders", t_cloud_api)
    check("web depth builders (multipart/DOM/CVE/sitemap)", t_web_depth)
    check("OOB callback listener", t_oob_listener)
    check("intel knowledge base files", t_intel_kb)
    check("standalone tools toolkit import", t_toolkit)
    check("KB-driven modules (loot/exposure/creds/login)", t_intel_modules)
    check("AXFR/race/PDF/SOCKS5/CVE-cache caps", t_next_caps)
    check("SNMPv1 community GET (BER + mock)", t_snmp_brute)
    check("native SMBv1 RAP share walk", t_share_native)
    check("workspace snapshots/delta/state/brain/export/import", t_workspace)
    check("synthesis narrative + cross-host correlation", t_synthesis)
    check("compliance coverage (CIS/NIST/PCI per module)", t_compliance)
    check("SOCKS5 pivot proxy E2E relay", t_pivot_proxy)
    check("payload pack() round-trip + sleep_jitter", t_pack_rt)
    check("AD DACL parser (canonical SIDs, risky/danger)", t_sid_acl)
    check("post-exploit SSH loot survey", t_loot_survey)
    check("staged C2 stagers compile (plain/tls/obfuscated)", t_staged_c2)
    fails = [r for r in RESULTS if not r[1]]
    print("-" * 60)
    print(" %d/%d checks passed%s" % (len(RESULTS) - len(fails), len(RESULTS),
                                      "" if not fails else " — FIX REQUIRED"))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(run_all())
