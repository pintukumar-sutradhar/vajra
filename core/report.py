"""Vajra - report generation: interactive HTML dashboard, JSON, Markdown."""
import datetime
import json
import os
from string import Template

from core.database import SEV_ORDER, SEV_WEIGHT
from core.utils import PROJECT_ROOT


def _poc_text(f):
    """PoC / Evidence text for a finding — the observed proof. Falls back to
    the recorded detail so the PoC cell is never an unexplained blank: a
    finding without either is not something we can honestly stand behind."""
    for key in ("evidence", "detail", "title"):
        val = (f.get(key) or "").strip()
        if val:
            return val
    return ""


def _evidence_urls(f):
    """All http(s) URLs mentioned in a finding's own evidence/detail."""
    import re as _re
    text = "%s %s" % ((f.get("evidence") or ""), (f.get("detail") or ""))
    out, seen = [], set()
    for m in _re.findall(r"https?://[^\s\"'<>\)\]]+", text):
        u = m.rstrip("),.;!?]\"")
        if u.startswith(("http://", "https://")) and u not in seen:
            seen.add(u)
            out.append(u)
    return out[:5]


def _target_host(f):
    try:
        from urllib.parse import urlsplit
        t = (f.get("target") or "").strip()
        if t.startswith(("http://", "https://")):
            return urlsplit(t).netloc
    except Exception:
        pass
    return "<TARGET>"


def _repro(f):
    """(command, [plain-language steps]) for the report's Proof-of-Concept
    block. Returns ("", []) when no meaningful reproduction exists — info
    findings and protocol-only leads are exempt (they have no web PoC)."""
    import re as _r
    sev = f.get("severity", "")
    if sev == "info":
        return "", []
    text = "%s %s %s" % (f.get("title", ""), f.get("detail", ""),
                         f.get("evidence", ""))
    tl = text.lower()
    target = (f.get("target") or "").strip().rstrip("/")
    host = _target_host(f)
    root = (target + "/") if target else "%s/" % host

    if "zone transfer" in tl:
        m = _r.search(r"\(([a-z0-9][a-z0-9.-]*\.)\)",
                      f.get("title") or "") or \
            _r.search(r"nameserver\s+([a-z0-9][a-z0-9.-]*\.)",
                      text)
        ns = (m.group(1) if m else "ns1.<DOMAIN>")
        dom = host.split(":")[0]
        cnt = "" 
        mc = _r.search(r"(\d+)\s*record", text)
        if mc:
            cnt = " — this target disclosed %s record(s)" % mc.group(1)
        return ("dig @%s %s AXFR" % (ns, dom),
                ["Send a DNS zone-transfer request to the authoritative "
                 "nameserver for the domain.",
                 "An AXFR-capable server replies with the full zone instead "
                 "of an error, handing any outsider the complete hostname "
                 "map.%s." % cnt])

    if ("host header" in tl) or ("cache poisoning" in tl):
        m = _r.search(r"https?://([^\s\"'<>\)\]]+)",
                      f.get("evidence") or "")
        atk = "vajra-oob.example"
        if m:
            try:
                from urllib.parse import urlsplit
                atk = urlsplit(m.group(0)).netloc
            except Exception:
                pass
        return ("curl -sk -H 'Host: %s' -i %s" % (atk, root),
                ["Replay a request whose Host header names a domain the "
                 "attacker controls.",
                 "Values from that Host header that are echoed back into the "
                 "page (here an `og:image` meta tag) prove the server trusts "
                 "attacker-supplied Host values — the prerequisite for "
                 "web-cache poisoning."])

    if ("discovered application path" in tl) or ("path/file" in tl):
        urls = _evidence_urls(f)
        if urls:
            lines = "\n".join(
                "curl -s -o /dev/null -w '%%{http_code} %%{url_effective}"
                "\\n' %r" % u for u in urls)
            return (lines,
                    ["Request every endpoint that the scan listed as "
                     "reachable (they appear in the proof block).",
                     "Each one that answers instead of a flat 404 is an "
                     "exposed asset that should be reviewed or removed."])

    if "security header" in tl:
        return ("curl -skI %s | grep -i '^[a-z]'" % root,
                ["Fetch the full response header set of the site root.",
                 "Compare it with the recommended headers in 'What we found' "
                 "— every one missing from the reply is a hardening gap."])

    if ("server version" in tl) or ("technology fingerprint" in tl) \
            or ("known cve" in tl):
        return ("curl -skI %s | grep -i '^server'" % root,
                ["Fetch the server banner of the site root.",
                 "The exact build (seen in the proof block) lets attackers "
                 "match public exploits — the CVEs for this version are "
                 "listed in the section above."])

    urls = _evidence_urls(f)
    if urls:
        return ("curl -skI %s" % urls[0],
                ["Replay the exact request the scanner made — the one shown "
                 "in the proof block below.",
                 "The observed reply from the server is reproduced verbatim "
                 "there, so the finding can be validated and then retested "
                 "after the fix."])

    return "", []


# Red-team mission objectives and how to recognise each from a finding.
# Each rule is a (category, substrings-in-title-or-detail) probe; a finding
# that matches is evidence the objective was (at least partially) achieved.
OBJECTIVE_RULES = [
    ("Remote Code Execution",
     ["rce", "command execution", "command injection", "code execution",
      "web shell", "reverse session", "execution channel", "webshell",
      "RCE"]),
    ("Credentials Captured",
     ["credentials", "credential", "cracked", "hash", "password", "creds",
      "kerberoast", "ntds", "pth", "default credential", "golden", "silver"]),
    ("Domain / AD Compromise",
     ["domain admin", "dc-sync", "dacl", "lateral", "kerberoast", "admincount",
      "trust", "smb", "ms17", "pass-the-hash", "golden ticket",
      "silver ticket", "ldap"]),
    ("Persistence Established",
     ["persistence", "implant", "schtasks", "cron", "systemd", "registry-run",
      "authorized_key", "web-root persistence"]),
    ("Cloud Compromise",
     ["cloud", "bucket", "aws", "azure", "gcs", "sts", "s3", "cloud key",
      "cloud cred", "identity"]),
    ("Sensitive Data Read",
     ["secret", "key material", "private key", "token", "ssrf", "lfi",
      "file read", "exfiltration", "env file", "data extraction", ".env",
      "backup", "dump"]),
    ("Web Application Pwned",
     ["sqli", "xss", "xxe", "ssti", "authentication bypass", "sql injection",
      "csrf", "idor", "bola", "upload", "open redirect"]),
    ("Network Pivot / Egress",
     ["pivot", "socks5", "tunnel", "connect-proxy", "egress", "port scan",
      "ssrf_pivot"]),
]


def objectives(findings, state=None):
    """Derive which red-team objectives were (at least partially) achieved,
    based only on findings whose evidence is present and whose confidence is
    firm/certain. Returns a list of dicts: {name, achieved, count, examples}.
    A naive objective is only counted once per distinct supported finding."""
    got = {}
    seen = set()
    state = state or {}
    for f in findings:
        conf = (f.get("confidence") or "").lower()
        if conf not in ("firm", "certain"):
            continue
        blob = ("%s %s %s %s" % (f.get("title", ""), f.get("detail", ""),
                                 f.get("category", ""), f.get("module", ""))).lower()
        for name, probes in OBJECTIVE_RULES:
            if any(p.lower() in blob for p in probes):
                key = (name, f.get("title", ""))
                if key in seen:
                    continue
                seen.add(key)
                e = got.setdefault(name, {"name": name, "count": 0,
                                          "examples": []})
                e["count"] += 1
                if len(e["examples"]) < 5:
                    e["examples"].append(f.get("title", ""))
    # Cloud objective can also be inferred when cloud creds were validated
    # even if no finding title matched a cloud probe (belt-and-braces).
    if not got.get("Cloud Compromise") and state.get("cloud_creds"):
        got["Cloud Compromise"] = {"name": "Cloud Compromise", "count": 1,
                                   "examples": ["on-host cloud credentials "
                                                "validated"]}
    return list(got.values())

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Assessment Report - $targets</title>
<style>
 :root{--ink:#1a1a24;--mut:#5b6472;--line:#d5dae3;--bg:#f4f6fa;--card:#ffffff;
       --crit:#d40000;--high:#dd4b00;--med:#b45309;--low:#1d6fb8;--info:#5b6472;
       --accent:#17365d;--accent2:#ffffff;}
 *{box-sizing:border-box;margin:0;padding:0;}
 body{background:var(--bg);color:var(--ink);font:14px/1.6 'Segoe UI',Arial,Helvetica,sans-serif;}
 .page{max-width:1040px;margin:0 auto;padding:36px 42px;background:var(--card);
   box-shadow:0 0 24px rgba(20,30,60,.06);}
 h1{font-size:26px;color:var(--accent);letter-spacing:.4px;}
 h2{font-size:19px;color:var(--accent);margin:34px 0 4px;padding-bottom:8px;
   border-bottom:2px solid var(--accent);}
 h2 .no{color:#93a3b8;margin-right:8px;}
 h3{font-size:16px;}
 .meta{border-top:3px solid var(--accent);margin-top:4px;padding-top:14px;}
 .meta table{border-collapse:collapse;width:100%;}
 .meta td{padding:5px 18px 5px 0;vertical-align:top;}
 .meta td:first-child{width:170px;color:var(--mut);text-transform:uppercase;
   font-size:11px;letter-spacing:1px;}
 .riskline{margin:18px 0 4px;}
 .bar{height:12px;width:100%;background:#e8ecf2;border-radius:6px;overflow:hidden;margin-top:6px;}
 .bar i{display:block;height:100%;background:#dd4b00;}
 .finds-band{margin-top:20px;}
 .finds-band table{border-collapse:collapse;width:100%;}
 .finds-band td{padding:8px 16px 8px 0;vertical-align:top;}
 .k{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--mut);}
 .v{font-size:26px;font-weight:700;color:var(--accent);}
 .pill{display:inline-block;padding:3px 12px;border-radius:14px;font-size:12px;
   font-weight:600;color:#fff;text-transform:uppercase;letter-spacing:.5px;}
 .pill.critical{background:var(--crit)} .pill.high{background:var(--high)}
 .pill.medium{background:var(--med)} .pill.low{background:var(--low)}
 .pill.info{background:var(--info)} .pill.ghost{background:#e8ecf2;color:#3a4250;text-transform:none;}
 .narr{white-space:pre-wrap;}
 .muted{color:var(--mut);}
 .small{font-size:12px;}
 table.data{width:100%;border-collapse:collapse;margin-top:10px;}
 table.data th{background:#eef1f6;text-align:left;padding:8px 12px;font-size:11px;
   text-transform:uppercase;letter-spacing:.6px;color:#40505f;border:1px solid var(--line);}
 table.data td{padding:8px 12px;border:1px solid var(--line);vertical-align:top;}
 .chip{display:inline-block;background:#eef1f6;border-radius:12px;padding:2px 10px;
   margin:2px 4px 2px 0;font-size:12px;color:#2b3440;}
 article.finding{border:1px solid var(--line);border-left:6px solid var(--line);
   border-radius:8px;padding:18px 24px;margin:18px 0;background:#fff;page-break-inside:avoid;}
 article.finding.sev-critical{border-left-color:var(--crit)}
 article.finding.sev-high{border-left-color:var(--high)}
 article.finding.sev-medium{border-left-color:var(--med)}
 article.finding.sev-low{border-left-color:var(--low)}
 article.finding.sev-info{border-left-color:var(--info)}
 .f-head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:10px;}
 .f-head h3{flex:1;min-width:260px;}
 .fld{margin:10px 0;}
 .fld b{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.7px;
   color:#40505f;margin-bottom:3px;}
 .lead{background:#fff7e6;border:1px solid #f2d199;color:#8a5a00;border-radius:6px;
   padding:8px 12px;margin:8px 0;font-size:13px;}
 ol.poc{margin:6px 0 10px 20px;}
 ol.poc li{margin:4px 0;}
 pre{background:#0e1420;color:#d9e2ef;border-radius:6px;padding:12px 14px;
   overflow:auto;font:12.5px/1.55 ui-monospace,Consolas,'Cascadia Mono',monospace;
   white-space:pre-wrap;word-break:break-word;}
 pre.proof{max-height:320px;}
 figure{margin:12px 0;}
 figure img{max-width:520px;max-height:520px;border:1px solid var(--line);
   border-radius:6px;display:block;}
 figcaption{font-size:12px;color:var(--mut);margin-top:6px;}
 footer{margin-top:36px;border-top:2px solid var(--accent);padding-top:14px;
   color:var(--mut);font-size:12px;line-height:1.7;}
 .toc{margin-top:6px;}
 .toc a{color:#17365d;text-decoration:none;}
 .toc li{margin:3px 0;}
 @media print{ body{background:#fff;} .page{box-shadow:none;padding:0;max-width:none;}
   article.finding{page-break-inside:avoid;} }
</style>
</head>
<body>
<div class="page">
 <h1>Security Assessment Report</h1>
 <div class="sub muted" style="margin-top:2px">Automated vulnerability assessment
   &bull; $targets</div>

 <div class="meta">
  <table>
   <tr><td>Prepared for</td><td><b>[Client name]</b></td></tr>
   <tr><td>Assessment of</td><td><b>$targets</b></td></tr>
   <tr><td>Date of assessment</td><td>$date</td></tr>
   <tr><td>Assessment type</td><td>$profile</td></tr>
   <tr><td>Overall risk</td><td><b>$score / 100</b> (of $total findings)</td></tr>
  </table>
  <div class="riskline muted small">Overall risk score</div>
  <div class="bar"><i style="width:$scorewidth%"></i></div>
 </div>

 <div class="finds-band">
  <table>
   <tr>
    <td><div class="k">Critical</div><div class="v" style="color:var(--crit)">$crit</div></td>
    <td><div class="k">High</div><div class="v" style="color:var(--high)">$high</div></td>
    <td><div class="k">Medium</div><div class="v" style="color:var(--med)">$medium</div></td>
    <td><div class="k">Low</div><div class="v" style="color:var(--low)">$low</div></td>
    <td><div class="k">Info</div><div class="v" style="color:var(--info)">$info</div></td>
    <td><div class="k">Total</div><div class="v">$total</div></td>
   </tr>
  </table>
 </div>

 <h2><span class="no">1.</span>Executive summary</h2>
 <div class="narr">$narrative</div>

 <h2><span class="no">2.</span>CVEs found on your systems</h2>
 <div class="small muted">Every technology recognised during the assessment is
   listed with the known-issue matches found for its version. Each CVE links to
   the National Vulnerability Database.</div>
 $cve_sections

 <h2><span class="no">3.</span>Services and open ports</h2>
 $services_table

 <h2><span class="no">4.</span>Findings and proof of concept</h2>
 <div class="small muted">Each finding states where it was seen, what was
   found, how to reproduce it (step by step), the exact proof the scan
   observed, and the recommended fix. </div>
 $finding_cards

 <h2><span class="no">5.</span>Recommended fixes</h2>
 $remediation

 <h2><span class="no">6.</span>Severity definitions</h2>
 <table class="data">
  <tr><th style="width:100px">Level</th><th>What it means</th></tr>
  <tr><td><span class="pill critical">critical</span></td><td>Emergency — an attacker could probably take control of the system or steal data with little effort. Fix immediately.</td></tr>
  <tr><td><span class="pill high">high</span></td><td>Urgent — a serious weakness most attackers could exploit. Fix as soon as possible.</td></tr>
  <tr><td><span class="pill medium">medium</span></td><td>Plan a fix — exploitable only under certain conditions or by a skilled attacker.</td></tr>
  <tr><td><span class="pill low">low</span></td><td>Minor — a small hardening gap. Fix when convenient.</td></tr>
  <tr><td><span class="pill info">info</span></td><td>Information only — not a vulnerability by itself.</td></tr>
 </table>

 <footer>
  <b>Confidential.</b> This report is intended for the owner of the assessed
  systems.<br>
  Confidence labels: <b>Certain</b> = proven end-to-end &bull; <b>Firm</b> =
  strong evidence &bull; <b>Tentative</b> = unverified lead, treat as a signal
  to confirm, never as a confirmed finding.<br>
  Unverified signals are reported only at low/info levels, never as
  critical/high. Validate key findings manually before remediation. Testing
  systems without written authorization is illegal.<br>
  Generated: $date
 </footer>
</div>
</body>
</html>"""


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _measured_web_services(data):
    """When the service scanner stored nothing, reconstruct an honest
    'what was actually measured' row from the web findings — e.g. the nginx
    banner and the URL scheme/port. Prevents the contradiction of a report
    that says 'no service reachable' on the same page where the web app was
    crawled and fingerprinted."""
    import re as _re
    from urllib.parse import urlsplit
    rows = []
    targets = (data.get("meta", {}) or {}).get("targets", []) or []
    for f in data.get("findings", []) or []:
        tl = ((f.get("title") or "") + " " + (f.get("detail") or "")).lower()
        if "server version" not in tl and "technology fingerprint" not in tl:
            continue
        ev = (f.get("evidence") or "") or (f.get("detail") or "")
        prod, ver = "", ""
        m = _re.search(r"server[:\s]+([a-z0-9][a-z0-9._-]*)\s*(?:/([\d][\w.]*))?",
                       ev.lower())
        if m:
            prod, ver = m.group(1), m.group(2) or ""
        tgt = (f.get("target") or (targets[0] if targets else ""))
        if not tgt or not tgt.startswith(("http://", "https://")):
            continue
        try:
            parts = urlsplit(tgt)
            port = parts.port or (443 if parts.scheme == "https" else 80)
            scheme = parts.scheme or "http"
        except Exception:
            port, scheme = 443, "https"
        rows.append({"target": tgt, "port": port,
                     "service": "https" if scheme == "https" else "http",
                     "product": prod or "-", "version": ver or "-"})
    if not rows and targets:
        tc = (data.get("tech_cves") or {})
        for t in targets:
            if not t.startswith(("http://", "https://")):
                continue
            try:
                parts = urlsplit(t)
                port = parts.port or (443 if parts.scheme == "https" else 80)
                prod = ""
                ver = ""
                if tc:
                    k = sorted(tc)[0]
                    prod = k.title()
                    ver = (tc[k].get("version") or "") or ""
            except Exception:
                port, prod, ver = 443, "", ""
            rows.append({"target": t, "port": port,
                         "service": "https" if parts.scheme == "https"
                         else "http",
                         "product": prod or "-", "version": ver or "-"})
    seen = set()
    deduped = []
    for r in rows:
        k = (r["target"], r["port"], r["service"])
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)
    return deduped


def build_data(engine):
    stats = engine.db.stats()
    findings = engine.db.findings()
    services = engine.db.services()
    events = engine.db.events()
    targets = [t.display for t in engine.targets]
    narrative = engine.intel.summarize(stats, findings, services,
                                       [{"display": d} for d in targets])
    score = engine.intel.score(findings)
    try:
        from core.attackpath import correlate_findings, build_attack_paths
        correlated = correlate_findings(findings)
        paths = build_attack_paths(engine.state, findings)
    except Exception:
        correlated, paths = [], []
    return {
        "meta": {"tool": "VAJRA",
                 "generated": datetime.datetime.now().isoformat(timespec="seconds"),
                 "profile": engine.profile,
                 "targets": targets,
                 "output_dir": str(engine.outdir)},
        "stats": stats,
        "score": score,
        "narrative": narrative,
        "services": services,
        "findings": findings,
        "events": events,
        "tech": sorted(set(engine.state.get("tech", []) or [])),
        "tech_cves": dict(engine.state.get("tech_cves", {}) or {}),
        "evidence_dir": str(engine.state.get("evidence_dir") or ""),
        "subdomains": engine.state.get("subdomains", []),
        "os_guess": engine.state.get("os_guess", ""),
        "evasion": list(getattr(engine, "evasion_all", []))[:150],
        "objectives": objectives(findings, getattr(engine, "state", {})),
        "correlated": correlated,
        "attack_paths": paths,
    }


def render_html(data):
    """Professional self-contained HTML report: plain-language, print-ready,
    findings presented as cards with step-by-step proofs."""
    stats = data["stats"]
    findings = data["findings"]
    total = len(findings)

    _services = data.get("services") or _measured_web_services(data)
    if _services:
        srows = "".join(
            '<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td>'
            '<td>%s</td></tr>' % (
                _esc(s["target"]), _esc(str(s["port"])),
                _esc(s["service"]),
                _esc(s.get("product") or "-"),
                _esc(s.get("version") or "-"))
            for s in _services)
        services_table = ('<table class="data"><tr><th>Target</th><th>Port</th>'
                          '<th>Service</th><th>Product</th><th>Version</th></tr>'
                          '%s</table>' % srows)
    else:
        services_table = ('<div class="muted">No reachable service was '
                          'recorded for this target range.</div>')

    cards = "".join(_finding_card(data, i, f)
                    for i, f in enumerate(findings)) if findings else \
        '<div class="muted">No findings recorded.</div>'

    score = min(100.0, max(0.0, float(data.get("score") or 0)))
    rem = _render_remediation(data.get("remediation", [])) or \
        '<div class="muted">No specific fix list was produced — the fix ' \
        'recommendations inside each finding card above apply.</div>'

    tpl = Template(HTML_TEMPLATE)
    return tpl.substitute(
        date=_esc(data["meta"]["generated"]),
        profile=_esc(data.get("meta", {}).get("profile", "default")),
        targets=_esc(", ".join(data.get("meta", {}).get("targets", []) or []))[:90],
        score="%.1f" % score, scorewidth=str(int(score)),
        crit=stats.get("critical", 0), high=stats.get("high", 0),
        medium=stats.get("medium", 0), low=stats.get("low", 0),
        info=stats.get("info", 0), total=total,
        narrative=_esc(data["narrative"]),
        cve_sections=_cve_sections_html(data.get("tech_cves") or {}),
        services_table=services_table,
        finding_cards=cards,
        remediation=rem)


def _finding_card(data, i, f):
    """One professional finding card: severity + confidence header, location,
    description, step-by-step PoC, observed proof (output + screenshot), fix."""
    sev = f.get("severity", "info")
    conf = (f.get("confidence") or "").lower()
    conf_short = _esc((f.get("confidence") or "-").title())
    title = _esc(f["title"])
    lead = ""
    if conf in ("tentative", "possible"):
        lead = ('<div class="lead"><b>Unverified lead.</b> This signal may be '
                'real or a false alarm — confirm it manually before acting on '
                'it.</div>')

    where_target = _esc(f.get("target") or "")
    if ("host header" in (f.get("title") or "").lower()) or \
            ("cache poisoning" in (f.get("title") or "").lower()):
        loc = where_target
    else:
        loc = _esc(_first_url(f.get("evidence")) or where_target)

    bits = ['<div class="fld"><b>Location</b>%s</div>' % loc]
    if f.get("detail"):
        bits.append('<div class="fld"><b>What we found</b><div>%s</div></div>'
                    % _esc(f["detail"][:1600]))

    cmd, steps = _repro(f)
    if cmd and steps:
        ol = "".join("<li>%s</li>" % _esc(s) for s in steps)
        bits.append('<div class="fld"><b>Proof of concept — how to reproduce</b>'
                    '<ol class="poc">%s</ol></div>' % ol)
        bits.append('<div class="fld"><b>Command</b>'
                    '<pre>%s</pre></div>' % _esc(cmd))

    poc = _poc_text(f)
    if poc:
        bits.append('<div class="fld"><b>Observed proof (what the scan saw)'
                    '</b><pre class="proof">%s</pre></div>'
                    % _esc(poc[:2400]))
    shot = _evidence_png_rel(data, i, f["title"])
    if shot:
        bits.append(
            '<figure><a href="%s" target="_blank"><img src="%s" '
            'alt="Proof screenshot for: %s"></a>'
            '<figcaption>Proof screenshot — rendering of the reproduced '
            'request above.</figcaption></figure>' % (shot, shot,
                                                      title.replace('"', "")))
    if f.get("remediation"):
        bits.append('<div class="fld"><b>Recommended fix</b><div>%s</div>'
                    '</div>' % _esc(f["remediation"]))

    head = ('<div class="f-head"><span class="pill %s">%s</span>'
            '<h3>%s</h3>'
            '<span class="pill ghost">confidence: %s</span></div>'
            % (sev, sev.capitalize(), title, conf_short))
    return ('<article class="finding sev-%s">%s%s%s</article>'
            % (sev, head, lead, "".join(bits)))


def _cve_sections_html(tech_cves):
    if not tech_cves:
        return '<div class="narr muted">No technology-to-CVE matches were ' \
               'found for any detected component (or no version was ' \
               'fingerprinted).</div>'
    blocks = []
    for tech in sorted(tech_cves):
        rec = tech_cves[tech]
        if not rec or not rec.get("cves"):
            continue
        rows = []
        for c in rec["cves"]:
            cve = c.get("id", "") or "-"
            cvss = c.get("cvss", "") or "-"
            rows.append('<tr><td><code>%s</code></td><td>%s</td><td>%s</td>'
                        '<td><a href="%s" target="_blank" '
                        'class="muted">View &rarr;</a></td></tr>' % (
                            _esc(cve), _esc(str(cvss)),
                            _esc((c.get("summary") or "")[:200]),
                            _esc(_nvd_url(cve))))
        blocks.append('<div class="card" style="margin-bottom:12px">'
                      '<b style="color:#f78166">%s</b> '
                      '<span class="muted">version %s</span>'
                      '<table style="margin-top:8px"><tr><th>CVE ID</th>'
                      '<th>CVSS</th><th>Summary</th><th>Details</th></tr>'
                      '%s</table></div>' % (
                          _esc(tech.title()), _esc(rec.get("version") or "?"),
                          "".join(rows)))
    return "".join(blocks) or '<div class="muted">No CVE matches.</div>'


def attack_paths_html(paths):
    if not paths:
        return ('<div class="narr muted">No evidence-grounded attack paths '
                'were derived — nothing to chain.</div>')
    blocks = []
    for i, p in enumerate(paths, 1):
        step_rows = "".join(
            '<tr><td><b>%s</b></td><td><code>%s</code></td><td>%s</td></tr>' % (
                _esc(s["title"]), _esc(s.get("technique", "-")),
                _esc("; ".join(s.get("evidence", []))[:200] or "-"))
            for s in p.get("steps", []))
        blocks.append(
            '<div class="card" style="margin-bottom:12px">'
            '<div><span class="sev %s">%s</span> '
            '<b style="color:#f78166">Path %d:</b> %s '
            '<span class="muted">&rarr;</span> %s</div>'
            '<div class="muted" style="margin:6px 0">confidence=%s &nbsp;|&nbsp; '
            'privilege: %s &nbsp;|&nbsp; technique: <code>%s</code></div>'
            '<table><tr><th>Step</th><th>Technique</th><th>Evidence</th></tr>'
            '%s</table></div>' % (
                _esc(p.get("severity", "info")), _esc(p.get("severity", "info")),
                i, _esc(p.get("start", "")), _esc(p.get("destination", "")),
                _esc(p.get("confidence", "-")),
                _esc(p.get("privilege_gained", "-")),
                _esc(p.get("technique", "-")), step_rows))
    return "".join(blocks)


def correlated_html(corr):
    if not corr:
        return ""
    rows = []
    for c in corr:
        if not c.get("key"):
            continue
        plural = "s" if c.get("title_count", 1) > 1 else ""
        rows.append(
            '<tr><td><span class="sev %s">%s</span></td>'
            '<td><b>%s</b><br><span class="muted">%s</span></td>'
            '<td>%s</td>'
            '<td>%d finding%s</td>'
            '<td><code>%s</code></td></tr>' % (
                _esc(c.get("severity", "info")), _esc(c.get("severity", "info")),
                _esc(c.get("label", "")), _esc(c.get("target", "")),
                "; ".join(_esc(t[:70]) for t in c.get("titles", [])[:3]),
                c.get("title_count", 1), plural,
                _esc(c.get("technique", "")) if c.get("technique") else "-"))
    if not rows:
        return ""
    return ('<div style="margin-top:14px"><b>Correlated findings '
            '(one issue, many detection sources):</b>'
            '<table style="margin-top:8px"><tr><th>Sev</th><th>Issue</th>'
            '<th>Evidence titles</th><th>Sources</th><th>MITRE</th></tr>%s'
            '</table></div>' % "".join(rows))


def objectives_html(objs):
    if not objs:
        return '<div class="narr muted">No confirmed compromise objectives ' \
               'were achieved on this target — no proof-tested findings ' \
               'matched a mission objective.</div>'
    rows = []
    for o in objs:
        chips = "".join('<span class="chip">%s</span>' % _esc(e)
                        for e in o["examples"])
        rows.append(
            '<div class="card" style="margin-bottom:10px">'
            '<b style="color:#f78166">%s</b> '
            '<span class="muted">(%d supporting finding(s))</span><br>%s'
            '</div>' % (_esc(o["name"]), o["count"], chips))
    return "".join(rows)


def objectives_md(objs):
    if not objs:
        return "No confirmed compromise objectives were achieved on this " \
               "target (no proof-tested finding matched a mission objective)."
    lines = ["| Objective | Supporting findings |", "|---|---|"]
    for o in objs:
        stub = "; ".join(o["examples"][:3])
        lines.append("| %s | %d — %s |" % (o["name"], o["count"], stub))
    lines.append("")
    return "\n".join(lines)


def _render_remediation(sections):
    if not sections:
        return ""
    rows = []
    for sec in sections:
        body = []
        for it in sec.get("items", [])[:50]:
            body.append('<tr><td><b>%s</b></td><td>%s</td></tr>'
                          % (_esc(it["title"]), _esc(it["remediation"])))
        if not body:
            continue
        rows.append('<h3 style="color:%s">%s — %s</h3>'
                      % (_SEV_HEX.get(sec["severity"], "#17365d"),
                         sec["severity"].upper(), sec.get("priority", "")))
        rows.append('<table class="data"><tr><th>Finding</th>'
                    '<th>Recommended fix</th></tr>' +
                      "".join(body) + "</table>")
    return "".join(rows)


# --- human-friendly report helpers -------------------------------------------

def _slugify(s):
    import re as _re
    s = _re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_")[:48]
    return s or "finding"


_SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡",
             "low": "🔵", "info": "⚪"}

_SEV_MEANS = {
    "critical": "Emergency. An attacker could probably take control of the "
                "system or steal data with little effort. Fix immediately.",
    "high": "Urgent. A serious weakness that most attackers could exploit. "
            "Fix as soon as possible.",
    "medium": "Plan a fix. Exploitable only under certain conditions or by a "
              "skilled attacker. Fix in the next release.",
    "low": "Minor. A small hardening gap. Fix when convenient.",
    "info": "Information only. Not a vulnerability by itself, but useful to "
            "know.",
}

_CONF_MEANS = {
    "certain": "Certain — the check was proven end-to-end.",
    "firm": "Firm — strong evidence the issue is real.",
    "tentative": "Unverified lead — a signal that may be real or a false "
                 "alarm; confirm it before acting.",
    "possible": "Unverified lead — a signal that may be real or a false "
                "alarm; confirm it before acting.",
}

_SEV_HEX = {"critical": "#d40000", "high": "#dd4b00", "medium": "#b45309",
            "low": "#1d6fb8", "info": "#5b6472"}


def _nvd_url(cve_id):
    if not cve_id:
        return ""
    return "https://nvd.nist.gov/vuln/detail/%s" % cve_id


def _first_url(text):
    import re as _re
    m = _re.search(r"https?://[^\s\"'<>\)\]]+", str(text or ""))
    return m.group(0) if m else ""


def _evidence_png(data, index, title):
    """Absolute path of the proof screenshot for a finding, or '' if none.
    The per-issue PNGs are written by the engine as evidence/fNNN_<slug>.png
    in the same folder as the report."""
    evdir = data.get("evidence_dir") or ""
    if not evdir:
        return ""
    slug = _slugify(title)
    cand = os.path.join(evdir, "f%03d_%s.png" % (index + 1, slug))
    if os.path.isfile(cand):
        return cand
    return ""


def _evidence_png_rel(data, index, title):
    """Path of a finding's proof screenshot relative to the report file
    (report.md/html live in the same folder as evidence/)."""
    png = _evidence_png(data, index, title)
    if not png:
        return ""
    repdir = os.path.dirname(data.get("evidence_dir") or "")
    if repdir:
        return os.path.relpath(png, repdir)
    return os.path.basename(png)


def _md_sev_line(sev, conf, title):
    icon = _SEV_ICON.get(sev, "⚪")
    conf_note = (" _(%s)_" % _CONF_MEANS.get((conf or "").lower(),
                                             str(conf or "")))
    return "%s **%s**%s" % (icon, title, conf_note)


def _cve_sections_md(tech_cves):
    """Per-technology CVE table — the 'show me the CVEs again for each tech'
    requirement."""
    if not tech_cves:
        return ""
    out = ["## CVEs found on your systems", "",
           "Every technology detected during the assessment is listed here "
           "with the known-issue matches found for its version. Each CVE has "
           "a link to the National Vulnerability Database for details.",
           ""]
    for tech in sorted(tech_cves):
        rec = tech_cves[tech]
        if not rec or not rec.get("cves"):
            continue
        ver = rec.get("version") or "?"
        out.append("### %s — version %s" % (tech.title(), ver))
        out.append("")
        out.append("| CVE ID | Severity (CVSS) | Summary | Details |")
        out.append("|---|---|---|---|")
        for c in rec["cves"]:
            cve = c.get("id", "") or ""
            cvss = c.get("cvss", "") or ""
            ref = _nvd_url(cve)
            out.append("| %s | %s | %s | [View](%s) |" % (
                cve or "-", cvss or "-",
                (c.get("summary") or "").replace("|", "/")[:220] or "-",
                ref))
        out.append("")
    return "\n".join(out)


def render_markdown(data):
    stats = data["stats"]
    findings = data["findings"]
    lines = []
    lines.append("# Security Assessment Report")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append("| Target | %s |" % ", ".join(data["meta"]["targets"]))
    lines.append("| Assessment date | %s |" % data["meta"]["generated"])
    lines.append("| Assessment type | %s |" % data["meta"]["profile"])
    lines.append("| Overall risk | **%.1f / 100** |" % data["score"])
    lines.append("| Findings | %d critical · %d high · %d medium · %d low "
                 "· %d info |"
                 % tuple(stats.get(s, 0) for s in SEV_ORDER))
    lines.append("")
    lines.append("## 1. Executive summary")
    lines.append("")
    lines.append(data["narrative"].replace("\n\n", "\n") if data["narrative"]
                 else "_No summary available._")
    lines.append("")

    cves_md = _cve_sections_md(data.get("tech_cves") or {})
    if cves_md:
        lines.append(cves_md)
        lines.append("")

    lines.append("## 2. Services and open ports")
    lines.append("")
    services = data.get("services") or _measured_web_services(data)
    if services:
        lines.append("| Target | Port | Service | Product | Version |")
        lines.append("|---|---|---|---|---|")
        for s in services:
            lines.append("| %s | %s | %s | %s | %s |" % (
                s["target"], s["port"], s["service"],
                s.get("product") or "-", s.get("version") or "-"))
    else:
        lines.append("_No reachable service was recorded._")
    lines.append("")

    lines.append("## 3. Findings")
    lines.append("")
    if not findings:
        lines.append("_No findings recorded._")
        lines.append("")
    else:
        grouped = {}
        for f in findings:
            grouped.setdefault(f["severity"], []).append(f)
        for sev in SEV_ORDER:
            flist = grouped.get(sev)
            if not flist:
                continue
            lines.append("### %s %s" % (_SEV_ICON.get(sev, ""),
                                        sev.upper()))
            lines.append("")
            lines.append(_SEV_MEANS.get(sev, ""))
            lines.append("")
            for i, f in enumerate(flist):
                title = f["title"]
                where_target = f.get("target") or ""
                # Use the report-wide index for the evidence filename; the
                # engine numbers PNVs across ALL findings of the target.
                global_i = data["findings"].index(f) if data["findings"] else i
                lines.append("#### %s" % _md_sev_line(
                    sev, f.get("confidence", ""), title))
                if f.get("confidence", "").lower() in ("tentative",
                                                       "possible"):
                    lines.append("> **Treat as a lead, not a confirmed "
                                 "problem** — verify before acting.")
                lines.append("")
                we_do = []
                if ("host header" in title.lower()) or \
                        ("cache poisoning" in title.lower()):
                    loc = where_target
                else:
                    loc = _first_url(f.get("evidence")) or where_target
                if loc:
                    we_do.append("**Location:** %s" % loc)
                if f.get("detail"):
                    detail = f["detail"].strip()
                    if len(detail) > 900:
                        detail = detail[:900] + " …"
                    we_do.append("**What we found:** %s" % detail)
                lines.append("\n\n".join(we_do) if we_do else "")
                lines.append("")
                cmd, steps = _repro(f)
                if steps and cmd:
                    lines.append("**Proof of concept — how to reproduce:**")
                    lines.append("")
                    for k, step in enumerate(steps, 1):
                        lines.append("%d. %s" % (k, step))
                    lines.append("")
                    lines.append("Command:")
                    lines.append("")
                    lines.append("```bash")
                    lines.append(cmd)
                    lines.append("```")
                    lines.append("")
                poc = _poc_text(f)
                if poc:
                    lines.append("**Observed proof (what the scan saw):**")
                    lines.append("")
                    lines.append("```")
                    for ln in poc.splitlines()[:14]:
                        lines.append("  " + ln[:260].rstrip())
                    lines.append("```")
                    lines.append("")
                png = _evidence_png_rel(data, global_i, title)
                if png:
                    lines.append("![Proof](%s)" % png)
                    lines.append("")
                if f.get("remediation"):
                    lines.append("**Recommended fix:** %s" % f["remediation"])
                    lines.append("")
    lines.append("## 4. How to read severity levels")
    lines.append("")
    lines.append("| Level | What it means |")
    lines.append("|---|---|")
    for sev in SEV_ORDER:
        icon = _SEV_ICON.get(sev, "")
        lines.append("| %s %s | %s |" % (icon, sev.capitalize(),
                                         _SEV_MEANS.get(sev, "")))
    lines.append("")
    lines.append("---")
    lines.append("_Automated assessment. All findings should be validated by "
                 "your team before remediation. Testing systems without "
                 "written authorization is illegal._")
    return "\n".join(lines)


def render_json(data):
    return json.dumps(data, indent=2, default=str)


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}

_SARIF_CATEGORY = {"web": "WebApp", "network": "Network", "exploit": "Exploit",
                   "ad": "ActiveDirectory", "recon": "Recon",
                   "post": "PostCorp", "core": "Aegis"}


def render_sarif(data):
    """SARIF 2.1.0 export (static-analysis schema) for CI/DevOps ingestion.
    Findings map to results; each finding's rule is inlined into the run so
    the file is self-contained (MSTEST-style stable toolComponent)."""
    from datetime import datetime
    rules, seen, results = [], set(), []
    for f in data.get("findings", []):
        rule_id = f.get("module") or "web.vulnscan"
        rule = {
            "id": rule_id,
            "name": rule_id.replace(".", "-"),
            "shortDescription": {"text": f.get("title") or rule_id},
            "helpUri": "https://github.com/pintukumar-sutradhar/vajra",
        }
        if f.get("detail"):
            rule["help"] = {"text": f.get("detail")}
        if f.get("mitre"):
            rule.setdefault("properties", {})["mitre"] = f.get("mitre")
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append(rule)
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get((f.get("severity") or "info").lower(),
                                      "note"),
            "message": {"text": f.get("title") or ""},
            "locations": [{
                "physicalLocation": {"artifactLocation": {
                    "uri": "vajra://%s" % (f.get("target") or "unknown")}},
            }],
            "properties": {
                k: v for k, v in {
                    "severity": f.get("severity"),
                    "confidence": f.get("confidence"),
                    "category": _SARIF_CATEGORY.get(
                        (f.get("module") or "").split(".")[0], "General"),
                    "remediation": f.get("remediation"),
                    "evidence": (f.get("evidence") or "".join(f.get("evidence", []) or []))[:2000],
                }.items() if v},
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "VAJRA",
                "informationUri": "https://github.com/pintukumar-sutradhar/vajra",
                "version": (data.get("meta") or {}).get("profile", ""),
                "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


_SEV_RGB = {"critical": (1.0, 0.1, 0.1), "high": (0.95, 0.32, 0.24),
            "medium": (0.95, 0.7, 0.1), "low": (0.2, 0.6, 0.95),
            "info": (0.55, 0.58, 0.62)}


def render_pdf(data, path="report.pdf"):
    """Minimal Valid-PDF writer (stdlib only): paginated text report with
    per-severity colour, risk-score header and wrapped findings. Each line is
    emitted as an absolute-positioned text object so offsets stay exact."""
    import math

    def esc(s):
        return str(s).replace("\\", "\\\\").replace("(", "\\(").replace(
            ")", "\\)")

    def wrap(text, width=96):
        words = text.split()
        if not words:
            return [""]
        lines, cur = [], ""
        for w in words:
            if len(cur) + len(w) + 1 > width:
                lines.append(cur)
                cur = w
            else:
                cur = (cur + " " + w).strip()
        lines.append(cur)
        return lines

    rows = []  # (r,g,b, bold, size, text)
    m = data["meta"]
    rows.append((0.97, 0.51, 0.4, True, 17, "VAJRA Security Assessment"))
    rows.append((0.55, 0.58, 0.62, False, 9,
                 "Generated %s  profile=%s  target=%s  output=%s" % (
                     m["generated"], m["profile"], ", ".join(m["targets"]),
                     m["output_dir"])))
    rows.append((0.1, 0.1, 0.1, False, 0, None))  # spacer
    stats = data["stats"]
    total = sum(stats.values())
    rows.append((0.1, 0.1, 0.1, True, 12,
                 "Risk score %.1f/100 (%d findings)" % (
                     data["score"], total)))
    rows.append((0.4, 0.4, 0.45, False, 9,
                 "critical=%d  high=%d  medium=%d  low=%d  info=%d" % (
                     stats.get("critical", 0), stats.get("high", 0),
                     stats.get("medium", 0), stats.get("low", 0),
                     stats.get("info", 0))))
    rows.append((0.1, 0.1, 0.1, False, 0, None))
    if data.get("narrative"):
        for ln in wrap(str(data["narrative"])[:600], 100):
            rows.append((0.3, 0.3, 0.35, False, 9, ln))
    rows.append((0.1, 0.1, 0.1, False, 0, None))

    for f in data["findings"]:
        rgb = _SEV_RGB.get(f["severity"], (0.5, 0.5, 0.5))
        rows.append((*rgb, True, 10.5,
                     "[%s][%s] %s" % (f["severity"].upper(), f["category"],
                                      f["title"])))
        if f.get("mitre"):
            rows.append((0.4, 0.4, 0.45, False, 8.5,
                         "ATT&CK %s  module=%s  confidence=%s" % (
                             f["mitre"], f["module"],
                             (f.get("confidence") or "-").title())))
        if f.get("detail"):
            for ln in wrap(str(f["detail"]).replace("\n", " ")[:600]):
                rows.append((0.25, 0.25, 0.3, False, 9, ln))
        poc = _poc_text(f)
        if poc:
            rows.append((0.3, 0.35, 0.5, False, 8, "Evidence / PoC:"))
            for ln in str(poc).splitlines()[:12]:
                rows.append((0.3, 0.35, 0.5, False, 7.5, ln))
        if f.get("remediation"):
            rows.append((0.2, 0.5, 0.3, False, 8.5,
                         "Fix: %s" % f["remediation"][:400]))
        rows.append((0.1, 0.1, 0.1, False, 0, None))

    PAGE_W, PAGE_H = 595, 792
    MARGIN, USABLE = 48, 792 - 2 * 48
    flat = []
    for r, g, b, bold, size, text in rows:
        if text is None:
            continue
        for ln in wrap(str(text), 110 if size >= 11 else 96):
            flat.append((r, g, b, bold, size, ln))
    pages, cur, top = [], [], 0
    for r, g, b, bold, size, ln in flat:
        h = 13 if size <= 9 else 15
        if top + h > USABLE:
            pages.append(cur)
            cur, top = [], 0
        cur.append((top, r, g, b, bold, size, ln))
        top += h
    pages.append(cur)

    def stream_for(page):
        ops = ["BT"]
        for top, r, g, b, bold, size, txt in page:
            y = PAGE_H - MARGIN - top
            ops.append("1 0 0 1 50 %d Tm" % y)
            ops.append("%.3f %.3f %.3f rg" % (r, g, b))
            ops.append("%s %.1f Tf" % ("/F2" if bold else "/F1", size))
            ops.append("(%s) Tj" % esc(txt))
        ops.append("ET")
        return ("\n".join(ops) + "\n").encode("latin1", "replace")

    def obj(num, body):
        out = bytearray()
        head = b"%d 0 obj\n" % num
        out += head
        out += body.encode("latin1", "replace") if isinstance(body, str) \
            else body
        out += b"\nendobj\n"
        return bytes(out)

    objs = []
    objs.append(obj(1, "<< /Type /Catalog /Pages 2 0 R >>"))
    page_refs = "".join("%d 0 R " % (3 + i * 2)
                        for i in range(len(pages))).strip()
    objs.append(obj(2, "<< /Type /Pages /Kids [%s] /Count %d >>" %
                    (page_refs, len(pages))))
    streams = []
    for i, page in enumerate(pages):
        s = stream_for(page)
        streams.append(s)
        objs.append(obj(3 + i * 2, "<< /Type /Page /Parent 2 0 R "
                        "/MediaBox [0 0 %d %d] /Resources << /Font "
                        "<< /F1 %d 0 R /F2 %d 0 R >> >> /Contents %d 0 R >>"
                        % (PAGE_W, PAGE_H, 5, 6, 4 + i * 2)))
        objs.append(obj(4 + i * 2, "<< /Length %d >>\nstream\n" % len(s)
                        + s.decode("latin1", "replace") + "endstream"))
    objs.append(obj(5, "<< /Type /Font /Subtype /Type1 /BaseFont "
                    "/Helvetica >>"))
    objs.append(obj(6, "<< /Type /Font /Subtype /Type1 /BaseFont "
                    "/Helvetica-Bold >>"))
    out = bytearray(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
    offsets = [0]
    for o in objs:
        offsets.append(len(out))
        out += o
    xref_at = len(out)
    out += b"xref\n0 %d\n" % (len(objs) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += b"%010d 00000 n \n" % off
    out += ("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n"
            % (len(objs) + 1, xref_at)).encode()
    out += b"%%EOF\n"
    with open(path, "wb") as f:
        f.write(bytes(out))
    return path


# ---------------------------------------------------------------------------
# Minimal XLSX writer (stdlib only: zipfile + XML). Produces a real
# spreadsheet that Excel / LibreOffice open natively, with a Summary sheet
# and a Findings sheet, so findings + evidence are exporter-friendly.
# ---------------------------------------------------------------------------

def _xlsx_esc(v):
    if v is None:
        return ""
    s = str(v)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # quotes are fine inside <v> / <t>; we keep them unescaped for readability


def _xlsx_shared_strings(strings):
    si = "".join("<si><t xml:space='preserve'>%s</t></si>" % _xlsx_esc(s)
                 for s in strings)
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'count="%d" uniqueCount="%d">%s</sst>' % (len(strings),
                                                      len(strings), si))


class _XlsxStr:
    """Marker for a cell that is a shared-string reference."""
    __slots__ = ("idx",)

    def __init__(self, idx):
        self.idx = idx


def _xlsx_sheet(name, rows, widths):
    """rows: list of lists where each cell is either a number (int/float) or
    an _XlsxStr (a shared-string index). `widths` are in Excel chars."""
    cols = "".join('<col min="%d" max="%d" width="%s" customWidth="1"/>' %
                   (i + 1, i + 1, w) for i, w in enumerate(widths))
    sheet_data = []
    for r, row in enumerate(rows):
        cells = []
        for c, val in enumerate(row):
            ref = "%s%d" % (_xlsx_col(c), r + 1)
            if isinstance(val, _XlsxStr):
                cells.append('<c r="%s" t="s"><v>%d</v></c>' % (ref, val.idx))
            else:
                cells.append('<c r="%s"><v>%s</v></c>' % (ref, val))
        sheet_data.append('<row r="%d">%s</row>' % (r + 1, "".join(cells)))
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<cols>%s</cols><sheetData>%s</sheetData></worksheet>'
            % (cols, "".join(sheet_data)))


_XLSX_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _xlsx_col(idx):
    s = ""
    while True:
        s = _XLSX_ALPHA[idx % 26] + s
        idx = idx // 26 - 1
        if idx < 0:
            break
    return s


def render_xlsx(data, path="report.xlsx"):
    """Stdlib-only XLSX report: Summary + Findings worksheets. Findings sheet
    carries severity, category, MITRE, confidence and the PoC/evidence text,
    so the report can be consumed in Excel pipelines and archiving."""
    import zipfile

    strings = []
    s_idx = {}

    def S(v):
        v = "" if v is None else str(v)
        if v not in s_idx:
            s_idx[v] = len(strings)
            strings.append(v)
        return s_idx[v]

    # Summary sheet target rows
    summary = []
    summary.append(["VAJRA Security Assessment", "", "", "", ""])
    summary.append(["Field", "Value", "", "", ""])
    meta = data.get("meta", {})
    summary.append(["Generated", meta.get("generated", ""), "", "", ""])
    summary.append(["Profile", meta.get("profile", ""), "", "", ""])
    summary.append(["Targets", ", ".join(meta.get("targets", []) or []),
                    "", "", ""])
    stats = data.get("stats", {})
    summary.append(["Risk score", round(float(data.get("score", 0)), 1),
                    "", "", ""])
    summary.append(["Findings", "%d critical / %d high / %d medium / %d low / %d info" % (
        stats.get("critical", 0), stats.get("high", 0),
        stats.get("medium", 0), stats.get("low", 0),
        stats.get("info", 0)), "", "", ""])
    summary.append(["", "", "", "", ""])
    tc = (data.get("tech_cves") or {})
    if tc:
        summary.append(["CVEs found by technology", "", "", "", ""])
        summary.append(["Technology", "Version", "CVE ID", "CVSS",
                        "Summary"])
        for tech in sorted(tc):
            rec = tc[tech]
            if not rec or not rec.get("cves"):
                continue
            for c in rec["cves"]:
                summary.append([
                    tech.title(), rec.get("version", "?"),
                    c.get("id", ""), c.get("cvss", ""),
                    (c.get("summary") or "")[:300],
                ])
        summary.append(["", "", "", "", ""])

    # Findings sheet
    fhead = ["Severity", "Title", "Detail", "Confidence",
             "PoC / Evidence", "How to reproduce (command)"]
    findings = [fhead]
    for f in data.get("findings", []):
        _cmd, _steps = _repro(f)
        findings.append([
            f.get("severity", ""), f.get("title", ""),
            f.get("detail", ""), f.get("confidence", ""),
            _poc_text(f), _cmd,
        ])

    # Build shared strings + rows. Strings are interned here and tagged with
    # _XlsxStr so the sheet writer emits t="s" string cells (numbers stay
    # numeric — this is what lost all text in the old writer).
    def T(v):
        if isinstance(v, _XlsxStr):
            return v
        if isinstance(v, str):
            return _XlsxStr(S(v))
        return v

    rows_sum = [[T(c) for c in row] for row in summary]
    rows_find = [[T(c) for c in row] for row in findings]

    sheet1 = _xlsx_sheet("Summary", rows_sum, [46, 70, 12, 12, 12])
    sheet2 = _xlsx_sheet("Findings", rows_find, [10, 34, 40, 12, 60, 46])

    # Workbook + relationships + styles (minimal).
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
          '<sheets><sheet name="Summary" sheetId="1" r:id="rId1"/>'
          '<sheet name="Findings" sheetId="2" r:id="rId2"/></sheets></workbook>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            'Target="worksheets/sheet1.xml"/>'
            '<Relationship Id="rId2" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            'Target="worksheets/sheet2.xml"/>'
            '<Relationship Id="rId3" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
            'Target="styles.xml"/>'
            '<Relationship Id="rId4" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" '
            'Target="sharedStrings.xml"/></Relationships>')
    content_types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                     '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                     '<Default Extension="rels" '
                     'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                     '<Default Extension="xml" ContentType="application/xml"/>'
                     '<Override PartName="/xl/workbook.xml" '
                     'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                     '<Override PartName="/xl/worksheets/sheet1.xml" '
                     'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                     '<Override PartName="/xl/worksheets/sheet2.xml" '
                     'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                     '<Override PartName="/xl/styles.xml" '
                     'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                     '<Override PartName="/xl/sharedStrings.xml" '
                     'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
                     '</Types>')
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
              '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
              '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
              '<fills count="2"><fill><patternFill patternType="none"/></fill>'
              '<fill><patternFill patternType="gray125"/></fill></fills>'
              '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
              '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
              '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
              '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
              '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
              '</styleSheet>')

    root_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                 '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                 '<Relationship Id="rId1" '
                 'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
                 'Target="xl/workbook.xml"/></Relationships>')

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", rels)
        z.writestr("xl/worksheets/sheet1.xml", sheet1)
        z.writestr("xl/worksheets/sheet2.xml", sheet2)
        z.writestr("xl/styles.xml", styles)
        z.writestr("xl/sharedStrings.xml", _xlsx_shared_strings(strings))
        z.writestr("[Content_Types].xml", content_types)
    return path
