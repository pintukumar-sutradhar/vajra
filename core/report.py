"""Vajra - report generation: interactive HTML dashboard, JSON, Markdown."""
import datetime
import json
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
<title>Vajra Report - $targets</title>
<style>
 :root { --bg:#0d1117; --card:#161b22; --line:#21262d; --fg:#e6edf3; --mut:#8b949e;
         --crit:#ff1744; --high:#ff5252; --med:#ffb300; --low:#4fc3f7; --info:#9e9e9e; }
 * { box-sizing:border-box; margin:0; padding:0; }
 body { background:var(--bg); color:var(--fg); font:14px/1.55 'Segoe UI',system-ui,sans-serif; padding:28px; }
 .wrap { max-width:1180px; margin:auto; }
 h1 { font-size:26px; letter-spacing:.5px; }
 h1 span { color:#f78166; }
 .sub { color:var(--mut); margin:6px 0 24px; }
 .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; margin-bottom:26px; }
 .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px 18px; }
 .card .num { font-size:32px; font-weight:700; }
 .card .lbl { color:var(--mut); font-size:12px; text-transform:uppercase; letter-spacing:1px; }
 .scorebig { font-size:40px; font-weight:800; }
 table { width:100%; border-collapse:collapse; background:var(--card); border-radius:12px; overflow:hidden; border:1px solid var(--line); margin-bottom:30px; }
 th { background:#1c2129; text-align:left; padding:10px 14px; font-size:12px; text-transform:uppercase; color:var(--mut); letter-spacing:1px; cursor:pointer; }
 td { padding:11px 14px; border-top:1px solid var(--line); vertical-align:top; }
 tr:hover td { background:#1a202a; }
 .sev { display:inline-block; min-width:74px; text-align:center; border-radius:20px; font-weight:700; font-size:11px; padding:3px 10px; text-transform:uppercase; color:#000; }
 .sev.critical{background:var(--crit)} .sev.high{background:var(--high)} .sev.medium{background:var(--med)}
 .sev.low{background:var(--low)} .sev.info{background:var(--info)}
 .chip { display:inline-block; background:#21262d; border:1px solid #30363d; border-radius:16px; padding:3px 12px; margin:3px; font-size:12px; }
pre { background:#0a0d12; border:1px solid var(--line); border-radius:8px; padding:10px; overflow-x:auto; white-space:pre-wrap; word-break:break-word; max-height:260px; font-size:12px; }
  table.fixed { table-layout:fixed; width:100%; }
  table.fixed th.col-sev{width:86px} table.fixed th.col-title{width:27%}
  table.fixed th.col-detail{width:32%} table.fixed th.col-conf{width:120px}
  td.poc { width:auto; }
  pre.poc { background:#0a0d12; border:1px solid #2d333b; border-left:4px solid #f78166;
            border-radius:8px; padding:12px 14px; overflow:auto; white-space:pre-wrap;
            word-break:break-word; max-height:360px; font:12.5px/1.55 ui-monospace,Consolas,
            'Cascadia Mono',monospace; }
  pre.poc::-webkit-scrollbar { width:8px; height:8px; }
  pre.poc::-webkit-scrollbar-thumb { background:#30363d; border-radius:4px; }
  section { margin-bottom:34px; }
 h2 { font-size:18px; margin-bottom:12px; padding-bottom:8px; border-bottom:1px solid var(--line); }
 .narr { background:var(--card); border-left:4px solid #f78166; border-radius:8px; padding:16px 18px; white-space:pre-wrap; }
 .muted { color:var(--mut); }
 footer { color:var(--mut); font-size:12px; margin-top:36px; line-height:1.7; border-top:1px solid var(--line); padding-top:18px; }
 input#f { background:var(--bg); color:var(--fg); border:1px solid var(--line); border-radius:8px; padding:8px 12px; margin-bottom:14px; width:320px; }
</style>
</head>
<body>
<div class="wrap">
 <h1>⚡ <span>VAJRA</span> Penetration Test Report</h1>
 <div class="sub">$date &nbsp;|&nbsp; profile: $profile &nbsp;|&nbsp; targets: $targets &nbsp;|&nbsp; risk score: <b>$score</b>/100</div>

 <div class="grid">
  <div class="card"><div class="num" style="color:var(--crit)">$crit</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num" style="color:var(--high)">$high</div><div class="lbl">High</div></div>
  <div class="card"><div class="num" style="color:var(--med)">$medium</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num" style="color:var(--low)">$low</div><div class="lbl">Low</div></div>
  <div class="card"><div class="num">$info</div><div class="lbl">Info</div></div>
  <div class="card"><div class="scorebig" style="color:$scorecolor">$score</div><div class="lbl">Risk score /100</div></div>
 </div>

  <section>
   <h2>Executive summary</h2>
   <div class="narr">$narrative</div>
  </section>

  <section>
   <h2>Red-team objectives achieved</h2>
   $objectives
  </section>

  <section>
   <h2>How to read this report</h2>
   <div class="narr">Every finding is colour-coded by severity:
  - <span class="sev critical">critical</span> Emergency — an attacker could take full control of the system or steal data with little effort.
  - <span class="sev high">high</span> Urgent — a serious weakness that most attackers can exploit; fix soon.
  - <span class="sev medium">medium</span> Plan a fix — exploitable only under certain conditions or by a skilled attacker.
  - <span class="sev low">low</span> Minor — a small hardening gap; fix when convenient.
  - <span class="sev info">info</span> Information only — not a vulnerability by itself.

The "Evidence / PoC" block under each finding shows exactly what the scanner saw (a returned page, a server reply, an access attempt). If the technical wording is unclear, send those evidence lines to your IT team — they reproduce the exact check. Work top-down: fix critical and high items first, re-test, then move on to medium and low.

Each finding also carries a confidence level saying how sure the scanner is:
  - <b>Certain</b> — the check was proven end-to-end (e.g. an exploit payload actually ran and its output was captured).
  - <b>Firm</b> — strong evidence the weakness is real, but it was not conclusively proof-tested.
  - <b>Tentative</b> — a signal that may be a real weakness or a false alarm; treat it as a lead to verify, not a confirmed problem.

A finding whose confidence is below its claimed severity is automatically downgraded, so unproven leads are never reported as critical or high.</div>
  </section>

  <section>
   <h2>Attack surface</h2>
   $chips
  </section>

  <section>
   <h2>Synthesis &amp; AI narrative</h2>
   <div class="narr">$synthesis</div>
  </section>

   $remediation

  <section>
   <h2>Attack paths &amp; finding correlation</h2>
   $atkpath
   $correlated
  </section>

  <section>
   <h2>Retest delta (vs previous snapshot)</h2>
   <pre>$delta</pre>
  </section>

  <section>
   <h2>Findings ($total)</h2>
   <input id="f" placeholder="filter findings..." onkeyup="filter()">
   $finding_rows
  </section>

  $evsection
 <section>
  <h2>Scan timeline</h2>
  <table><tr><th>Time</th><th>Target</th><th>Event</th></tr>$event_rows</table>
 </section>

<footer>
 <b>VAJRA</b> — automated penetration testing framework.<br>
 Unverified, heuristic signals are flagged "unverified lead" and are never
 reported critical/high (anti-false-positive policy). Still, validate all
 findings manually before remediation. Use of this tool against systems
 without written authorization is illegal.<br>
 Generated: $date
</footer>
</div>
<script>
 function filter(){
  var q=document.getElementById('f').value.toLowerCase();
  document.querySelectorAll('tr.frow').forEach(function(r){
   r.style.display = r.innerText.toLowerCase().includes(q)?'':'none';});
 }
 document.querySelectorAll('th').forEach(th=>th.addEventListener('click',()=>{
  const tb=th.closest('table');const idx=[...th.parentElement.children].indexOf(th);
  const rows=[...tb.querySelectorAll('tr.frow,tr.erow')];
  rows.sort((a,b)=>a.children[idx].innerText.localeCompare(b.children[idx].innerText));
  rows.forEach(r=>tb.appendChild(r));}));
</script>
</body>
</html>"""


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


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
        "subdomains": engine.state.get("subdomains", []),
        "os_guess": engine.state.get("os_guess", ""),
        "evasion": list(getattr(engine, "evasion_all", []))[:150],
        "objectives": objectives(findings, getattr(engine, "state", {})),
        "correlated": correlated,
        "attack_paths": paths,
    }


def render_html(data):
    stats = data["stats"]
    chips = []
    for s in data.get("services", []):
        chips.append("%s:%s %s%s" % (_esc(s["target"]), s["port"],
                                     _esc(s["service"]),
                                     (" (%s)" % _esc(s["product"])) if s.get("product") else ""))
    for tech in data.get("tech") or []:
        chips.append(str(tech))
    if data.get("os_guess"):
        chips.append("OS: " + data["os_guess"])
    chips_html = "".join('<span class="chip">%s</span>' % _esc(c) for c in chips)

    rows = []
    for f in data["findings"]:
        mitre = _esc(f.get("mitre", ""))
        conf = (f.get("confidence") or "").lower()
        conf_label = (f.get("confidence") or "-").title()
        # Unverified / heuristic signals are explicitly surfaced as LEADS, not
        # confirmed problems, so the report never reads as a proven finding
        # when the check was not proof-tested (no false positives).
        if conf == "tentative":
            conf_badge = ('<span class="chip">%s</span>'
                          '<div class="muted" style="font-size:11px">'
                          '&nbsp;unverified lead — verify manually</div>'
                          % _esc(conf_label))
        else:
            conf_badge = '<span class="chip">%s</span>' % _esc(conf_label)
        poc = _poc_text(f)
        poc_block = ('<pre class="poc">%s</pre>' % _esc(poc[:2400])
                     if poc else
                     '<span class="muted">no proof captured — see detail</span>')
        rows.append(
            '<tr class="frow"><td><span class="sev %s">%s</span></td>'
            '<td>%s<br><span class="muted">%s / %s</span></td>'
            '<td>%s%s</td>'
            '<td class="poc">%s</td>'
            '<td class="muted">%s</td></tr>' % (
                f["severity"], f["severity"], _esc(f["title"]),
                _esc(f["category"]), _esc(f["module"]),
                _esc(f["detail"]),
                ("<br><span class='muted'>ATT&amp;CK: %s</span>" % mitre)
                if mitre else "",
                poc_block,
                conf_badge))
    finding_rows = ('<table class="fixed findings"><thead><tr>'
                     '<th class="col-sev">Severity</th>'
                     '<th class="col-title">Title</th>'
                     '<th class="col-detail">Detail</th>'
                     '<th class="col-poc">PoC / Evidence</th>'
                     '<th class="col-conf">Confidence</th></tr></thead>' +
                     "".join(rows) + "</table>") if rows else \
        '<p class="muted">No findings recorded.</p>'

    ev_entries = data.get("evasion") or []
    if ev_entries:
        passed = sum(1 for e in ev_entries if e.get("result") == "passed")
        rows_ev = "".join(
            '<tr class="frow"><td>%s</td><td><code>%s</code></td>'
            '<td><pre>%s</pre></td><td><span class="sev %s">%s</span></td></tr>' % (
                _esc(e.get("waf", "?")), _esc(e.get("ops", "")),
                _esc((e.get("original", "")[:110] + "  ==>  " +
                      e.get("mutant", "")[:110])),
                "low" if e.get("result") == "passed" else "info",
                _esc(e.get("result", "")))
            for e in ev_entries[:60])
        evsection = (
            '<section><h2>Evasion operations (%d attempts against WAF, '
            '%d payloads passed filters)</h2>'
            '<table><tr><th>WAF</th><th>Operator chain</th><th>payload '
            'mutation</th><th>Result</th></tr>%s</table></section>'
            % (len(ev_entries), passed, rows_ev))
    else:
        evsection = ""

    erows = []
    for ev_target, event, detail, created in data["events"]:
        erows.append('<tr class="erow"><td>%s</td><td>%s</td><td>%s</td></tr>' %
                         (_esc(created[11:19] if len(created) >= 19 else created),
                          _esc(ev_target[:40]), _esc(event)))
    score = float(data["score"])
    scorecolor = "#f44336" if score >= 25 else \
        ("#ffb300" if score >= 10 else "#4caf50")
    es_for = objectives_html(data.get("objectives") or [])
    tpl = Template(HTML_TEMPLATE)
    return tpl.substitute(
        date=data["meta"]["generated"], profile=_esc(data["meta"]["profile"]),
        targets=_esc(", ".join(data["meta"]["targets"])[:90]),
        score=data["score"], scorecolor=scorecolor, objectives=es_for,
        crit=stats.get("critical", 0), high=stats.get("high", 0),
        medium=stats.get("medium", 0), low=stats.get("low", 0),
        info=stats.get("info", 0), total=len(data["findings"]),
        narrative=_esc(data["narrative"]), chips=chips_html or "<i class='muted'>none</i>",
        finding_rows=finding_rows,
        event_rows="".join(erows)[:200000], evsection=evsection,
        synthesis=_esc(data.get("synthesis", "")),
        delta=_esc("\n".join(
            "%s: %s" % (k, ", ".join(v[:3]) + ("..." if len(v) > 3 else ""))
            for k, v in data.get("delta", {}).items())),
        remediation=_render_remediation(data.get("remediation", [])),
        atkpath=attack_paths_html(data.get("attack_paths") or []),
        correlated=correlated_html(data.get("correlated") or []))


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
            '<td>%d finding%s from %d module(s)</td>'
            '<td><code>%s</code></td></tr>' % (
                _esc(c.get("severity", "info")), _esc(c.get("severity", "info")),
                _esc(c.get("label", "")), _esc(c.get("target", "")),
                "; ".join(_esc(t[:70]) for t in c.get("titles", [])[:3]),
                c.get("title_count", 1), plural, len(c.get("sources", [])),
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
                          % (_esc(it["title"]), _esc(it["module"])))
        if not body:
            continue
        rows.append('<h3 style="color:var(--%s)">%s — %s</h3>'
                      % (sec["severity"], sec["severity"].upper(),
                         sec.get("priority", "")))
        rows.append('<table><tr><th>Title</th><th>Module</th></tr>' +
                      "".join(body) + "</table>")
    return "".join(rows)


def render_markdown(data):
    from core.attackpath import attack_path_md
    stats = data["stats"]
    lines = []
    lines.append("# ⚡ Vajra Security Assessment Report")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append("| Generated | %s |" % data["meta"]["generated"])
    lines.append("| Profile | %s |" % data["meta"]["profile"])
    lines.append("| Targets | %s |" % ", ".join(data["meta"]["targets"]))
    lines.append("| Risk Score | %.1f/100 |" % data["score"])
    ev = data.get("evasion") or []
    if ev:
        passed = sum(1 for e in ev if e.get("result") == "passed")
        lines.append("| Evasion Ops | %d attempted / %d passed filters |" %
                         (len(ev), passed))
    lines.append("| Findings | %d critical / %d high / %d medium / %d low / %d info |"
                 % tuple(stats.get(s, 0) for s in SEV_ORDER))
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(data["narrative"])
    lines.append("")
    lines.append("## Red-team objectives achieved")
    lines.append("")
    lines.append(objectives_md(data.get("objectives") or []))
    lines.append("")
    lines.append("## Synthesis & AI narrative")
    lines.append("")
    lines.append(data.get("synthesis", ""))
    lines.append("")
    lines.append("## Attack Paths")
    lines.append("")
    lines.append(attack_path_md(data.get("attack_paths") or []))
    lines.append("")
    if data.get("correlated"):
        lines.append("## Correlated findings (deduplicated)")
        lines.append("")
        lines.append("| Severity | Issue | Sources | Evidence titles |")
        lines.append("|---|---|---|---|")
        for c in data["correlated"]:
            if not c.get("key"):
                continue
            lines.append("| %s | %s | %s | %s |" % (
                c["severity"], c["label"],
                ", ".join(c["sources"]),
                "; ".join(t[:60] for t in c["titles"][:3])))
        lines.append("")
    lines.append("## Remediation Playbook")
    lines.append("")
    for sec in data.get("remediation", []):
        lines.append("### %s — %s" % (sec["severity"].upper(),
                                 sec.get("priority", "")))
        lines.append("")
        for it in sec.get("items", [])[:50]:
            lines.append("- **%s** (%s)" % (it["title"], it["module"]))
            lines.append("  - Remediation: %s" % it["remediation"])
            refs = []
            if it["cis"]:
                refs.append("CIS: %s" % ", ".join(it["cis"]))
            if it["nist"]:
                refs.append("NIST CSF: %s" % ", ".join(it["nist"]))
            if it["pci"]:
                refs.append("PCI DSS: %s" % ", ".join(it["pci"]))
            if refs:
                lines.append("  - Controls: " + " | ".join(refs))
        lines.append("")
    lines.append("## Retest delta (vs previous snapshot)")
    lines.append("")
    for k, v in data.get("delta", {}).items():
        lines.append("- %s: %s" % (k, ", ".join(v[:3]) + ("..." if len(v) > 3 else "")))
    lines.append("")
    lines.append("## Services")
    lines.append("")
    lines.append("| Target | Port | Service | Product | Version | TLS |")
    lines.append("|---|---|---|---|---|---|")
    for s in data.get("services", []):
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            s["target"], s["port"], s["service"], s.get("product") or "-",
            s.get("version") or "-", "yes" if s.get("tls") else "no"))
    lines.append("")
    lines.append("## Detailed Findings")
    lines.append("")
    cur = None
    for f in data["findings"]:
        if f["severity"] != cur:
            cur = f["severity"]
            lines.append("### Severity: %s" % cur.upper())
            lines.append("")
        lines.append("#### [%s] %s" % (f["severity"].upper(), f["title"]))
        lines.append("- **Module:** %s  **Category:** %s  **Confidence:** %s"
                         % (f["module"], f["category"], f["confidence"]))
        if (f.get("confidence") or "").lower() == "tentative":
            lines.append("  - **Note:** unverified lead — confirm manually "
                         "before treating as a real finding.")
        if f.get("mitre"):
            lines.append("- **ATT&CK:** %s" % f["mitre"])
        if f.get("detail"):
            lines.append("- **Detail:** %s" % f["detail"].replace("\n", " ")[:500])
        if f.get("remediation"):
            lines.append("- **Remediation:** %s" % f["remediation"])
        poc = _poc_text(f)
        if poc:
            lines.append("- **Evidence / PoC:**")
            lines.append("  ```")
            for ln in poc.splitlines()[:15]:
                lines.append("  " + ln[:300])
            lines.append("  ```")
        lines.append("")
    lines.append("---")
    lines.append("*Automated tool output. Validate all findings manually. "
                  "Unauthorized testing is illegal.")
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
    summary.append(["Red-team objectives achieved", "", "", "", ""])
    objs = data.get("objectives") or []
    if not objs:
        summary.append(["No confirmed compromise objectives achieved",
                        "", "", ""])
    else:
        summary.append(["Objective", "Supporting findings", "", "", ""])
        for o in objs:
            summary.append([o["name"], o["count"], "", "", ""])

    # Findings sheet
    fhead = ["Severity", "Category", "Title", "Detail", "Module",
             "Confidence", "MITRE", "PoC / Evidence"]
    findings = [fhead]
    for f in data.get("findings", []):
        findings.append([
            f.get("severity", ""), f.get("category", ""),
            f.get("title", ""), f.get("detail", ""),
            f.get("module", ""), f.get("confidence", ""),
            f.get("mitre", ""), _poc_text(f),
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
    sheet2 = _xlsx_sheet("Findings", rows_find, [10, 14, 34, 40, 14, 12, 12, 50])

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
