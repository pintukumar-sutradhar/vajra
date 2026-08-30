"""Vajra - report generation: interactive HTML dashboard, JSON, Markdown."""
import datetime
import json
from string import Template

from core.database import SEV_ORDER, SEV_WEIGHT
from core.utils import PROJECT_ROOT

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
   <h2>Synthesis &amp; AI-brain narrative</h2>
   <div class="narr">$synthesis</div>
  </section>

  $remediation

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
 This report was generated by an automated tool and may contain false positives.
 All findings must be validated by a qualified professional before remediation decisions.
 Use of this tool against systems without written authorization is illegal.<br>
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
        rows.append(
            '<tr class="frow"><td><span class="sev %s">%s</span></td>'
            '<td>%s<br><span class="muted">%s / %s</span></td>'
            '<td>%s%s</td>'
            '<td class="poc"><pre class="poc">%s</pre></td>'
            '<td class="muted">%s</td></tr>' % (
                f["severity"], f["severity"], _esc(f["title"]),
                _esc(f["category"]), _esc(f["module"]),
                _esc(f["detail"]),
                ("<br><span class='muted'>ATT&amp;CK: %s</span>" % mitre)
                if mitre else "",
                _esc(f["evidence"][:2400]) if f["evidence"] else "<i>-</i>",
                _esc((f.get("confidence") or "-").title())))
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
    tpl = Template(HTML_TEMPLATE)
    return tpl.substitute(
        date=data["meta"]["generated"], profile=_esc(data["meta"]["profile"]),
        targets=_esc(", ".join(data["meta"]["targets"])[:90]),
        score=data["score"], scorecolor=scorecolor,
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
        remediation=_render_remediation(data.get("remediation", [])))


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
    lines.append("## Synthesis & AI-brain narrative")
    lines.append("")
    lines.append(data.get("synthesis", ""))
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
        if f.get("mitre"):
            lines.append("- **ATT&CK:** %s" % f["mitre"])
        if f.get("detail"):
            lines.append("- **Detail:** %s" % f["detail"].replace("\n", " ")[:500])
        if f.get("remediation"):
            lines.append("- **Remediation:** %s" % f["remediation"])
        if f.get("evidence"):
            lines.append("- **Evidence:**")
            lines.append("  ```")
            for ln in f["evidence"].splitlines()[:15]:
                lines.append("  " + ln[:300])
            lines.append("  ```")
        lines.append("")
    lines.append("---")
    lines.append("*Automated tool output. Validate all findings manually. "
                  "Unauthorized testing is illegal.")
    return "\n".join(lines)
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
                     % (f["module"], f["category"],
                        (f["confidence"] or "-").title()))
        if f.get("mitre"):
            lines.append("- **ATT&CK:** %s" % f["mitre"])
        if f.get("detail"):
            lines.append("- **Detail:** %s" % f["detail"].replace("\n", " ")[:500])
        if f.get("remediation"):
            lines.append("- **Remediation:** %s" % f["remediation"])
        if f.get("evidence"):
            lines.append("- **Evidence:**")
            lines.append("  ```")
            for ln in f["evidence"].splitlines()[:15]:
                lines.append("  " + ln[:300])
            lines.append("  ```")
        lines.append("")
    lines.append("---")
    lines.append("*Automated tool output. Validate all findings manually. "
                 "Unauthorized testing is illegal.*")
    return "\n".join(lines)


def render_json(data):
    return json.dumps(data, indent=2, default=str)


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
        if f.get("evidence"):
            rows.append((0.3, 0.35, 0.5, False, 8, "Evidence:"))
            for ln in str(f["evidence"]).splitlines()[:12]:
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
