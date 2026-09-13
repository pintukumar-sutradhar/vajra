"""Branded report generation: a professional PDF (fpdf2) and a self-contained
branded HTML report, both generated on demand from the database.

Reports never need anything saved in the engine's Outputs folder. Screenshot
evidence is embedded directly into the artifacts (base64 in HTML), so a
downloaded report is self-contained and available at any time.
"""

import base64
import datetime
import html
import os

from fpdf import FPDF

from .config import BRAND

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLOR = {
    "critical": (190, 24, 60),
    "high": (217, 119, 6),
    "medium": (202, 138, 4),
    "low": (37, 99, 235),
    "info": (71, 85, 105),
}
SEVERITY_HEX = {
    "critical": "#be183c",
    "high": "#d97706",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#475569",
}
SEVERITY_PDF = {
    "critical": (190, 24, 60), "high": (217, 119, 6),
    "medium": (202, 138, 4), "low": (37, 99, 235), "info": (71, 85, 105),
}
STATUS_LABEL = {
    "open": "Open",
    "triaged": "Triaged",
    "false-positive": "False Positive",
    "accepted-risk": "Accepted Risk",
    "fixed": "Fixed",
}
CONFIDENCE_LABEL = {"certain": "Certain", "firm": "Firm",
                    "tentative": "Assessed"}

PRIMARY = tuple(int(BRAND["colors"]["primary"][i:i + 2], 16)
                for i in (1, 3, 5))
ACCENT = tuple(int(BRAND["colors"]["accent"][i:i + 2], 16)
               for i in (1, 3, 5))
INK = (30, 41, 59)
MUTE = (100, 116, 139)
LINE = (203, 213, 225)


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

def _clean(value, limit=None):
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = text.replace("\x00", "").replace("\ufffd", "?")
    encoded = text.encode("latin-1", errors="replace").decode("latin-1")
    if limit and len(encoded) > limit:
        encoded = encoded[:limit]
    return encoded


def _esc(value):
    return html.escape(str(value or ""))


def _duration(scan):
    try:
        start = scan.started_at or scan.created_at
        end = scan.finished_at or datetime.datetime.now(
            datetime.timezone.utc)
        total = int((end - start).total_seconds())
        h, r = divmod(total, 3600)
        m, s = divmod(r, 60)
        return "%dh %02dm %02ds" % (h, m, s) if h else "%02dm %02ds" % (m, s)
    except Exception:
        return "-"


def _fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M UTC") if ts else "-"


def _sev_hex(sev):
    return SEVERITY_HEX.get((sev or "info").lower(), SEVERITY_HEX["info"])


def _counts(findings):
    c = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        s = (f.severity or "info").lower()
        c[s] = c.get(s, 0) + 1
    return c


def _risk_score(counts):
    weights = {"critical": 9.0, "high": 7.5, "medium": 5.0,
               "low": 2.5, "info": 0.5}
    total = sum(counts.values())
    if not total:
        return 0.0, "No issues"
    score = round(sum(weights.get(k, 0) * v for k, v in counts.items())
                  / total, 1)
    label = ("Critical" if score >= 8 else "High" if score >= 6
             else "Medium" if score >= 4 else "Low")
    return score, label


def _ranked(findings):
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: (
        order.get((f.severity or "info").lower(), 9), f.id or 0))


def _module_label(f):
    return (getattr(f, "module_label", None)
            or (f.source_module or ""))


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

class Report(FPDF):
    def __init__(self, brand=None):
        super().__init__(format="A4", unit="mm")
        self.brand = brand or BRAND
        self.set_auto_page_break(True, margin=18)
        self.set_margins(16, 18, 16)
        self.body = False

    def header(self):
        if not self.body:
            return
        self.set_font("helvetica", "B", 10)
        self.set_text_color(255, 255, 255)
        self.set_fill_color(*PRIMARY)
        self.rect(0, 0, 210, 11, style="F")
        self.set_fill_color(*ACCENT)
        self.rect(0, 11, 210, 1.2, style="F")
        self.set_xy(16, 3)
        self.cell(40, 5, _clean(self.brand["product"]))
        self.set_font("helvetica", "", 8)
        self.set_text_color(203, 213, 225)
        self.cell(0, 5, _clean("Security Assessment Report"), align="R")
        self.set_y(17)

    def footer(self):
        if not self.body:
            return
        self.set_y(-12)
        self.set_draw_color(*LINE)
        self.line(16, self.get_y(), 194, self.get_y())
        self.set_font("helvetica", "", 8)
        self.set_text_color(*MUTE)
        self.set_y(-10)
        note = "Confidential - authorized security testing only"
        self.cell(0, 5, "%s  |  Page %s/{nb}" % (_clean(note),
                                                 self.page_no()), align="C")


def _label(pdf, text):
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(*ACCENT)
    pdf.ln(4)
    pdf.cell(0, 6, _clean(text.upper()))
    pdf.ln(3)


def _maybe_page(pdf, limit=256):
    if pdf.get_y() > limit:
        pdf.add_page()


def _fit_width(png, max_h=190):
    try:
        from PIL import Image
        with Image.open(png) as im:
            w, h = im.size
        if not h:
            return 178.0
        w = 178.0 * max_h / h if h > max_h else 178.0
        return max(10.0, min(178.0, w))
    except Exception:
        return 178.0


def _draw_meta(pdf, rows):
    pdf.ln(2)
    for label, value in rows:
        _maybe_page(pdf)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("helvetica", "B", 8.5)
        pdf.set_text_color(*MUTE)
        pdf.cell(44, 6, _clean(label))
        pdf.set_font("helvetica", "", 8.5)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 6, _clean(value or "-"))
    pdf.set_x(pdf.l_margin)
    pdf.ln(1)


def _severity_chart(pdf, counts):
    total = sum(counts.values())
    if not total:
        return
    y = pdf.get_y()
    pdf.set_font("helvetica", "B", 8)
    for i, sev in enumerate(SEVERITY_ORDER):
        n = counts.get(sev, 0)
        if not n:
            continue
        pdf.set_text_color(*_sev_pdf(sev))
        pdf.set_xy(16 + i * 30, y)
        pdf.cell(30, 4, "%s  %d" % (_clean(sev.upper()), n))
    pdf.ln(8)
    x = 16.0
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        w = 100.0 * n / total
        pdf.set_fill_color(*_sev_pdf(sev))
        pdf.rect(x, pdf.get_y(), max(1.0, w), 7, style="F")
        x += w
    pdf.ln(10)


def _sev_pdf(sev):
    return SEVERITY_PDF.get((sev or "info").lower(), SEVERITY_PDF["info"])


def _pdf_finding(pdf, i, total, f, bundle):
    sev = (f.severity or "info").lower()
    sc = _sev_pdf(sev)
    _maybe_page(pdf, 242)
    line_y = pdf.get_y()
    pdf.set_fill_color(*sc)
    pdf.rect(16, line_y, 2.6, 10, style="F")
    pdf.set_xy(20, line_y)
    pdf.set_font("helvetica", "B", 10.5)
    pdf.set_text_color(*sc)
    pdf.cell(30, 10, _clean(sev.upper()))
    pdf.set_font("helvetica", "B", 8)
    pdf.set_text_color(*MUTE)
    pdf.cell(0, 10, _clean("FINDING %d OF %d    [%s]" % (
        i, total, (f.ref or "finding").upper())), align="R")
    pdf.set_xy(20, line_y + 11)
    pdf.set_font("helvetica", "B", 11.5)
    pdf.set_text_color(*INK)
    pdf.multi_cell(0, 6, _clean(f.title or "(untitled finding)"))
    pdf.ln(1)

    meta = []
    if f.asset:
        meta.append(("Asset", f.asset))
    if _module_label(f):
        meta.append(("Module", _module_label(f)))
    if f.category:
        meta.append(("Category", f.category))
    meta.append(("Status", STATUS_LABEL.get(f.status, f.status)))
    if f.confidence:
        meta.append(("Confidence", CONFIDENCE_LABEL.get(
            f.confidence, f.confidence.title())))
    if f.cvss:
        meta.append(("CVSS", f.cvss))
    if f.cwe:
        meta.append(("CWE", f.cwe))
    for k in range(0, len(meta), 2):
        chunk = meta[k:k + 2]
        _maybe_page(pdf)
        for label, value in chunk:
            pdf.set_font("helvetica", "B", 8)
            pdf.set_text_color(*MUTE)
            pdf.cell(22, 5, _clean(label))
            pdf.set_font("helvetica", "", 8)
            pdf.set_text_color(*INK)
            pdf.cell(58, 5, _clean(value, limit=48))
            pdf.cell(6, 5, "")
        pdf.ln(5)

    if f.detail:
        _label(pdf, "Description")
        _maybe_page(pdf)
        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 5, _clean(f.detail))

    ev = ((f.evidence or {}).get("text")
          if isinstance(f.evidence, dict) else f.evidence)
    if ev:
        _label(pdf, "Evidence / proof of concept")
        _maybe_page(pdf)
        pdf.set_font("courier", "", 8)
        pdf.set_text_color(*INK)
        pdf.set_fill_color(239, 244, 249)
        pdf.multi_cell(0, 4, _clean(ev, limit=3600), fill=True, border=0)

    shots = ((f.evidence or {}).get("screenshots")
             if isinstance(f.evidence, dict) else [])
    for rel in shots or []:
        _maybe_page(pdf)
        png = os.path.join(bundle, rel) if bundle else rel
        if not os.path.isfile(png):
            continue
        pdf.set_font("helvetica", "", 7)
        pdf.set_text_color(*MUTE)
        pdf.cell(0, 4, _clean("Screenshot: %s" % os.path.basename(rel)))
        pdf.ln(4)
        y0 = pdf.get_y()
        try:
            pdf.image(png, x=16, y=y0, w=_fit_width(png))
        except Exception:
            pdf.set_y(y0)
            pdf.set_font("helvetica", "I", 8)
            pdf.set_text_color(*MUTE)
            pdf.cell(0, 5, "[image unavailable]")
            pdf.ln(5)
        pdf.set_y(pdf.get_y() + 2)

    if f.remediation:
        _label(pdf, "Remediation")
        _maybe_page(pdf)
        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 5, _clean(f.remediation))

    if f.state_note:
        _label(pdf, "Triage note")
        _maybe_page(pdf)
        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 5, _clean(f.state_note))
    pdf.ln(3)


def _pdf_cover(pdf, brand, scan, target, engine_label, score, label,
               when, rows):
    pdf.set_fill_color(*PRIMARY)
    pdf.rect(0, 0, 210, 42, style="F")
    pdf.set_fill_color(*ACCENT)
    pdf.rect(0, 42, 210, 1.5, style="F")
    pdf.set_xy(16, 12)
    pdf.set_font("helvetica", "B", 24)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 12, _clean(brand["product"]))
    pdf.set_font("helvetica", "", 11)
    pdf.set_text_color(203, 213, 225)
    pdf.ln(12)
    pdf.cell(0, 6, _clean(brand["tagline"]))

    pdf.set_xy(16, 56)
    pdf.set_font("helvetica", "B", 19)
    pdf.set_text_color(*INK)
    pdf.cell(0, 10, "Security Assessment Report")
    pdf.set_font("helvetica", "", 9.5)
    pdf.set_text_color(*MUTE)
    pdf.ln(10)
    pdf.cell(0, 6, "Prepared by %s  |  %s" % (
        _clean(brand["company"] or brand["product"]), _clean(when)))

    pdf.ln(8)
    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(*INK)
    pdf.cell(0, 7, "Assessment summary")
    pdf.ln(1)
    _draw_meta(pdf, rows)

    pdf.ln(2)
    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(*INK)
    pdf.cell(0, 7, "Overall risk")
    pdf.ln(7)
    boxcol = _sev_pdf("critical" if label == "Critical" else
                      "high" if label == "High" else
                      "medium" if label == "Medium" else
                      "low" if label != "No issues" else "info")
    pdf.set_fill_color(*boxcol)
    pdf.set_draw_color(255, 255, 255)
    pdf.rect(16, pdf.get_y(), 58, 14, style="F")
    pdf.set_xy(16, pdf.get_y() + 3)
    pdf.set_font("helvetica", "B", 12)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(58, 8, _clean("%s / 10   %s" % (score, label)), align="C")
    pdf.ln(16)
    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(*INK)
    pdf.cell(0, 7, "Executive summary")
    pdf.ln(7)
    total = sum(_counts([]).values())
    pdf.set_font("helvetica", "", 9)
    pdf.multi_cell(0, 5, _clean(
        "This report documents the outcome of the %s security assessment "
        "performed against %s. Every issue below is ranked by severity and "
        "supported by evidence captured during the engagement, followed by "
        "specific remediation guidance. See the findings section for "
        "technical detail and the appendices for the agreed severity model."
        % (brand["product"], (target.address if target else "-"))))


def build_pdf(scan, target, findings, engine_label, user):
    pdf = Report()
    pdf.alias_nb_pages()
    brand = pdf.brand
    counts = _counts(findings)
    total = sum(counts.values())
    score, label = _risk_score(counts)
    bundle = (scan.stats or {}).get("bundle_dir", "")
    ranked = _ranked(findings)
    mains = [f for f in ranked if (f.severity or "info").lower() != "info"]
    obs = [f for f in ranked if (f.severity or "info").lower() == "info"]
    when = _fmt(datetime.datetime.now(datetime.timezone.utc))

    rows = [
        ("Target", (target.address if target else "") or "-"),
        ("Target kind", (target.kind if target else "") or "-"),
        ("Engine", engine_label or scan.engine_id),
        ("Profile", scan.profile),
        ("Scan ID", "#%s" % scan.id),
    ]
    if target and target.authorization_proof:
        rows.insert(2, ("Authorization", target.authorization_proof[:80]))
    rows += [
        ("Started", _fmt(scan.started_at or scan.created_at)),
        ("Finished", _fmt(scan.finished_at)),
        ("Duration", _duration(scan)),
        ("Status", ("Completed" if scan.status == "completed"
                    else scan.status)),
        ("Analyzed by", (user.display_name or user.username) if user else "-"),
    ]

    # ----- cover -----
    pdf.add_page()
    _pdf_cover(pdf, brand, scan, target, engine_label, score, label,
               when, rows)
    if total:
        pdf.ln(2)
        _severity_chart(pdf, counts)
    else:
        pdf.ln(2)
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(*MUTE)
        pdf.cell(0, 6, "No security findings were recorded by this scan.")

    # ----- table of contents -----
    pdf.add_page()
    pdf.set_font("helvetica", "B", 14)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, "Table of contents")
    pdf.ln(10)
    if not ranked:
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(*MUTE)
        pdf.cell(0, 6, "No findings to list.")
        pdf.ln(8)
    for idx, f in enumerate(ranked, 1):
        _maybe_page(pdf)
        pdf.set_fill_color(*_sev_pdf(f.severity))
        pdf.rect(16, pdf.get_y(), 4, 5.4, style="F")
        pdf.set_xy(22, pdf.get_y())
        pdf.set_font("helvetica", "", 8.5)
        pdf.set_text_color(*INK)
        pdf.cell(0, 5.4, _clean("%d.  %s" % (idx, f.title or
                                             "(untitled finding)"), limit=118))
        pdf.ln(5.9)
    pdf.ln(7)
    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(*INK)
    pdf.cell(0, 7, "Sections")
    pdf.ln(7)
    pdf.set_font("helvetica", "", 9)
    for line in ("1. Introduction & scope", "2. Methodology",
                 "3. Findings (severity ranked)",
                 "4. Observations (informational)",
                 "5. Appendix - severity definitions",
                 "6. Appendix - engagement record"):
        _maybe_page(pdf)
        pdf.cell(0, 6, _clean(line))
        pdf.ln(6)

    # ----- body -----
    pdf.body = True
    pdf.add_page()
    pdf.set_font("helvetica", "B", 14)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, "1. Introduction & scope")
    pdf.ln(9)
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(*INK)
    pdf.multi_cell(0, 5, _clean(
        "This report documents the %s security assessment performed against "
        "%s (%s). The scan used the '%s' engine profile and recorded every "
        "finding with proof-of-concept evidence gathered during the "
        "engagement. Findings should be retested after remediation is "
        "deployed, and severities re-evaluated in the context of the "
        "organization's own risk appetite."
        % (scan.engine_id, (target.address if target else "-"),
           (target.kind if target else "-"), scan.profile)))
    _maybe_page(pdf)
    _label(pdf, "2. Methodology")
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(*INK)
    pdf.multi_cell(0, 5, _clean(
        "Assessment was executed in automated phases: discovery and "
        "reconnaissance, service and technology fingerprinting, vulnerability "
        "identification, and exploitation with proof-of-concept evidence "
        "capture. Each reported issue is backed by the evidence observed at "
        "scan time, and its confidence indicates how strongly that evidence "
        "supports the conclusion. Post-delivery, findings are tracked through "
        "a triage lifecycle in the platform."))
    pdf.ln(3)

    _maybe_page(pdf)
    pdf.set_font("helvetica", "B", 14)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, "3. Findings")
    pdf.ln(9)
    if mains:
        for i, f in enumerate(mains, 1):
            _pdf_finding(pdf, i, len(mains), f, bundle)
    else:
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(*MUTE)
        pdf.cell(0, 6, "No findings above informational severity.")
        pdf.ln(8)

    pdf.add_page()
    pdf.set_font("helvetica", "B", 14)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, "4. Observations (informational)")
    pdf.ln(9)
    if obs:
        for i, f in enumerate(obs, 1):
            _pdf_finding(pdf, i, len(obs), f, bundle)
    else:
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(*MUTE)
        pdf.cell(0, 6, "No informational observations were recorded.")
        pdf.ln(8)

    # ----- appendices -----
    pdf.add_page()
    pdf.set_font("helvetica", "B", 14)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, "5. Appendix - severity definitions")
    pdf.ln(10)
    definitions = [
        ("Critical", "Immediate exploitable risk with high-impact compromise "
                     "possible (remote code execution, credential theft, "
                     "large data exposure)."),
        ("High", "Serious weakness with realistic exploitation and material "
                 "business impact."),
        ("Medium", "Meaningful weakness requiring an additional condition or "
                   "limited preconditions to be exploited."),
        ("Low", "Limited impact or difficult to exploit; defense-in-depth "
                "improvement."),
        ("Info", "Informational observation or hardening hint with no direct "
                 "exploitability."),
    ]
    for name, desc in definitions:
        _maybe_page(pdf)
        col = SEVERITY_PDF[name.lower()]
        pdf.set_fill_color(*col)
        pdf.rect(16, pdf.get_y(), 34, 6.4, style="F")
        pdf.set_xy(16, pdf.get_y())
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("helvetica", "B", 8)
        pdf.cell(34, 6.4, "%s" % name.upper(), align="C")
        pdf.set_xy(56, pdf.get_y())
        pdf.set_text_color(*INK)
        pdf.set_font("helvetica", "", 8.5)
        pdf.multi_cell(0, 5, _clean(desc, limit=220))
        pdf.ln(2)

    pdf.ln(2)
    pdf.set_font("helvetica", "B", 14)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, "6. Appendix - engagement record")
    pdf.ln(9)
    _draw_meta(pdf, rows)
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(*INK)
    pdf.ln(2)
    pdf.multi_cell(0, 5, _clean(
        "Scan findings: %d total (%d actionable). Overall risk: %s / 10 (%s). "
        "This report was generated on %s by the %s platform and reflects the "
        "state of the target at the time of the scan. It is confidential and "
        "intended solely for the party that authorized the engagement; "
        "redistribution requires permission from the issuer."
        % (total, len(mains), score, label, when, brand["product"])))

    return bytes(pdf.output())


# ---------------------------------------------------------------------------
# HTML report (self-contained, built from the database)
# ---------------------------------------------------------------------------

def _html_img(bundle, rel):
    png = os.path.join(bundle, rel) if bundle else rel
    if not os.path.isfile(png):
        return None
    try:
        with open(png, "rb") as fh:
            data = base64.b64encode(fh.read()).decode("ascii")
        ext = os.path.splitext(png)[1].lower().lstrip(".") or "png"
        mime = "jpeg" if ext in ("jpg", "jpeg") else "png"
        return "data:image/%s;base64,%s" % (mime, data)
    except Exception:
        return None


def _style_css(pkey, pacc):
    return """\
:root{--pkey:%s;--pacc:%s;--text:#1f2937;--muted:#64748b;--line:#e2e8f0;
--bg:#f4f6fa;--card:#fff;}
*{box-sizing:border-box;}
body{margin:0;font-family:'Segoe UI',system-ui,-apple-system,Roboto,Arial,sans-serif;
background:var(--bg);color:var(--text);font-size:14px;line-height:1.58;}
.page{max-width:880px;margin:0 auto;padding:34px 26px 70px;}
.cover{background:linear-gradient(135deg,%s,%s);color:#fff;border-radius:16px;
padding:44px 40px;margin-bottom:26px;}
.cover h1{margin:6px 0 2px;font-size:30px;letter-spacing:-.02em;}
.cover .tag{opacity:.88;font-size:13px;}
.cover .risk{display:flex;gap:26px;margin-top:26px;align-items:center;flex-wrap:wrap;}
.risk .score{font-size:46px;font-weight:800;line-height:1;}
.risk .rlabel{font-size:12px;opacity:.9;text-transform:uppercase;letter-spacing:.1em;margin-top:2px;}
h2.sec{font-size:19px;margin:34px 0 12px;padding-bottom:8px;border-bottom:2px solid var(--pacc);color:%s;}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin-bottom:18px;}
table.meta{width:100%%;border-collapse:collapse;}
table.meta th,table.meta td{text-align:left;padding:7px 12px;font-size:13px;border-bottom:1px solid var(--line);}
table.meta th{width:150px;color:var(--muted);font-weight:600;}
.sevrow{display:flex;align-items:center;gap:12px;margin-bottom:10px;}
.sevrow .lbl{width:80px;font-weight:700;text-transform:uppercase;font-size:12px;}
.sevrow .track{flex:1;height:12px;background:#e8edf4;border-radius:7px;overflow:hidden;}
.sevrow .track i{display:block;height:100%%;border-radius:7px;}
.sevrow .cnt{width:36px;color:var(--muted);font-weight:700;}
ul.toc{list-style:none;margin:0;padding:0;}
ul.toc li{padding:9px 4px;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:center;}
ul.toc .dot{width:10px;height:10px;border-radius:50%%;flex:0 0 10px;}
ul.toc a{color:var(--text);text-decoration:none;}
ul.toc a:hover{color:var(--pacc);}
.finding{background:var(--card);border:1px solid var(--line);border-radius:12px;margin-bottom:20px;overflow:hidden;}
.finding .fhead{display:flex;justify-content:space-between;align-items:center;padding:11px 18px;font-weight:700;font-size:12px;letter-spacing:.06em;color:#fff;}
.finding.critical .fhead{background:%s;}
.finding.high .fhead{background:%s;}
.finding.medium .fhead{background:%s;}
.finding.low .fhead{background:%s;}
.finding.info .fhead{background:%s;}
.finding .fhead .sev{text-transform:uppercase;}
.finding .fhead .ref{opacity:.9;font-weight:500;}
.finding h3{margin:0;padding:16px 18px 4px;font-size:17px;}
ul.meta{list-style:none;display:grid;grid-template-columns:1fr 1fr;margin:4px 18px 6px;padding:0;}
ul.meta li{display:flex;gap:8px;font-size:12.5px;padding:3px 0;}
ul.meta .k{color:var(--muted);min-width:76px;}
.finding .p{padding:2px 18px 8px;}
.finding h4{margin:13px 0 4px;font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;}
.finding pre{background:#0f172a;color:#dbe7ff;border-radius:8px;padding:12px 14px;
font:12.5px/1.55 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word;
max-height:440px;overflow:auto;}
.finding figure{margin:6px 0;}
.finding figure img{max-width:100%%;border:1px solid var(--line);border-radius:8px;}
.finding figure figcaption{font-size:11.5px;color:var(--muted);margin-top:4px;}
.finding .fix{background:#eefbf0;border:1px solid #cfead6;color:#14532d;border-radius:8px;padding:10px 12px;white-space:pre-wrap;}
.empty{color:var(--muted);padding:10px 4px;}
footer{text-align:center;color:var(--muted);font-size:12px;margin-top:40px;padding-top:14px;border-top:1px solid var(--line);}
@media print{body{background:#fff;}.cover{border-radius:0;}}
@media (max-width:640px){ul.meta{grid-template-columns:1fr;}}""" % (
        pkey, pacc, pkey, pacc, pkey,
        SEVERITY_HEX["critical"], SEVERITY_HEX["high"],
        SEVERITY_HEX["medium"], SEVERITY_HEX["low"], SEVERITY_HEX["info"])


def _html_finding(f, fnum, bundle):
    sev = (f.severity or "info").lower()
    ev = f.evidence if isinstance(f.evidence, dict) else {}
    meta = [
        ("Asset", f.asset or "-"),
        ("Module", _module_label(f) or "-"),
        ("Category", f.category or "-"),
        ("Status", STATUS_LABEL.get(f.status, f.status or "-")),
        ("Confidence", CONFIDENCE_LABEL.get(f.confidence,
                                            (f.confidence or "-").title())),
        ("CVSS", f.cvss or "-"),
        ("CWE", f.cwe or "-"),
    ]
    meta_rows = "\n".join(
        "<li><span class='k'>%s</span><span>%s</span></li>"
        % (_esc(k), _esc(v)) for k, v in meta)
    shots = ""
    for rel in ev.get("screenshots") or []:
        src = _html_img(bundle, rel)
        cap = _esc(os.path.basename(rel))
        if not src:
            continue
        shots += "<figure><img src='%s' alt='%s'><figcaption>%s</figcaption>" \
                 "</figure>" % (src, cap, cap)
    detail = ("<div class='p'><h4>Description</h4><p>%s</p></div>"
              % _esc(f.detail)) if f.detail else ""
    evidence = ("<div class='p'><h4>Evidence / proof of concept</h4>"
                "<pre>%s</pre></div>" % _esc(ev.get("text"))
                ) if ev.get("text") else ""
    remediation = ("<div class='p'><h4>Remediation</h4><div class='fix'>%s"
                   "</div></div>" % _esc(f.remediation)
                   ) if f.remediation else ""
    note = ("<div class='p'><h4>Triage note</h4><p class='muted'>%s</p></div>"
            % _esc(f.state_note)) if f.state_note else ""
    return ("<article class='finding %s' id='f%d'>"
            "<div class='fhead'><span class='sev'>%s</span>"
            "<span class='ref'>Finding %d%s</span></div>"
            "<h3>%s</h3><ul class='meta'>%s</ul>%s%s%s%s%s</article>"
            % (sev, fnum, _esc(sev).upper(), fnum,
               (" &middot; [%s]" % _esc(f.ref)) if f.ref else "",
               _esc(f.title or "(untitled finding)"), meta_rows,
               detail, evidence, shots, remediation, note))


def build_html(scan, target, findings, engine_label, user):
    brand = BRAND
    counts = _counts(findings)
    total = sum(counts.values())
    score, label = _risk_score(counts)
    bundle = (scan.stats or {}).get("bundle_dir", "")
    ranked = _ranked(findings)
    mains = [f for f in ranked if (f.severity or "info").lower() != "info"]
    obs = [f for f in ranked if (f.severity or "info").lower() == "info"]
    pkey = brand["colors"]["primary"]
    pacc = brand["colors"]["accent"]
    risk_color = _sev_hex("critical" if label == "Critical" else
                          "high" if label == "High" else
                          "medium" if label == "Medium" else
                          "low" if label != "No issues" else "info")
    when = _fmt(datetime.datetime.now(datetime.timezone.utc))

    bars = ""
    nb = max(1, total)
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        pct = 100.0 * n / nb
        bars += ("<div class='sevrow'><span class='lbl' style='color:%s'>%s"
                 "</span><div class='track'><i style='width:%.1f%%;background:"
                 "%s'></i></div><span class='cnt'>%d</span></div>"
                 % (_sev_hex(sev), sev.title(), min(100.0, pct),
                    _sev_hex(sev), n))

    meta_rows = [
        ("Target", (target.address if target else "-")),
        ("Target kind", (target.kind if target else "-")),
        ("Engine", engine_label or scan.engine_id),
        ("Profile", scan.profile),
        ("Scan ID", "#%s" % scan.id),
    ]
    if target and target.authorization_proof:
        meta_rows.insert(2, ("Authorization", target.authorization_proof))
    meta_rows += [
        ("Started", _fmt(scan.started_at or scan.created_at)),
        ("Finished", _fmt(scan.finished_at)),
        ("Duration", _duration(scan)),
        ("Status", ("Completed" if scan.status == "completed"
                    else scan.status)),
        ("Analyzed by", (user.display_name or user.username) if user else "-"),
    ]
    meta_html = "".join("<tr><th>%s</th><td>%s</td></tr>"
                        % (_esc(k), _esc(v)) for k, v in meta_rows)

    toc = "".join(
        "<li><span class='dot' style='background:%s'></span>"
        "<a href='#f%d'>%s</a></li>"
        % (_sev_hex(f.severity), i, _esc(f.title or "(untitled finding)"))
        for i, f in enumerate(ranked, 1))

    findings_html = "".join(_html_finding(f, i, bundle)
                            for i, f in enumerate(mains, 1))
    obs_html = "".join(_html_finding(f, i, bundle)
                       for i, f in enumerate(obs, 1))

    css = _style_css(pkey, pacc)
    return ("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>%s - Security Assessment Report</title><style>%s</style>"
            "</head><body><div class='page'>"
            "<div class='cover'><div class='tag'>%s</div>"
            "<h1>Security Assessment Report</h1>"
            "<div class='tag'>Generated %s</div>"
            "<div class='risk'><div><div class='score' style='color:%s'>%s</div>"
            "<div class='rlabel' style='color:%s'>%s risk</div></div></div>"
            "</div>"
            "<div class='panel'><h2 class='sec'>Assessment summary</h2>"
            "<table class='meta'>%s</table></div>"
            "<div class='panel'><h2 class='sec'>Executive summary</h2>"
            "<p>The %s security assessment of %s identified %d finding%s, "
            "rated <b>%s / 10 (%s)</b> overall. Issues are ranked by severity "
            "below and backed by evidence captured during the engagement, "
            "with remediation guidance provided for each item.</p>"
            "<div style='margin-top:14px'>%s</div></div>"
            "<div class='panel'><h2 class='sec'>Findings</h2>"
            "<ul class='toc'>%s</ul></div>"
            "<h2 class='sec'>Findings (severity ranked)</h2>%s"
            "<h2 class='sec'>Observations (informational)</h2>%s"
            "<h2 class='sec'>Appendix - severity model</h2>"
            "<div class='panel'><p>The following model is used to map "
            "severity:</p></div><footer>Confidential - authorized security "
            "testing only. Generated by %s.</footer></div></body></html>"
            % (_esc(brand["product"]), css, _esc(brand["tagline"]), when,
               risk_color, score, risk_color, _esc(label), meta_html,
               _esc(brand["product"]), _esc(target.address if target else "-"),
               total, "" if total == 1 else "s", score, _esc(label), bars,
               toc, findings_html, obs_html or "<div class='empty'>No "
               "informational observations were recorded.</div>",
               _esc(brand["product"]))).encode("utf-8")
