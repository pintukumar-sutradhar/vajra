"""Branded PDF report generation (pure Python, fpdf2)."""

import datetime

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
STATUS_LABEL = {
    "open": "Open",
    "triaged": "Triaged",
    "false-positive": "False Positive",
    "accepted-risk": "Accepted Risk",
    "fixed": "Fixed",
}

PRIMARY = tuple(int(BRAND["colors"]["primary"][i:i+2], 16)
                for i in (1, 3, 5))
ACCENT = tuple(int(BRAND["colors"]["accent"][i:i+2], 16)
               for i in (1, 3, 5))
INK = (30, 41, 59)
MUTE = (100, 116, 139)
LINE = (203, 213, 225)


def _clean(value, limit=None):
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = text.replace("\x00", "").replace("\ufffd", "?")
    encoded = text.encode("latin-1", errors="replace").decode("latin-1")
    if limit and len(encoded) > limit:
        encoded = encoded[:limit]
    return encoded


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
        self.set_xy(16, 3)
        self.cell(40, 5, _clean(self.brand["product"]))
        self.set_font("helvetica", "", 8)
        self.set_text_color(203, 213, 225)
        self.cell(0, 5, _clean(self.brand["tagline"]), align="R")
        self.set_y(16)

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


def _duration(scan):
    try:
        start = scan.started_at or scan.created_at
        end = scan.finished_at or datetime.datetime.now(datetime.timezone.utc)
        total = int((end - start).total_seconds())
        h, r = divmod(total, 3600)
        m, s = divmod(r, 60)
        return "%dh %02dm %02ds" % (h, m, s) if h else "%02dm %02ds" % (m, s)
    except Exception:
        return "-"


def _fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M UTC") if ts else "-"


def _sev_colors(sev):
    return SEVERITY_COLOR.get((sev or "info").lower(), SEVERITY_COLOR["info"])


def _label(pdf, text):
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(*ACCENT)
    pdf.ln(3)
    pdf.cell(0, 6, _clean(text.upper()))
    pdf.ln(2)


def _maybe_page(pdf):
    if pdf.get_y() > 256:
        pdf.add_page()


def build_pdf(scan, target, findings, engine_label, user):
    pdf = Report()
    pdf.alias_nb_pages()
    brand = pdf.brand

    # ----- cover -----
    pdf.add_page()
    pdf.set_fill_color(*PRIMARY)
    pdf.rect(0, 0, 210, 42, style="F")
    pdf.set_fill_color(*ACCENT)
    pdf.rect(0, 42, 210, 1.5, style="F")
    pdf.set_xy(16, 12)
    pdf.set_font("helvetica", "B", 26)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 12, _clean(brand["product"]))
    pdf.set_font("helvetica", "", 11)
    pdf.set_text_color(203, 213, 225)
    pdf.ln(12)
    pdf.cell(0, 6, _clean(brand["tagline"]))

    pdf.set_xy(16, 58)
    pdf.set_font("helvetica", "B", 20)
    pdf.set_text_color(*INK)
    pdf.cell(0, 10, "Penetration Test Report")
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(*MUTE)
    pdf.ln(10)
    pdf.cell(0, 6, "Prepared by %s %s  |  Edition: %s" % (
        _clean(brand["company"] or brand["product"]),
        _clean(brand["edition"]), _clean(brand["edition"])))

    pdf.ln(10)
    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(*INK)
    pdf.cell(0, 7, "Assessment summary")
    pdf.ln(8)
    rows = [
        ("Target", (target.address if target else "") or "-"),
        ("Target kind", (target.kind if target else "") or "-"),
        ("Engine", engine_label or scan.engine_id),
        ("Profile", scan.profile),
        ("Scan ID", "#%s" % scan.id),
        ("Started", _fmt(scan.started_at or scan.created_at)),
        ("Finished", _fmt(scan.finished_at)),
        ("Duration", _duration(scan)),
        ("Status", scan.status),
        ("Analyzed by", (user.display_name or user.username) if user else "-"),
    ]
    for label, value in rows:
        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(*MUTE)
        pdf.cell(44, 6, _clean(label))
        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(*INK)
        pdf.cell(0, 6, _clean(value or "-"))
        pdf.ln(6)
    pdf.ln(2)

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = (f.severity or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    total = sum(counts.values())

    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(*INK)
    pdf.cell(0, 7, "Executive summary")
    pdf.ln(8)
    pdf.set_font("helvetica", "", 9)
    pdf.multi_cell(0, 5, _clean(
        "The %s assessment of %s identified %d finding%s. The engagement "
        "was performed against an authorized target to identify exploitable "
        "weaknesses across the application, infrastructure, and directory "
        "services layers. Findings are reported below with supporting "
        "evidence and remediation guidance."
        % (brand["product"], (target.address if target else "-"), total,
           "" if total == 1 else "s")))
    pdf.ln(4)

    # severity matrix (manual draw for precise color control)
    labels = []
    for sev in SEVERITY_ORDER:
        labels.append(("  %s" % sev.title(), counts[sev], _sev_colors(sev)))
    x0, block = 16, 32.6
    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(*INK)
    pdf.set_draw_color(255, 255, 255)
    for i, (name, n, color) in enumerate(labels):
        x = x0 + i * block
        pdf.set_fill_color(*color)
        pdf.rect(x, pdf.get_y(), block, 12, style="F")
        pdf.set_xy(x, pdf.get_y())
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("helvetica", "B", 13)
        pdf.cell(block, 8, str(n), align="C")
        pdf.set_xy(x, pdf.get_y() + 8)
        pdf.set_font("helvetica", "", 7)
        pdf.cell(block, 4, _clean(name), align="C")
        pdf.set_y(pdf.get_y() - 12)
    pdf.set_y(pdf.get_y() + 12)
    pdf.set_text_color(*INK)

    # ----- findings -----
    pdf.body = True
    pdf.add_page()
    ordered = sorted(findings, key=lambda f: (
        SEVERITY_ORDER.index((f.severity or "info").lower())
        if (f.severity or "info").lower() in SEVERITY_ORDER else 9,
        f.id or 0))
    for i, f in enumerate(ordered, 1):
        sev = (f.severity or "info").lower()
        sc = _sev_colors(sev)
        pdf.set_font("helvetica", "B", 10)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 6, "Finding %d of %d" % (i, len(ordered)))
        _maybe_page(pdf)
        line_y = pdf.get_y()
        pdf.set_fill_color(*sc)
        pdf.rect(16, line_y, 2.2, 9, style="F")
        pdf.set_xy(20, line_y)
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(*sc)
        pdf.cell(28, 8, sev.upper())
        ref = (f.ref or "finding").upper()
        pdf.set_font("helvetica", "", 8)
        pdf.set_text_color(*MUTE)
        pdf.cell(0, 8, "[%s]" % _clean(ref), align="R")
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(*INK)
        pdf.set_xy(20, line_y + 8)
        pdf.multi_cell(0, 5.5, _clean(f.title or "(untitled finding)"))
        pdf.ln(1)

        meta = []
        if f.asset:
            meta.append(("Asset", f.asset, 40))
        if f.confidence:
            meta.append(("Confidence", f.confidence, 20))
        if f.cvss:
            meta.append(("CVSS", f.cvss, 12))
        if f.cwe:
            meta.append(("CWE", f.cwe, 14))
        if f.category:
            meta.append(("Category", f.category, 22))
        if f.source_module:
            meta.append(("Module", f.source_module, 20))
        meta.append(("Status", STATUS_LABEL.get(f.status, f.status), 18))
        for k in range(0, len(meta), 2):
            chunk = meta[k:k + 2]
            _maybe_page(pdf)
            for label, value, width in chunk:
                pdf.set_font("helvetica", "B", 8)
                pdf.set_text_color(*MUTE)
                pdf.cell(20, 5, _clean(label))
                pdf.set_font("helvetica", "", 8)
                pdf.set_text_color(*INK)
                pdf.cell(width, 5, _clean(value, limit=42))
                pdf.cell(4, 5, "")
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
            pdf.multi_cell(0, 4, _clean(ev, limit=3200), fill=True, border=0)
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

        if i < len(ordered):
            _maybe_page(pdf)
            pdf.set_draw_color(*LINE)
            pdf.line(16, pdf.get_y(), 194, pdf.get_y())
            pdf.ln(4)

    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(*INK)
    pdf.ln(5)
    pdf.cell(0, 7, "About this report")
    pdf.ln(8)
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(*INK)
    pdf.multi_cell(0, 5, _clean(
        "This report was produced by %s %s. Findings reflect the state of "
        "the target at the time of the scan and are based on automated "
        "assessment combined with evidence captured during the engagement. "
        "Remediation should be prioritized by severity and validated with a "
        "follow-up scan after changes are deployed. This document is "
        "confidential and intended solely for the party that authorized the "
        "engagement." % (brand["product"], brand["edition"])))

    return bytes(pdf.output())