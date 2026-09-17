"""Vajra - email harvesting from crawled content."""
import re

from core import proof as P
from core.utils import extract_emails


def run(engine):
    t = engine.target
    emails = set(engine.state.get("emails", []))
    for page in engine.state.get("pages", []):
        emails |= extract_emails(page.get("body", ""))
    meta_emails = set()
    for page in engine.state.get("pages", []):
        for m in re.finditer(r"mailto:([^\"'>\s]+)", page.get("body", ""), re.I):
            meta_emails.add(m.group(1).lower())
    emails |= meta_emails
    emails = {e for e in emails if "." in e and "@" in e}
    engine.state["emails"] = sorted(emails)
    if emails:
        ev = "\n".join(sorted(emails)[:50])
        engine.record(
            t.display, "recon.emails", "osint", "low",
            "Email addresses exposed on site: %d" % len(emails),
            detail="Exposed emails aid phishing/social-engineering recon.",
            evidence=ev,
            cls="other",
            proof=P.observation(ev))
