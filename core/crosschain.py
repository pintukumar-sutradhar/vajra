"""VAJRA read-only AI cross-chaining (advisory).

Takes the *accumulated* findings across the whole run and asks an optionally
present AI operator to connect dots a fixed corpus can't: lateral chains
("the creds found in web1's .env are reused on web2"), post-conditions that
could follow, and priorities. This is strictly ADVISORY:

- It never writes a Finding and never edits severity/confidence/evidence
  (the anti-false-positive ladder in core.database stays authoritative).
- It never claims evidence the scan did not itself observe.
- It only runs when an AI backend is online, and it never blocks the scan
  (best-effort, short timeout, results cached).

Output is a clearly-flagged advisory written next to the run narrative and
dropped into the report as an "AI operator advisory" panel — not into the
findings table.
"""
import datetime

# System prompt keeps the operator on the read-only rails: correlate what the
# scan already proved, propose hypotheses that MUST be re-verified manually, and
# never assert a new vuln as fact.
_SYSTEM = (
    "You are VAJRA's read-only advisory analyst. You are given a pen-test's "
    "CONFIRMED findings only. Your job:\n"
    "1) Chain_connect only findings the scan already proved into attack paths "
    "    (evidence-grounded reasoning).\n"
    "2) Flag cross-host credential/credential-reuse or pivot opportunities the "
    "    raw list alone doesn't make obvious.\n"
    "3) Suggest at most 3 follow-on checks a human verifier should run.\n"
    "RULES: This is ADVICE. Never assert a new vulnerability as discovered. "
    "Never assign severity/confidence. Label every suggestion ADVICE. If you "
    "cannot ground a link in the listed evidence, say so instead of guessing."
)


def run_crosschain(ai, per_target, log=None, output_dir=None):
    """Best-effort read-only advisory. Returns markdown text (advisory) or ''.

    ai     : an AIEngine-like object with .available()/.ask().
    per_target : {display: {"findings":[...], "services":[...]}}
    """
    if ai is None or not getattr(ai, "available", lambda: False)():
        return ""
    lines = []
    for disp, tgt in per_target.items():
        fs = tgt.get("findings", [])
        if not fs:
            continue
        lines.append("### %s" % disp)
        for f in fs[:40]:
            lines.append("- [%s] %s" % (f.get("severity", "?"),
                                        (f.get("title", "") or "").strip()))
    if not lines:
        return ""
    payload = "\n".join(lines)
    prompt = (
        "Confirmed findings by host:\n%s\n"
        "\nProduce a short advisory (markdown) covering: (1) any evidence-grounded "
        "attack chain across these hosts, (2) credential-reuse or pivots, "
        "(3) up to 3 follow-on checks for a human verifier. Label everything "
        "ADVICE." % payload[:12000])
    try:
        raw = ai.ask(prompt, system=_SYSTEM, max_tokens=700)
    except Exception as e:
        if log:
            try:
                log.debug("[crosschain] advisory skipped: %r" % e)
            except Exception:
                pass
        return ""
    if not raw or not raw.strip():
        return ""
    out = [
        "## AI operator advisory (read-only)",
        "_Auto-generated at %s. ADVICE ONLY — not validated findings; every "
        "line must be manually re-verified. Not incorporated into the findings "
        "table, score, or severity._"
        % datetime.datetime.now().isoformat(timespec="seconds"),
        "",
        raw.strip(),
        "",
    ]
    md = "\n".join(out)
    if output_dir:
        import os
        try:
            os.makedirs(output_dir, exist_ok=True)
            with open(os.path.join(output_dir, "ai_advisory.md"), "w",
                      encoding="utf-8") as fh:
                fh.write(md)
        except Exception:
            pass
    if log:
        try:
            log.info("[crosschain] read-only AI advisory written (%d hosts)"
                     % len([l for l in lines if l.startswith("### ")]))
        except Exception:
            pass
    return md