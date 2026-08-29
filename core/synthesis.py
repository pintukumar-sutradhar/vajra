"""VAJRA synthesis layer — deterministic run narrative, cross-host campaign
correlation and the cumulative AI-brain write-up. Runs with zero LLM
dependencies; the output is also fed to the AI operator as prior context."""
import datetime

from core.database import SEV_ORDER

SEV_SHORT = {"critical": "crit", "high": "high", "medium": "med",
             "low": "low", "info": "info"}


def auto_narrative(stats, findings, services, targets, score, grade):
    """Deterministic human-readable executive narrative."""
    total = sum(stats.values())
    critical = stats.get("critical", 0)
    high = stats.get("high", 0)
    lines = []
    if total == 0:
        lines.append("No findings were recorded during this assessment; the "
                     "tested attack surface showed no exploitable condition "
                     "the scanner could confirm.")
        return "\n".join(lines)
    sev_words = []
    if critical:
        sev_words.append("%d critical" % critical)
    if high:
        sev_words.append("%d high" % high)
    lines.append(
        "Scan of %s produced %d finding(s) (%s), for an overall risk score "
        "of %.1f/100 (grade %s)."
        % (", ".join(t.get("display", "") for t in targets), total,
           ", ".join(sev_words) or "no critical/high", score, grade))
    if critical or high:
        lines.append(
            "Immediate exposure exists. Priority should go to the %s finding"
            "(s) marked %s before expanding the engagement."
            % (critical + high, "critical/high"))
    tops = [f for f in findings
            if f.get("severity") in ("critical", "high")][:6]
    if tops:
        lines.append("Highest-signal items:")
        lines.append("\n".join(
            "  - [%s] %s (%s)" % (SEV_SHORT.get(f.get("severity"), "?"),
                                  f.get("title", ""), f.get("module", ""))
            for f in tops))
    web = sum(1 for s in services if s.get("port") in (80, 443, 8080, 8443)
              or (s.get("service", "").lower().find("http") >= 0))
    if services:
        lines.append("%d service(s) exposed; %d web/app tier(s) in scope."
                     % (len(services), web))
    return "\n".join(lines)


def correlate_across(findings):
    """Cross-host campaign pattern: identical module+title on >=2 distinct
    targets is a 'spread' pattern worth escalating."""
    from collections import defaultdict
    groups = defaultdict(list)
    for f in findings:
        if f.get("severity") == "info":
            continue
        groups[(f.get("module"), f.get("title"))].append(
            f.get("target", "?"))
    out = []
    for (module, title), targets in groups.items():
        if len(set(targets)) >= 2:
            out.append({"module": module, "title": title,
                        "hosts": sorted(set(targets)),
                        "count": len(set(targets))})
    out.sort(key=lambda o: -o["count"])
    return out


def build_brain_blocks(per_target, delta_summary=None, spread=None):
    """Human/AI-readable markdown summarizing an entire run."""
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    blocks = ["## Run %s" % stamp]
    for disp, tgt in per_target.items():
        fs = tgt.get("findings", [])
        if not fs:
            blocks.append("- **%s**: clean (no findings)" % disp)
            continue
        n_c = sum(1 for f in fs if f.get("severity") == "critical")
        n_h = sum(1 for f in fs if f.get("severity") == "high")
        blocks.append("- **%s**: %d finding(s) [%d crit, %d high] score=%s"
                      % (disp, len(fs), n_c, n_h, tgt.get("score", "-")))
        for f in sorted(fs,
                        key=lambda x: -x.get("severity", "info").count("x"))[:5]:
            blocks.append("    - [%s] %s" % (f.get("severity"),
                                             f.get("title", "")))
    if delta_summary:
        blocks.append("Retest delta (vs previous snapshot): %d new, "
                      "%d fixed, %d still-open."
                      % (delta_summary.get("new", 0),
                         delta_summary.get("fixed", 0),
                         delta_summary.get("still", 0)))
    if spread:
        blocks.append("Campaign patterns: " + ("; ".join(
            "%s on %d host(s)" % (p["title"][:48], p["count"])
            for p in spread[:5]) or "none"))
    return "\n".join(blocks)