"""VAJRA web.ai_assist — AI remediation + next-attack planning over the run's
findings.

Runs only when AI is enabled (--ai) and a local model is reachable. It is a
strictly advisory, offline-safe assist: if the model is unreachable it silently
does nothing and emits no findings. Output is written as `ai_assist.json` in the
target's report directory and appended to the run narrative; nothing here is
ever reported as a vulnerability, so it cannot cause a false positive."""
import json
import os

from core.database import Finding

MAX_FINDINGS = 12

SYSTEM = ("You are VAJRA's remediation advisor. For each finding give a short, "
          "actionable, specific fix and a one-line worst-case impact. Be "
          "concise and practical; never invent findings.")


def _severity_weight(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3,
            "info": 4}.get(sev, 5)


def _assist(engine, tdir):
    findings = engine.db.findings(engine.target.display)
    fs = sorted(findings, key=lambda f: (0 if f["severity"] == "critical"
                                         else 1))[:MAX_FINDINGS]
    if not fs:
        return
    ai = engine.ai
    if not ai.available(refresh=True):
        return None
    rem = []
    for f in fs:
        prompt = ("Finding: [%s] %s\n%s\nGive fix + impact." % (
            f["severity"], f["title"], (f.get("detail") or "")[:400]))
        text = ai.ask(prompt, system=SYSTEM, max_tokens=180)
        if text:
            rem.append({"id": f.get("id") or f["title"], "title": f["title"],
                        "severity": f["severity"], "remediation": text[:600],
                        "url": f.get("url") or ""})
    summary = "\n".join("- [%s] %s" % (f["severity"], f["title"]) for f in fs)
    acts = ai.plan_actions(summary)
    result = {"target": engine.target.display,
              "advisory_only": True,
              "remediations": rem,
              "next_actions": acts[:8]}
    path = os.path.join(tdir, "ai_assist.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    if rem or acts:
        engine.log.info("AI assist: %d remediation drafts, %d next actions"
                        % (len(rem), len(acts)))
        engine.db.add_finding(Finding(
            engine.target.display, "web.ai_assist", "advisory", "info",
            "AI remediation assist prepared",
            detail="Full per-finding remediation and next-attack plan written "
                   "to ai_assist.json in the report directory.",
            evidence="%d remediation drafts, %d next actions"
                     % (len(rem), len(acts)),
            confidence="firm"))
    return result


def run(engine):
    try:
        tdir = engine.target_dirs.get(engine.target.display)
        if not tdir or not engine.ai.enabled:
            return
        _assist(engine, tdir)
    except Exception as e:
        engine.log.debug("ai_assist skipped: %r" % e)
