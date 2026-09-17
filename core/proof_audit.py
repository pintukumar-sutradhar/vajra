#!/usr/bin/env python3
"""VAJRA — proof-gate completeness audit.

Two structural invariants, checked by reading source rather than by trusting
the modules to behave:

  1. **No module files a finding directly.** Every vulnerability finding must
     go through `engine.record(..., cls=..., proof=...)`, which is the only
     path that validates evidence. A direct `db.add_finding(...)` bypasses the
     gate entirely, so one remaining call site is one remaining way for a
     status code to become a high-severity finding.

  2. **Every `cls=` a module names has a rule.** An unregistered class means
     the gate cannot say what would prove it — the candidate would be
     suppressed, but silently and for the wrong reason. This makes the gap
     loud.

This is what answers "may there be many more?" by running a command instead
of by reading 15 000 lines, and it stays true as modules are added.

    python3 core/proof_audit.py           # census + pass/fail
    python3 core/proof_audit.py --list    # every offending site

Exit status is 0 only when both invariants hold.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import proof as P  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODULES = os.path.join(_ROOT, "modules")

_ADD_FINDING_RE = re.compile(r"\badd_finding\s*\(")
_RECORD_RE = re.compile(r"\.record\s*\(")
# A *literal* class name ("xss") is checkable statically. A *variable* value
# (cls=cls) is delegated to the runtime gate, which validates the resolved
# name and logs an ERROR for an unknown one — so it cannot file a finding
# behind the gate either. What must still be rejected is a record() call
# carrying NO cls= at all: a candidate with no way to pick a proof rule.
_CLS_RE = re.compile(r"\bcls\s*=\s*[\"']([^\"']+)[\"']")
_CLS_EXPR_RE = re.compile(r"\bcls\s*=\s*([^,\)]+)")


def sources():
    """(relpath, text) for every Python file under modules/."""
    out = []
    for dirpath, dirnames, filenames in os.walk(_MODULES):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    out.append((os.path.relpath(path, _ROOT), fh.read()))
            except OSError:
                continue
    return out


def _balanced(text, open_idx):
    """Return the arguments of the call whose '(' is at `open_idx`.

    Balanced-paren scan that respects string literals, so a nested call or a
    parenthesis inside a string does not truncate the window — which matters
    because the `cls=` we are looking for is usually the last argument.
    """
    depth = 0
    i = open_idx
    quote = None
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return ""


def _line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def _group(rel):
    """modules/web/x.py -> 'web'; modules/x.py -> '(root)'."""
    parts = rel.split(os.sep)
    return parts[1] if len(parts) > 2 else "(root)"


def audit():
    """Return a report dict. Never raises on a bad module."""
    direct = []       # (rel, line, snippet) — bypasses the gate
    noclss = []       # (rel, line)          — record() with no cls=
    unknown = []      # (rel, line, cls)     — cls= literal with no rule
    dynamic = []      # (rel, line, cls)     — cls= is an expression, not a
                        # literal: validated at runtime (unknown -> ERROR log)
                        # rather than statically
    records = 0
    files = 0
    by_group = {}

    for rel, text in sources():
        files += 1
        grp = _group(rel)
        bucket = by_group.setdefault(grp, {"files": 0, "direct": 0, "record": 0})
        bucket["files"] += 1

        for m in _ADD_FINDING_RE.finditer(text):
            line = _line_of(text, m.start())
            direct.append((rel, line, _snippet_line(text, line)))
            bucket["direct"] += 1

        for m in _RECORD_RE.finditer(text):
            args = _balanced(text, m.end() - 1)
            if not args:
                continue
            records += 1
            bucket["record"] += 1
            line = _line_of(text, m.start())
            cm = _CLS_RE.search(args)
            em = _CLS_EXPR_RE.search(args)
            if not em:
                noclss.append((rel, line))
            elif cm:
                if P.resolve_class(cm.group(1)) is None:
                    unknown.append((rel, line, cm.group(1)))
            else:
                dynamic.append((rel, line, em.group(1).strip()[:40]))

    return {
        "files": files,
        "records": records,
        "direct": direct,
        "noclss": noclss,
        "unknown": unknown,
        "dynamic": dynamic,
        "by_group": by_group,
        "ok": not direct and not noclss and not unknown,
    }


def _snippet_line(text, line):
    lines = text.splitlines()
    return (lines[line - 1].strip()[:90] if 0 < line <= len(lines) else "")


def report(rep, show_list=False):
    print("proof-gate audit — %d module file(s), %d record() call site(s)"
          % (rep["files"], rep["records"]))
    print("-" * 68)
    print("  %-12s %6s %8s %8s" % ("group", "files", "direct", "record"))
    for grp in sorted(rep["by_group"]):
        b = rep["by_group"][grp]
        flag = "  <-- unmigrated" if b["direct"] else ""
        print("  %-12s %6d %8d %8d%s"
              % (grp, b["files"], b["direct"], b["record"], flag))
    print("-" * 68)
    n_direct = len(rep["direct"])
    print("  direct db.add_finding() sites : %d%s"
          % (n_direct, "" if not n_direct else "   FAIL"))
    print("  record() without cls=         : %d%s"
          % (len(rep["noclss"]), "" if not rep["noclss"] else "   FAIL"))
    print("  cls= with no registered rule  : %d%s"
          % (len(rep["unknown"]), "" if not rep["unknown"] else "   FAIL"))
    print("  cls= as expression (runtime)  : %d%s"
          % (len(rep["dynamic"]),
             "   note" if rep["dynamic"] else ""))

    if show_list:
        for label, rows in (("DIRECT add_finding", rep["direct"]),
                            ("NO cls=", rep["noclss"]),
                            ("UNKNOWN cls", rep["unknown"]),
                            ("DYNAMIC cls (delegated to runtime)",
                             rep["dynamic"])):
            if not rows:
                continue
            print("\n%s:" % label)
            for row in rows:
                if len(row) == 3:
                    print("  %s:%d  %s" % (row[0], row[1], row[2]))
                else:
                    print("  %s:%d  (no cls)" % (row[0], row[1]))

    print("\n%s" % ("PASS — every finding goes through the proof gate"
                    if rep["ok"] else
                    "INCOMPLETE — %d site(s) still bypass or misdeclare the "
                    "gate" % (n_direct + len(rep["noclss"]) + len(rep["unknown"]))))
    return rep["ok"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--list", action="store_true",
                    help="list every offending call site")
    args = ap.parse_args(argv)
    return 0 if report(audit(), args.list) else 1


if __name__ == "__main__":
    raise SystemExit(main())
