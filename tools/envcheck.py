#!/usr/bin/env python3
"""envcheck — resolve & report the external tooling matrix on this host.

usage:  envcheck.py            summary table
        envcheck.py -m         markdown report
        envcheck.py -c web     single category
"""
import argparse
import os
import shutil
import sys

try:
    from _core import c, ok, err, hr, load_json
except ImportError:
    from tools._core import c, ok, err, hr, load_json

SHIMS = {
    "impacket-secretsdump": None, "impacket-GetUserSPNs": None,
}


def resolve(binname):
    if shutil.which(binname):
        return binname
    return None


def main():
    ap = argparse.ArgumentParser(prog="envcheck")
    ap.add_argument("-m", "--markdown", action="store_true")
    ap.add_argument("-c", "--category")
    args = ap.parse_args()

    cats = load_json("config/tooling.json", {}).get("categories", {})
    if args.category and args.category not in cats:
        err("unknown category %r (have: %s)" % (args.category,
                                                ", ".join(sorted(cats))))
        return 1
    report = []
    total_present = total_known = 0
    for cat in sorted(cats if not args.category else [args.category]):
        spec = cats[cat]
        tools = spec["tools"]
        present, missing = [], []
        for t in tools:
            total_known += 1
            hit = resolve(t)
            if hit:
                present.append(t)
                total_present += 1
            else:
                missing.append(t)
        if args.markdown:
            report.append("### %s\n" % spec["label"])
            report.append("PRESENT: %s\n" % ("`" + "` `".join(present)
                                             if present else "_none_"))
            report.append("MISSING: %s\n" % (", ".join(missing)
                                             if missing else "_all_"))
        else:
            report.append(c("%s [%s]" % (spec["label"], cat), bold=True))
            report.append("  present: %s" % (
                c(", ".join(present), color="\033[92m") if present else "  none"))
            if missing:
                report.append("  missing: %s" % c(", ".join(missing),
                                                  color=None, dim=True))
            if args.category:
                report.append("  %d/%d available" % (len(present),
                                                     len(present) + len(missing)))
    if not args.markdown:
        hr()
        report.append("%d/%d tool(s) available%s" % (
            total_present, total_known,
            "" if total_present >= max(5, total_known // 2) else
            " — check setup.sh"))
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())