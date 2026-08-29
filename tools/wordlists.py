#!/usr/bin/env python3
"""wordlists — inspect, filter, merge, convert and generate attacker wordlists
reusing the framework generator.

usage:  wordlists.py list                catalog what ships
        wordlists.py info passwords.txt  stats for a file (any path or shipped)
        wordlists.py filter -i in.txt -o out.txt -l 6-24 -r '^[a-z]'
        wordlists.py merge -i a.txt -i b.txt -o merged.txt ...unique
        wordlists.py gen -t users|pass|dirs|subs   (invokes gen_wordlists)
"""
import argparse
import os
import re
import sys

try:
    from _core import c, ok, err, hr, data, PROJECT_ROOT
except ImportError:
    from tools._core import c, ok, err, hr, data, PROJECT_ROOT

SHIPPED = {p.stem: p for p in (PROJECT_ROOT / "wordlists").glob("*")}


def resolve_path(name):
    if os.path.exists(str(name)):
        return str(name)
    if name in SHIPPED:
        return str(SHIPPED[name])
    if (PROJECT_ROOT / "wordlists" / name).exists():
        return str(PROJECT_ROOT / "wordlists" / name)
    return None


def stream(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            yield ln.strip("\r\n")


def info(path):
    p = resolve_path(path)
    if not p:
        err("cannot resolve %r (use `list`)" % path)
        return 1
    total, lens, low, has_upper, has_digit = 0, {}, 0, 0, 0
    for ln in stream(p):
        total += 1
        lens[len(ln)] = lens.get(len(ln), 0) + 1
        if ln.islower():
            low += 1
        if re.search(r"[A-Z]", ln):
            has_upper += 1
        if re.search(r"\d", ln):
            has_digit += 1
    mini = min(lens) if lens else 0
    maxi = max(lens) if lens else 0
    print(c("%s (%d lines)" % (p, total), bold=True))
    print("  length range  %d..%d   median %d" % (mini, maxi,
                                                  sorted(lens.keys())[
                                                      len(lens) // 2]
                                                  if lens else 0))
    print("  lowercase-only %.1f%%  has-upper %.1f%%  has-digit %.1f%%" %
          (100.0 * low / max(1, total), 100.0 * has_upper / max(1, total),
           100.0 * has_digit / max(1, total)))
    return 0


def do_filter(args):
    p = resolve_path(args.input)
    if not p:
        err("cannot resolve input")
        return 1
    lo, hi = 0, 10 ** 9
    if args.length and "-" in args.length:
        a, b = args.length.split("-", 1)
        lo = int(a or 0)
        hi = int(b or 10 ** 9)
    rx = re.compile(args.regex) if args.regex else None
    out = 0
    with open(args.output, "w", encoding="utf-8") as f:
        for ln in stream(p):
            if lo <= len(ln) <= hi:
                if rx and not rx.search(ln):
                    continue
                f.write(ln + "\n")
                out += 1
    ok("filtered %d line(s) -> %s" % (out, args.output))
    return 0


def do_merge(args):
    seen, out = set(), 0
    with open(args.output, "w", encoding="utf-8") as f:
        for i in args.input:
            p = resolve_path(i)
            if not p:
                err("skip un-resolvable %r" % i)
                continue
            for ln in stream(p):
                if ln not in seen:
                    seen.add(ln)
                    f.write(ln + "\n")
                    out += 1
    ok("merged %d unique line(s) -> %s" % (out, args.output))
    return 0


def main():
    ap = argparse.ArgumentParser(prog="wordlists")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list")
    p_info = sub.add_parser("info")
    p_info.add_argument("path")
    p_f = sub.add_parser("filter")
    p_f.add_argument("-i", "--input", required=True)
    p_f.add_argument("-o", "--output", required=True)
    p_f.add_argument("-l", "--length")
    p_f.add_argument("-r", "--regex")
    p_m = sub.add_parser("merge")
    p_m.add_argument("-i", "--input", action="append", required=True)
    p_m.add_argument("-o", "--output", required=True)
    args = ap.parse_args()

    if args.cmd == "list":
        hr()
        print(c("shipped wordlists:", bold=True))
        for stem, p in sorted(SHIPPED.items()):
            size = os.path.getsize(p)
            first = None
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    first = f.readline().strip()
            except Exception:
                pass
            print("  %-20s %8d  sample: %s" % (stem, size, first or ""))
        print(c("generator:", bold=True))
        print("  tools/gen_wordlists.py  (builds all wordlists from rules)")
        return 0
    if args.cmd == "info":
        return info(args.path)
    if args.cmd == "filter":
        return do_filter(args)
    if args.cmd == "merge":
        return do_merge(args)
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())