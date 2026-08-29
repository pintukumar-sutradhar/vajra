#!/usr/bin/env python3
"""cve — query the built-in vulnerability database (100% offline).

usage:  cve.py -s apache            list products with 'apache'
        cve.py -p apache -v 2.4.49  which CVEs hit version 2.4.49
        cve.py --all                product count+catalog
"""
import argparse
import re
import sys

try:
    from _core import c, ok, err, hr, data, load_json
except ImportError:
    from tools._core import c, ok, err, hr, data, load_json


def ver_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v)))


def range_matches(oprn, version):
    m = re.match(r"^(<=|>=|<|>|==|=)\s*(.*)$", oprn.strip())
    if not m:
        return False
    op, bound = m.group(1), ver_tuple(m.group(2))
    v = ver_tuple(version)
    n = min(len(v), len(bound))
    a, b = v[:n], bound[:n]
    if len(a) < len(b):
        a = a + (0,) * (len(b) - len(a))
    elif len(b) < len(a):
        b = b + (0,) * (len(a) - len(b))
    return {"<=": a <= b, "<": a < b, ">=": a >= b, ">": a > b,
            "==": a == b, "=": a == b}.get(op, False)


def main():
    ap = argparse.ArgumentParser(prog="cve")
    ap.add_argument("-s", "--search", help="product-name substring")
    ap.add_argument("-p", "--product")
    ap.add_argument("-v", "--version")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    db = load_json("intel/cve_db.json", {}).get("products", {})
    if args.all:
        print(c("%d products in knowledge base" % len(db), bold=True))
        for key in sorted(db):
            print("  %-22s %s" % (key, db[key].get("product", key)))
        return 0
    if args.search:
        sub = args.search.lower()
        keys = [k for k in db if sub in k.lower() or
                sub in (db[k].get("product", "").lower())]
        if not keys:
            err("no product matches %r" % args.search)
            return 1
        print(c("%d match(es) for %r:" % (len(keys), args.search), bold=True))
        for k in keys:
            print("  %-22s %s" % (k, db[k].get("product", "")))
        return 0
    if args.product:
        cfg = db.get(args.product.lower())
        if not cfg:
            aliases = [cfg for k, cfg in db.items()
                       if args.product.lower() in
                       [a.lower() for a in (cfg.get("aliases") or [])]]
            cfg = aliases[0] if aliases else None
        if not cfg:
            err("unknown product %r (use -s to search)" % args.product)
            return 1
        print(c("%s: %s" % (args.product, cfg.get("product", "?")), bold=True))
        ranges = cfg.get("ranges") or {}
        if args.version:
            hits = [(rng, cves) for rng, cves in ranges.items()
                    if range_matches(rng, args.version)]
            print("CVEs affecting version %s:" % args.version)
            for rng, cves in hits:
                hr(58)
                for cv in cves:
                    parts = cv.split("|")
                    ident = parts[0]
                    desc = parts[1] if len(parts) > 1 else ""
                    score = parts[2] if len(parts) > 2 else ""
                    col = "\033[91m" if ident.startswith("CVE-2021-41773") \
                        or "RCE" in desc else "\033[93m"
                    print("  %s %-20s %-45s CVSS %s" %
                          (c("[%s]" % rng, dim=True), c(ident, color=col),
                           desc[:48], score))
        else:
            print("%d version range rule(s):" % len(ranges))
            for rng, cves in list(ranges.items())[:20]:
                print("  %-14s %d CVE(s)" % (rng, len(cves)))
            print("  (pass -v VERSION to resolve)")
        return 0
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())