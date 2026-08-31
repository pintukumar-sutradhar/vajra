#!/usr/bin/env python3
"""VAJRA - build a vast offline CVE database from the GitHub Advisory
Database (GHSA, OSV schema).

Usage:  python tools/build_cve_db.py /path/to/advisory-database-main.tar.gz

Merges every github-reviewed advisory into intel/cve_db.json under the
same schema the correlator already reads (products -> ranges -> CVE|summary|cvss),
converting OSV introduced/fixed SEMVER windows into <= / >= operators.
Existing curated entries (CMS/infra) are preserved. Deterministic output."""
import json
import os
import re
import sys
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.cve_refresh import _cvss_base3  # noqa: E402

GH_SEV = {"LOW": 3.1, "MODERATE": 5.5, "MEDIUM": 5.5, "HIGH": 7.8,
          "CRITICAL": 9.8}
OUT = os.path.join(ROOT, "intel", "cve_db.json")

# Package names that are too generic to match on as banner substrings without
# producing false positives (e.g. NPM "ip" matching "F5 BIG-IP"). Kept out of
# the automated expansion entirely; the curated CVE DB still covers infra/CMS.
AMBIGUOUS = {
    "ip", "js", "go", "os", "ui", "net", "ts", "db", "fs", "io", "dd",
    "git", "path", "parse", "string", "number", "object", "array", "list",
    "data", "file", "utils", "util", "helper", "helpers", "index", "main",
    "init", "config", "conf", "auth", "core", "server", "client", "cli",
    "args", "argv", "resolve", "safe", "hapi", "boom", "ping", "ms", "qs",
}


def _clean(name):
    return re.sub(r"\s+", " ", (name or "")).strip()[:140]


def _windows(events):
    """[(introduced, fixed_or_None, last_or_None)] from OSV events."""
    out = []
    evs = list(events)
    i = 0
    while i < len(evs):
        e = evs[i]
        if "introduced" not in e:
            i += 1
            continue
        introduced = e.get("introduced")
        fixed = last = None
        if i + 1 < len(evs) and "fixed" in evs[i + 1]:
            fixed = evs[i + 1]["fixed"]
            i += 2
        elif i + 1 < len(evs) and "last_affected" in evs[i + 1]:
            last = evs[i + 1]["last_affected"]
            i += 2
        else:
            i += 1
        out.append((introduced, fixed, last))
    return out


def _entry_spec(introduced, fixed, last):
    vals = []
    if introduced and introduced != "0":
        vals.append(">=%s" % introduced)
    if fixed:
        vals.append("<%s" % fixed)
    elif last:
        vals.append("<=%s" % last)
    return vals


def _severity(vuln):
    for s in vuln.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS"):
            b = _cvss_base3(s.get("score") or "")
            if b:
                return b
    return GH_SEV.get(str(vuln.get("database_specific", {}).get(
        "severity", "")).upper(), 0.0)


def build(tarball):
    products = {}
    total = 0
    t0 = time.time()
    with tarfile.open(tarball, "r:gz") as tf:
        for member in tf:
            if not member.isfile():
                continue
            if "github-reviewed" not in member.name or \
                    not member.name.endswith(".json"):
                continue
            try:
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                raw = fh.read()
            except Exception:
                continue
            try:
                vuln = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                continue
            if not vuln.get("affected"):
                continue
            summary = _clean(vuln.get("summary") or vuln.get("details"))
            ids = vuln.get("aliases") or []
            cve_id = next((a for a in ids if a.startswith("CVE-")),
                          vuln.get("id") or "GHSA")
            cvss = round(_severity(vuln), 1)
            entry = "%s|%s|%s" % (cve_id, summary, cvss)
            produced = False
            for aff in vuln["affected"]:
                pkg = aff.get("package") or {}
                name = str(pkg.get("name") or "").strip().lower()
                if not name:
                    continue
                if name in AMBIGUOUS:
                    continue
                for rng in aff.get("ranges") or []:
                    if str(rng.get("type", "")).upper() not in (
                            "SEMVER", "ECOSYSTEM"):
                        continue
                    for introduced, fixed, last in _windows(
                            rng.get("events") or []):
                        for spec in _entry_spec(introduced, fixed, last):
                            cfg = products.setdefault(
                                name, {"product": name, "aliases": [name],
                                       "ranges": {}})
                            lst = cfg["ranges"].setdefault(spec, [])
                            if not lst or lst[-1] != entry:
                                lst.append(entry)
                                produced = True
            if produced:
                total += 1
    return products, total, time.time() - t0


def main():
    tarball = sys.argv[1] if len(sys.argv) > 1 else "advisories.tar.gz"
    products, total, secs = build(tarball)
    try:
        existing = json.load(open(OUT, encoding="utf-8")).get("products", {})
    except Exception:
        existing = {}
    for name, cfg in existing.items():
        if name in AMBIGUOUS or len(name) < 3:
            continue
        base = products.setdefault(
            name, {"product": name, "aliases": [name], "ranges": {}})
        if cfg.get("product") and len(str(cfg.get("product"))) > len(
                str(base.get("product", ""))):
            base["product"] = cfg["product"]
        base.setdefault("aliases", [name])
        for a in cfg.get("aliases") or []:
            if a and a not in base["aliases"]:
                base["aliases"].append(a)
        for spec, lst in (cfg.get("ranges") or {}).items():
            kept = base["ranges"].setdefault(spec, [])
            for e in lst:
                if e not in kept:
                    kept.append(e)
    out = {"products": products,
           "meta": {"source": "GitHub Advisory Database (GHSA, OSV schema) "
                              "+ curated entries",
                    "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "advisories_processed": total,
                    "products": len(products)}}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, separators=(",", ":"))
    n_ranges = sum(len(m.get("ranges", {})) for m in products.values())
    print("advisories: %d | products: %d | range-entries: %d | size: %.1f MB "
          "| took %.0fs" % (total, len(products), n_ranges,
                            os.path.getsize(OUT) / 1048576, secs))


if __name__ == "__main__":
    main()