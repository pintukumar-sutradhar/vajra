"""Vajra - optional live CVE refresh (opt-in via --cve-update).

Precision-first replacement for the old CIRCL free-text search: we now talk
only to the OSV API (api.osv.dev), which returns *exact* package identities
and version ranges. A result is kept only when OSV marks our version inside an
affected SEMVER range (server-side filter + local re-check), so an online CVE
hit is as trustworthy as an offline one. Lookups are cached per product|version
for 24h (intel/cve_online_cache.json). Pure stdlib; every failure degrades to
a silent no-op and never invents findings."""
import json
import time
import urllib.request

from core.utils import load_json, PROJECT_ROOT

CACHE_RELPATH = "intel/cve_online_cache.json"
OSV_API = "https://api.osv.dev/v1/query"
TTL = 24 * 60 * 60

# Product name -> OSV package name. Unmapped products are queried as-is
# (best-effort; an unknown package returns empty and degrades silently).
ALIASES = {
    "ruby on rails": "rails",
    "rubyonrails": "rails",
    "rails": "rails",
}
_GH_SEV = {"LOW": 3.1, "MODERATE": 5.5, "MEDIUM": 5.5, "HIGH": 7.8,
           "CRITICAL": 9.8}


def _cache():
    try:
        d = load_json(CACHE_RELPATH)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save(c):
    try:
        path = PROJECT_ROOT / CACHE_RELPATH
        path.write_text(json.dumps(c, indent=1), encoding="utf-8")
    except Exception:
        pass


def _segments(v):
    parts = []
    for bit in str(v).replace("-", ".").split("."):
        if bit.isdigit():
            parts.append(int(bit))
        else:
            parts.append((0, bit))
    return parts


def _range_match(version, introduced, fixed):
    """version within [introduced, fixed) via semver-ish compare."""
    v = _segments(version)
    if introduced and introduced not in ("0",):
        if v < _segments(introduced):
            return False
    if fixed:
        if v >= _segments(fixed):
            return False
    return True


def _cvss_base3(vector):
    """Compact CVSS v3.1 base-score calculator from a vector string."""
    if not vector:
        return 0.0
    m = {}
    for part in vector.split("/"):
        kv = part.split(":", 1)
        if len(kv) == 2:
            m[kv[0].strip()] = kv[1].strip()
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(m.get("AV"), 0)
    ac = {"L": 0.77, "H": 0.44}.get(m.get("AC"), 0)
    ui = {"N": 0.85, "R": 0.62}.get(m.get("UI"), 0)
    pr = 0.85
    if m.get("PR") == "L":
        pr = 0.68 if m.get("S") == "C" else 0.62
    elif m.get("PR") == "H":
        pr = 0.50 if m.get("S") == "C" else 0.27
    c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("C"), 0)
    i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("I"), 0)
    a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("A"), 0)
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    exp = 8.22 * av * ac * pr * ui
    if m.get("S") == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        base = 1.08 * (exp + impact)
    else:
        impact = 6.42 * iss
        base = exp + impact
    import math
    base = max(0.0, min(base, 10.0))
    return math.ceil(base * 10 - 1e-9) / 10


def _severity(vuln):
    for sev in vuln.get("severity") or []:
        if (sev.get("type") or "").startswith("CVSS"):
            b = _cvss_base3(sev.get("score", ""))
            if b:
                return b
    import re
    db = vuln.get("database_specific") or {}
    return _GH_SEV.get(str(db.get("severity", "")).upper(), 0.0)


def _osv_lookup(name, version, timeout=10):
    """POST exact package@version query to OSV. Returns raw vuln dicts that
    OSV confirms are affected by 'version', or ().
    """
    body = json.dumps({"package": {"name": name}, "version": version}).encode()
    req = urllib.request.Request(
        OSV_API, data=body,
        headers={"Content-Type": "application/json",
                 "User-Agent": "vajra-cve-update/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None
    out = []
    for v in data.get("vulns") or []:
        for aff in v.get("affected") or []:
            if aff.get("package", {}).get("name", "").lower() != name.lower():
                continue
            versions = aff.get("versions") or []
            if "SEMVER" not in str(aff.get("ranges", [])) and \
                    version not in versions:
                continue
            seen_in_range = False
            for rng in aff.get("ranges") or []:
                if str(rng.get("type")).upper() != "SEMVER":
                    continue
                ev = rng.get("events") or []
                for i, e in enumerate(ev):
                    if "introduced" in e and _range_match(
                            version, e["introduced"],
                            ev[i + 1].get("fixed") if i + 1 < len(ev) else ""):
                        seen_in_range = True
                        break
                if seen_in_range:
                    break
            if not seen_in_range and version not in versions:
                continue
            out.append({
                "id": v.get("id") or "",
                "cvss": _severity(v),
                "summary": (v.get("summary") or v.get("details") or "")[:220],
            })
            break
    return out


def lookup_online(product, version, timeout=10):
    """Best-effort OSV exact lookup for product:version.

    Returns parsed cve entries [{id, cvss, summary}] that OSV confirms affect
    this exact version, or None on miss/offline. Never fuzzy.
    """
    if not product or not version:
        return None
    name = ALIASES.get(product.strip().lower(), product.strip().lower())
    key = "%s|%s" % (name, version)
    cache = _cache()
    hit = cache.get(key)
    if hit and time.time() - hit.get("ts", 0) < TTL:
        return hit.get("results")
    results = _osv_lookup(name, version, timeout)
    cache[key] = {"ts": time.time(), "results": results}
    _save(cache)
    return results