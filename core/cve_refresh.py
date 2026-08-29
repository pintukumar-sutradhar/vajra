"""Vajra - optional live CVE refresh (opt-in via --cve-update).

The offline knowledge base (intel/cve_db.json) stays the default so scans work
air-gapped. With the flag on, when a product/version is *not* covered by the
local KB we ask the CIRCL VULN API once per product|version and cache the
result in intel/cve_online_cache.json (with timestamp) so repeated runs are
quiet. Pure stdlib; failures degrade to no-op."""
import json
import time
import urllib.parse

from core.utils import load_json, PROJECT_ROOT

CACHE_RELPATH = "intel/cve_online_cache.json"
API = "https://cve.circl.lu/api/search/%s/%s"
TTL = 24 * 60 * 60


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


def lookup_online(product, version, timeout=8):
    """Best-effort CIRCL lookup for product:version.
    Returns parsed cve entries [{id, cvss, summary}] or None (miss/offline)."""
    if not product or not version:
        return None
    key = "%s|%s" % (product.strip().lower(), version)
    cache = _cache()
    hit = cache.get(key)
    if hit and time.time() - hit.get("ts", 0) < TTL:
        return hit.get("results")
    q = urllib.parse.quote("%s %s" % (product, version))
    url = "https://cve.circl.lu/api/search/%s" % q
    try:
        import urllib.request as _u
        req = _u.Request(url, headers={"User-Agent": "vajra-cve-update/1"})
        with _u.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None
    results = []
    for item in (data.get("results") or [])[:12]:
        results.append({
            "id": item.get("id", ""),
            "cvss": item.get("cvss", 0) or 0,
            "summary": (item.get("summary") or "")[:220],
        })
    cache[key] = {"ts": time.time(), "results": results}
    _save(cache)
    return results or None