"""Vajra - sensitive-file / leak-path checklist.

Data-driven from intel/loot_paths.json: read-only GETs for classic leak
locations (.git/HEAD, .env, backup archives, phpinfo, actuator, exposed
admin panels). Uses a marker-led heuristic per path type and a soft-404
filter, so real files are reported without tripping on template 404s.
"""
from core.database import Finding
from core.utils import load_json

GROUPS = load_json("intel/loot_paths.json", {}).get("groups", [])

SOFT404 = ("404 not found", "page not found", "no such file", "not found on",
           "does not exist", "<title>404", "file not found")
HTML_TYPES = ("text/html", "application/xhtml")
MAX_PATHS = 120


def _looks_real(status, body, ctype, path, name):
    if status != 200:
        return False
    low = (body or "").lower()[:4000]
    if any(m in low for m in SOFT404):
        return False
    p = path.lower()
    n = name.lower()
    if p == ".git/head":
        return "ref:" in low
    if p == ".git/config":
        return "[core]" in low
    if "env" in n and n.endswith(".env") or (n.startswith(".env")):
        return "=" in body[:2000] and len(body) > 6
    if n.endswith((".sql", ".zip", ".tar.gz", ".gz", ".bak", ".7z", ".rar",
                   ".rdb", ".csv")):
        return bool(body) and ctype not in HTML_TYPES
    if p == "phpinfo.php":
        return "php version" in low or "phpinfo()" in low
    return len(body) > 40 and ctype not in HTML_TYPES


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    probed = 0
    for wt in targets:
        base = wt["url"].rstrip("/")
        for grp in GROUPS:
            label = grp.get("label", grp.get("name", "leak"))
            hits = []
            for path in (grp.get("paths") or []):
                if probed >= MAX_PATHS:
                    continue
                ap = path if path.startswith("/") else "/" + path
                try:
                    r = engine.http.get(base + ap, allow_redirects=False,
                                        timeout=5)
                except Exception:
                    continue
                probed += 1
                ctype = r.headers.get("content-type", "")
                if _looks_real(r.status, r.body, ctype, path.lower(),
                               path.rsplit("/", 1)[-1].lower()):
                    hits.append(path)
            if not hits:
                continue
            sev = grp.get("severity", "medium")
            engine.db.add_finding(Finding(
                t.display, "web.loot", "info-leak", sev,
                "%s on %s" % (label, base),
                detail="Read-only probes reached %d of %d candidate path(s) "
                       "from the %s group." % (len(hits), len(grp.get("paths")
                                                              or []),
                                               grp.get("name", "?"))[:600],
                evidence="\n".join(hits[:24]),
                remediation="Remove sensitive files/archives from the web "
                            "tree; deny access to VCS metadata and debug "
                            "endpoints.",
                confidence="firm" if sev in ("critical", "high") else
                "possible"))
            engine.log.finding("[LOOT:%s] %s: %s" % (grp.get("name", "?"),
                                                     base, ", ".join(hits
                                                                    [:6])))