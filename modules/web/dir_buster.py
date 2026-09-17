"""VAJRA - directory & sensitive file discovery.

Existence is decided by comparing every response against how the host answers
paths that certainly do not exist (core.evidence) — for *every* status class,
not just 200. That last part matters: a server answering 403, or a 302 to
/login, for every URL used to produce a mass of bogus "protected path"
findings. Those responses are now recognised as indistinguishable from the
host's not-found behaviour and are not reported.

Findings are filed through engine.record(), so each one carries the proof that
produced it and a severity its proof kind can actually support.
"""
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.evidence import baseline_for, verdict, REAL, ABSENT, WILDCARD, \
    UNREACHABLE
from core import proof as P

ENV_LINE_RE = re.compile(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S+")
HTML_RE = re.compile(r"<\s*(html|body|div|a\s)", re.I)

BACKUP_SUFFIXES = [".bak", ".old", ".zip", ".tar.gz", ".tgz", ".sql", ".swp",
                   "~", ".save"]
SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.svn/entries", "/.env", "/.env.bak",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/database.sql",
    "/dump.sql", "/site.sql", "/config.php.bak", "/wp-config.php.bak",
    "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
    "/WEB-INF/web.xml", "/composer.json", "/package.json",
    "/.DS_Store", "/Thumbs.db", "/crossdomain.xml",
    "/.well-known/security.txt", "/security.txt",
]
INTERESTING_STATUS = {200: "found", 301: "redirect", 302: "redirect",
                      307: "redirect", 308: "redirect", 401: "auth-required",
                      403: "forbidden"}

# A response is only worth a finding when it differs from the host's
# not-found behaviour. These are the verdicts that carry no such evidence.
_NO_EVIDENCE = (ABSENT, WILDCARD, UNREACHABLE)

# Markers that make an autoindex listing self-evident rather than inferred.
LISTING_MARKERS = ("directory listing for", "<h1>index of /", "<title>index of")


def _fetch(engine, url):
    try:
        return engine.http.get(url, allow_redirects=False, timeout=8)
    except Exception:
        return None


def _is_listing(r):
    head = (r.body or "")[:600].lower()
    return any(m in head for m in LISTING_MARKERS)


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    paths = engine.dirs_words() or ["admin", "login", "dashboard",
                                    "uploads", "backup"]
    threads = int(engine.cfg("dir_threads", 25))
    # Lift concurrency under aggressive/--threads so bulk fuzzing moves at
    # red-team speed (dir busting is I/O-bound HTTP, not CPU-bound).
    if bool(getattr(engine.args, "aggressive", False)) and \
            not bool(getattr(engine.args, "stealth", False)):
        base = int(getattr(engine.args, "threads", 0) or 0) or 40
        threads = max(threads, min(800, max(100, base * 12)))
    elif not getattr(engine, "_stealthed", False):
        base = int(getattr(engine.args, "threads", 0) or 0) or 40
        threads = max(threads, min(400, max(threads, base * 4)))

    jobs = []
    for wt in targets:
        base = wt["url"].rstrip("/")
        subset = paths if wt.get("primary") else paths[:35]
        for p in subset:
            jobs.append((base, "/" + p.lstrip("/")))
        if wt.get("primary"):
            for p in SENSITIVE_PATHS:
                jobs.append((base, p))
    engine.log.info("Directory scan: %d request target(s) against %d host(s)"
                    % (len(jobs), len(targets)))
    # One baseline per host, three probes each — not one probe per host and
    # not one probe per path.
    for wt in targets:
        baseline_for(engine, wt["url"])
    verdicts = {REAL: 0, ABSENT: 0, WILDCARD: 0, UNREACHABLE: 0}

    def work(job):
        base, path = job
        bl = baseline_for(engine, base)
        r = _fetch(engine, base + path)
        if r is None:
            return (base, path, None, UNREACHABLE, "no response")
        v, why = verdict(r, bl, path)
        return (base, path, r, v, why)

    results = []
    total_jobs = len(jobs)
    checked = 0
    with ThreadPoolExecutor(max_workers=threads) as ex:
        fut = {ex.submit(work, j): j for j in jobs}
        for af in as_completed(fut):
            try:
                results.append(af.result())
            except Exception:
                pass
            checked += 1
            engine.progress(checked, total_jobs,
                            detail="dir %d/%d" % (checked, total_jobs))

    hits, restricted, listings, auth_paths = [], [], [], []
    for base, path, r, v, why in results:
        verdicts[v] = verdicts.get(v, 0) + 1
        if v in _NO_EVIDENCE:
            continue
        engine.log.debug("[PROBE] %s%s -> %s (%s)" % (base, path, v, why))
        cls = INTERESTING_STATUS.get(r.status)
        if _is_listing(r) and r.status == 200:
            listings.append((base + path, r.body[:400]))
            continue
        if cls == "found":
            hits.append((base + path, r, why))
        elif cls in ("auth-required", "forbidden"):
            # A 403/401 that differs from the not-found baseline is real
            # evidence the resource exists — worth listing, not worth a
            # severity.
            restricted.append(base + path)
            if cls == "auth-required":
                auth_paths.append((base, path))
        # Redirects that differ from baseline are recorded for the auth
        # surface check below but never mass-reported.

    engine.state["http_auth_paths"] = auth_paths
    engine.log.info("[dirbuster] %d diff from baseline, %d not-found, "
                    "%d catch-all (suppressed), %d unreachable"
                    % (verdicts.get(REAL, 0), verdicts.get(ABSENT, 0),
                       verdicts.get(WILDCARD, 0), verdicts.get(UNREACHABLE, 0)))

    if hits:
        listing = "\n".join(sorted({u for u, _, _ in hits}))
        engine.record(
            t.display, "web.dirbuster", "exposure", "medium",
            "Discovered application paths/files: %d" % len(hits),
            detail="Each path answered differently from this host's "
                   "not-found response; manually review each endpoint.",
            evidence=listing[:8000], cls="exposure",
            proof=P.differential(
                listing[:2000], control_clean=True,
                note="%d path(s) each verified to differ from the baseline "
                     "response for a known-absent path" % len(hits)))
    for url, r, why in hits:
        low_body = (r.body or "")[:1500].lower().replace(" ", "")
        if "index of/" in low_body:
            continue  # already covered as a listing
        if any(x in url.lower() for x in ("/admin", "/manager", "/console",
                                          "/phpmyadmin", "/jenkins")):
            engine.record(
                t.display, "web.dirbuster", "exposure", "low",
                "Administrative interface reachable: %s" % url,
                detail="An administrative surface is reachable without "
                       "authentication.", evidence=why,
                cls="exposure",
                proof=P.differential(url, control_clean=True, note=why))
    if restricted:
        engine.record(
            t.display, "web.dirbuster", "exposure", "info",
            "Protected/restricted paths detected: %d" % len(restricted),
            evidence="\n".join(sorted(restricted))[:4000],
            detail="These paths answer 403/401 where a known-absent path "
                   "does not, so they exist and are access-controlled. "
                   "Candidates for bypass testing.",
            cls="exposure",
            proof=P.differential(
                "\n".join(sorted(restricted))[:2000], control_clean=True,
                note="status differs from the host's not-found baseline"))
    for url, snippet in listings:
        engine.record(
            t.display, "web.vulnscan", "misconfiguration", "medium",
            "Directory listing enabled: %s" % url,
            detail="Autoindex exposes file structure and may expose "
                   "sensitive documents.",
            evidence=snippet,
            remediation="Disable autoindex on the web server.",
            cls="misconfiguration",
            proof=P.marker(snippet, note="server-rendered index page"))

    _check_git(engine, t, targets)
    _check_env(engine, t, targets)


def _check_git(engine, t, targets):
    """`.git/HEAD` is self-authenticating: a 404 template cannot produce a
    line beginning `ref:`. No baseline needed."""
    for wt in targets:
        base = wt["url"].rstrip("/")
        bl = baseline_for(engine, base)
        r = _fetch(engine, base + "/.git/HEAD")
        if r is None:
            continue
        body = (r.body or "").strip()
        if r.status == 200 and body.startswith("ref:") and \
                verdict(r, bl, "/.git/HEAD")[0] == REAL:
            engine.record(
                t.display, "web.dirbuster", "exposure", "high",
                "Exposed Git repository metadata (.git)",
                detail="Source code and history may be fully recoverable "
                       "via tools like git-dumper.",
                evidence="%s/.git/HEAD\n%s" % (base, body[:300]),
                remediation="Block access to .git and remove VCS "
                            "directories from deployment.",
                cls="exposure",
                proof=P.marker(body[:300],
                               note="version-control HEAD reference returned"))
            return


def _check_env(engine, t, targets):
    for wt in targets:
        base = wt["url"].rstrip("/")
        bl = baseline_for(engine, base)
        r = _fetch(engine, base + "/.env")
        if r is None or r.status != 200:
            continue
        body = r.body or ""
        if len(body) < 20 or "=" not in body:
            continue
        if verdict(r, bl, "/.env")[0] != REAL:
            continue
        # Require real KEY=value structure and reject anything HTML-shaped: a
        # page that merely contains an "=" is not an exposed env file.
        if not ENV_LINE_RE.search(body) or HTML_RE.search(body[:200]):
            continue
        keys = ENV_LINE_RE.findall(body)
        secretish = any(k in body.lower() for k in
                        ("password", "secret", "key", "token"))
        lines = [ln for ln in body.splitlines() if ENV_LINE_RE.match(ln)]
        engine.record(
            t.display, "web.dirbuster", "exposure",
            "critical" if secretish else "high",
            "Environment file exposed: /.env (%d variable(s))" % len(keys),
            evidence="%s/.env\n%s" % (base, "\n".join(lines)[:800]),
            remediation="Remove .env from webroot; deny dotfiles at server "
                        "level.",
            cls="exposure",
            proof=P.marker("\n".join(lines)[:800],
                           note="KEY=value configuration lines returned as "
                                "text/plain"))
        return
