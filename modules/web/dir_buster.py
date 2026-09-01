"""Vajra - directory & sensitive file discovery with smart classification."""
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.database import Finding
from core.utils import rand_path

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


def _check(engine, base, path, use_head_first=True):
    url = base + path
    if use_head_first:
        r = engine.http.head(url, allow_redirects=False)
        if r.status in (0, 501, 405, 400):
            r = engine.http.get(url, allow_redirects=False)
    else:
        r = engine.http.get(url, allow_redirects=False)
    return url, r


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    paths = engine.dirs_words() or ["admin", "login", "dashboard",
                                    "uploads", "backup"]
    threads = int(engine.cfg("dir_threads", 25))
    hits, restricted, redirects, listings = [], [], [], []
    auth_paths = []

    def work(args):
        base, path, light = args
        url, r = _check(engine, base, path)
        cls = INTERESTING_STATUS.get(r.status)
        loc = r.headers.get("location", "")
        body = r.body
        body_head = body[:600].lower()
        is_listing = ("directory listing for" in body_head or
                      "<h1>index of /" in body_head)
        soft404 = False
        if cls == "found" and baselines.get(base):
            bstat, blen = baselines[base]
            if r.status == bstat and abs(len(body) - blen) < 32:
                soft404 = True
        return (base, path, url, r.status, cls, loc, is_listing, r, soft404)

    jobs = []
    for wt in targets:
        base = wt["url"].rstrip("/")
        subset = paths if wt.get("primary") else paths[:35]
        for p in subset:
            jobs.append((base, "/" + p.lstrip("/"), False))
        if wt.get("primary"):
            for p in SENSITIVE_PATHS:
                jobs.append((base, p, True))
    engine.log.info("Directory scan: %d request target(s)" % len(jobs))
    baselines = {}
    for wt in targets:
        base = wt["url"].rstrip("/")
        rb = engine.http.get(base + "/" + rand_path(12) + ".php",
                             allow_redirects=False)
        baselines[base] = (rb.status, len(rb.body))
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

    for base, path, url, status, cls, loc, is_listing, r, soft404 in results:
        if soft404:
            continue
        if is_listing and status == 200:
            listings.append(url)
            continue
        if cls == "found":
            hits.append((url, r))
        elif cls == "auth-required":
            restricted.append(url)
            auth_paths.append((base, path))
        elif cls == "forbidden":
            if any(k in r.body[:300].lower() for k in ("denied", "blocked", "waf")):
                continue
            restricted.append(url)
        elif cls == "redirect":
            redirects.append((url, loc))

    engine.state["http_auth_paths"] = auth_paths
    if hits:
        listing = "\n".join(sorted({u for u, _ in hits}))
        engine.db.add_finding(Finding(
            t.display, "web.dirbuster", "exposure", "medium",
            "Discovered application paths/files: %d" % len(hits),
            detail="Manually review each discovered endpoint.",
            evidence=listing[:8000], confidence="firm"))
    for url, r in hits:
        low_body = r.body[:1500].lower()
        tag = ""
        if "index of/" in low_body.replace(" ", ""):
            tag = " (autoindex)"
        elif any(x in url.lower() for x in ("/admin", "/manager", "/console",
                                            "/phpmyadmin", "/jenkins")):
            tag = " (admin surface)"
        if tag and "autoindex" not in tag:
            engine.db.add_finding(Finding(
                t.display, "web.dirbuster", "exposure", "low",
                "Administrative interface reachable%s: %s" % (tag, url),
                confidence="firm"))
    if restricted:
        engine.db.add_finding(Finding(
            t.display, "web.dirbuster", "exposure", "info",
            "Protected/restricted paths detected: %d" % len(restricted),
            evidence="\n".join(sorted(restricted))[:4000],
            detail="403 responses may still leak existence of resources; "
                   "candidates for bypass testing.", confidence="firm"))
    if redirects:
        interesting = [(u, l) for u, l in redirects if any(
            k in u.lower() for k in ("/login", "/admin", "/signin", "/auth"))][:15]
        if interesting:
            engine.db.add_finding(Finding(
                t.display, "web.dirbuster", "exposure", "info",
                "Login/auth redirect endpoints",
                evidence="\n".join("%s -> %s" % (u, l) for u, l in interesting),
                confidence="firm"))
    for url in listings:
        engine.db.add_finding(Finding(
            t.display, "web.vulnscan", "misconfiguration", "medium",
            "Directory listing enabled: %s" % url,
            detail="Autoindex exposes file structure and may expose sensitive "
                   "documents.", remediation="Disable autoindex on the web server.",
            confidence="firm"))

    git_probe = None
    for wt in targets:
        base = wt["url"].rstrip("/")
        u0, r0 = _check(engine, base, "/.git/HEAD")
        if r0.status == 200 and r0.body.strip().startswith("ref:"):
            git_probe = base + "/.git/"
            break
    if git_probe:
        engine.db.add_finding(Finding(
            t.display, "web.dirbuster", "exposure", "high",
            "Exposed Git repository metadata (.git)",
            detail="Source code and history may be fully recoverable via "
                   "tools like git-dumper.",
            evidence=git_probe, remediation="Block access to .git and remove "
                    "VCS directories from deployment.", confidence="firm"))
    env_probe = None
    for wt in targets:
        base = wt["url"].rstrip("/")
        u1, r1 = _check(engine, base, "/.env")
        if r1.status == 200 and "=" in r1.body and len(r1.body) > 20:
            env_probe = (u1, r1.body[:500])
            break
    if env_probe:
        body = env_probe[1]
        looks_env = bool(ENV_LINE_RE.search(body)) and not HTML_RE.search(body[:200])
        if looks_env:
            keys = ENV_LINE_RE.findall(body)
            sev = "critical" if any(k.lower() in body.lower() for k in
                                    ("password", "secret", "key", "token")) else "high"
            engine.db.add_finding(Finding(
                t.display, "web.dirbuster", "exposure", sev,
                "Environment file exposed: /.env (%d variable(s))" % len(keys),
                evidence=env_probe[0] + "\n" + "\n".join(
                    ln for ln in body.splitlines()
                    if ENV_LINE_RE.match(ln))[:800],
                remediation="Remove .env from webroot; deny dotfiles at server "
                            "level.", confidence="firm"))
