"""Vajra - breadth-first web crawler collecting pages, forms, emails, JS."""
import time
from collections import deque
from urllib.parse import urlparse

from core.database import Finding
from core.utils import (extract_links, extract_forms, extract_emails,
                        extract_comments, extract_title, load_json)

LOGIN_INTEL = load_json("intel/login_surfaces.json", {})
LOGIN_PATHS = LOGIN_INTEL.get("paths", [])


def _sitemap_locs(body, base=None):
    """Parse sitemap XML (plain or sitemap-index) for <loc> entries."""
    import re
    return set(re.findall(r"<loc>\s*([^<\s]+?)\s*</loc>", body or "", re.I))


def run(engine):
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    max_pages = int(engine.cfg("crawl_max_pages", 40))
    max_depth = int(engine.cfg("crawl_max_depth", 4))
    pages = []
    emails = set()
    forms_all = []
    js_all = []
    interesting_comments = []
    sitemap_urls = set()

    def add_sitemap(seed_base):
        """Robots-discovered or default sitemap.xml candidate feeds."""
        try:
            r = engine.http.get(seed_base.rstrip("/") + "/sitemap.xml",
                                allow_redirects=True)
            if 200 <= r.status < 300:
                return _sitemap_locs(r.body, seed_base)
        except Exception:
            return set()
        return set()

    for wt in targets:
        base = wt["url"].rstrip("/")
        pbase = urlparse(base)
        limit = max_pages if wt.get("primary") else min(10, max_pages)
        depth_limit = max_depth if wt.get("primary") else 1
        queue = deque([(base + "/", 0)])
        seen = set()
        robots_disallow = set()
        r0 = engine.http.get(base + "/robots.txt", allow_redirects=True)
        if 200 <= r0.status < 300:
            for line in r0.body.splitlines():
                lowl = line.lower().strip()
                if lowl.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        robots_disallow.add(path)
                elif lowl.startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    if sm:
                        sitemap_urls.update(_sitemap_locs(
                            engine.http.get(sm, timeout=6).body, sm))
            engine.state.setdefault("robots", {})["text"] = r0.body[:4000]
            engine.state.setdefault("robots", {})["sitemaps"] = \
                sorted(sitemap_urls)[:200]
            if "admin" in r0.body.lower() or "private" in r0.body.lower():
                interesting_comments.append("robots.txt reveals private paths:\n" +
                                            r0.body[:800])
        if not sitemap_urls:
            sitemap_urls.update(add_sitemap(base))
        for su in sorted(sitemap_urls)[:limit]:
            pl = urlparse(su)
            if (pl.hostname, pl.port) == (pbase.hostname, pbase.port):
                queue.append((su, 1))
        while queue and len(seen) < limit:
            url, depth = queue.popleft()
            norm = url.split("#")[0].rstrip("/")
            if not norm or norm in seen:
                continue
            pu = urlparse(norm)
            if (pu.hostname, pu.port) != (pbase.hostname, pbase.port):
                continue
            if any(norm.endswith(d) or ("/" + d.lstrip("/") in norm) for d in robots_disallow) \
                    and depth > 0:
                continue
            seen.add(norm)
            r = engine.http.get(norm)
            body = r.body
            title = extract_title(body)
            links = extract_links(body, norm)
            forms = extract_forms(body, norm)
            emls = extract_emails(body)
            comments = extract_comments(body)
            jss = [l for l in links if l.lower().endswith(".js")]
            page = {"url": norm, "status": r.status, "title": title,
                    "body": body[:300000], "headers": r.headers,
                    "links": sorted(links)[:200], "forms": forms,
                    "emails": sorted(emls), "comments": comments,
                    "js": jss, "depth": depth}
            pages.append(page)
            forms_all.extend(forms)
            emails |= emls
            js_all.extend(jss)
            for c in comments:
                low = c.lower()
                if any(k in low for k in ("password", "secret", "api_key", "apikey",
                                          "token", "todo", "fixme", "debug")):
                    interesting_comments.append("%s :: %s" % (norm, c[:300]))
            engine.log.debug("crawled [%d] %s (%d links)" % (r.status, norm, len(links)))
            if r.status == 0:
                continue
            if depth < depth_limit:
                for l in links:
                    pl = urlparse(l)
                    if (pl.hostname, pl.port) == (pbase.hostname, pbase.port) and \
                            l not in seen and not l.lower().endswith(
                                (".jpg", ".png", ".gif", ".svg", ".css", ".ico",
                                 ".woff", ".woff2", ".ttf", ".mp4", ".pdf", ".zip")):
                        queue.append((l, depth + 1))
    engine.state["pages"] = pages
    engine.state["forms"] = forms_all
    engine.state["emails"] = sorted(emails)
    engine.state["js"] = sorted(set(js_all))

    login_surfaces = []
    cands = LOGIN_PATHS[:12]
    for wt in targets[:1]:
        base = wt["url"].rstrip("/")
        for cand in cands:
            url = base + cand if cand.startswith("/") else base + "/" + cand
            try:
                r = engine.http.get(url, allow_redirects=False, timeout=5)
            except Exception:
                continue
            body_low = (r.body or "").lower()[:1200]
            loginish = ("password" in body_low or "log in" in body_low or
                        "sign in" in body_low or "username" in body_low)
            if r.status in (200, 301, 302, 303) and loginish:
                login_surfaces.append(url)
    if login_surfaces:
        engine.state["login_surfaces"] = sorted(set(login_surfaces))[:12]
    t = engine.target
    engine.db.add_finding(Finding(
        t.display, "web.crawl", "recon", "info",
        "Crawl complete: %d page(s), %d form(s), %d JS file(s), %d email(s)" %
        (len(pages), len(forms_all), len(set(js_all)), len(emails)),
        detail="Scope: %s" % ", ".join(w["url"] for w in targets),
        confidence="firm"))
    for c in interesting_comments[:8]:
        engine.db.add_finding(Finding(
            t.display, "web.crawl", "info-disclosure", "low",
            "Interesting HTML comment / robots entry",
            evidence=c[:1000], confidence="firm"))
