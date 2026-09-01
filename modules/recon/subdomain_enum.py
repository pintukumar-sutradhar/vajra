"""Vajra - subdomain enumeration: wordlist DNS brute + optional CT logs."""
import concurrent.futures as cf
import socket
import urllib.request
import json

from core.database import Finding
from core.utils import load_json


def _resolve(host):
    try:
        socket.setdefaulttimeout(2.5)
        ip = socket.gethostbyname(host)
        return host, ip
    except Exception:
        return host, None


def _fetch_crt(dom, ua):
    """Query crt.sh with a hard time-box so a stalled DNS/connect cannot block
    the run. Returns set of candidate names (possibly empty) on success."""
    names = set()
    req = urllib.request.Request(
        "https://crt.sh/?q=%s&output=json" % dom,
        headers={"User-Agent": ua})
    with urllib.request.urlopen(req, timeout=6) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    for row in data[:300]:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower()
            if n.endswith(dom):
                names.add(n)
    return names


def run(engine):
    t = engine.target
    dom = t.hostname.lstrip(".")
    if t.is_ip_literal:
        return
    found = {dom: ip for ip in [t.primary_ip] if ip}
    words = engine.subs_words() or ["www", "mail", "api", "dev", "test"]
    candidates = {"%s.%s" % (w, dom) for w in words}
    if engine.online:
        # crt.sh in its own thread with a hard wall-clock cap (8s): even if the
        # DNS lookup or connect wedges, the whole module cannot stall at 0%.
        with cf.ThreadPoolExecutor(max_workers=1) as _pool:
            f = _pool.submit(_fetch_crt, dom, engine.http.next_ua())
            try:
                candidates |= f.result(timeout=8)
                engine.log.info("[recon.subdomains] +%d names from CT logs"
                                % (len(candidates) - len(words)))
            except Exception as e:
                f.cancel()
                _l = getattr(engine, "log", None)
                if _l is not None:
                    try:
                        _l.debug("crt.sh time-boxed out (%r) - wordlist-only"
                                 % e)
                    except Exception:
                        pass
    cands = list(candidates)[:30000]
    resolved = 0
    with cf.ThreadPoolExecutor(max_workers=min(engine.cfg("threads", 40), 64)) as ex:
        futures = {ex.submit(_resolve, h): h for h in cands}
        for fut in cf.as_completed(futures):
            host, ip = fut.result()
            resolved += 1
            if ip:
                found[host] = ip
            # Live run-meter feed: show the DNS brute sub-progress so the bar
            # moves and a stable ETA appears instead of a frozen 0.0%.
            if resolved % 25 == 0 or resolved == len(cands):
                engine.progress(cur=resolved, total=len(cands),
                                detail="recon.subdomains %d/%d" %
                                       (resolved, len(cands)))
    live = [{"host": h, "ip": found[h]} for h in sorted(found.keys())]
    engine.state.setdefault("subdomains", live)
    if live:
        listing = "\n".join("%-42s %s" % (e["host"], e["ip"]) for e in live[:60])
        extra = "" if len(live) <= 60 else "\n... (%d total)" % len(live)
        engine.db.add_finding(Finding(
            t.display, "recon.subdomains", "recon", "info",
            "Subdomains discovered: %d" % len(live),
            detail="Enumerated via DNS wordlist%s" %
                   (" + Certificate Transparency logs" if engine.online else ""),
            evidence=listing + extra, confidence="firm"))
        wildcard_test = "vjr-wildcard-%s.%s" % (engine.nonce(), dom)
        if _resolve(wildcard_test)[1]:
            engine.db.add_finding(Finding(
                t.display, "recon.subdomains", "recon", "info",
                "Wildcard DNS detected",
                detail="Every subdomain resolves; enumeration results may be "
                       "wildcard artifacts.", confidence="firm"))
