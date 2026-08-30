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


def run(engine):
    t = engine.target
    dom = t.hostname.lstrip(".")
    if t.is_ip_literal:
        return
    found = {dom: ip for ip in [t.primary_ip] if ip}
    words = engine.subs_words() or ["www", "mail", "api", "dev", "test"]
    candidates = {"%s.%s" % (w, dom) for w in words}
    online = engine.online
    if online:
        try:
            req = urllib.request.Request(
                "https://crt.sh/?q=%s&output=json" % dom,
                headers={"User-Agent": engine.http.next_ua()})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            names = set()
            for row in data[:300]:
                for n in str(row.get("name_value", "")).splitlines():
                    n = n.strip().lower()
                    if n.endswith(dom):
                        names.add(n)
            candidates |= names
        except Exception:
            engine.log.debug("crt.sh unreachable - continuing wordlist-only")
    with cf.ThreadPoolExecutor(max_workers=min(engine.cfg("threads", 40), 64)) as ex:
        for host, ip in ex.map(_resolve, list(candidates)[:30000]):
            if ip:
                found[host] = ip
    live = [{"host": h, "ip": found[h]} for h in sorted(found.keys())]
    engine.state.setdefault("subdomains", live)
    if live:
        listing = "\n".join("%-42s %s" % (e["host"], e["ip"]) for e in live[:60])
        extra = "" if len(live) <= 60 else "\n... (%d total)" % len(live)
        engine.db.add_finding(Finding(
            t.display, "recon.subdomains", "recon", "info",
            "Subdomains discovered: %d" % len(live),
            detail="Enumerated via DNS wordlist%s" %
                   (" + Certificate Transparency logs" if online else ""),
            evidence=listing + extra, confidence="firm"))
        wildcard_test = "vjr-wildcard-%s.%s" % (engine.nonce(), dom)
        if _resolve(wildcard_test)[1]:
            engine.db.add_finding(Finding(
                t.display, "recon.subdomains", "recon", "info",
                "Wildcard DNS detected",
                detail="Every subdomain resolves; enumeration results may be "
                       "wildcard artifacts.", confidence="firm"))
