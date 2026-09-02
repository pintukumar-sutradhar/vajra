"""Vajra - subdomain enumeration: wordlist DNS brute + optional CT logs."""
import concurrent.futures as cf
import socket
import urllib.request
import json

from core.database import Finding


def _resolve(host):
    """Best-effort A lookup. Keeps a short socket timeout so failed names (the
    vast majority in a brute) fail fast instead of tying up a worker for the
    full timeout; the dedicated high-concurrency pool then amortises the whole
    sweep far faster than the general HTTP thread count could."""
    try:
        socket.setdefaulttimeout(1.5)
        ip = socket.gethostbyname(host)
        if ip:
            return host, ip
        return host, None
    except Exception:
        return host, None


def _fetch_ct(dom, ua):
    """Certificate-transparency name harvesting from crt.sh JSON. Time-boxed by
    the caller via Future.result(timeout); returns a set of candidate names,
    possibly empty, never raising."""
    names = set()
    try:
        req = urllib.request.Request(
            "https://crt.sh/?q=%s&output=json" % dom,
            headers={"User-Agent": ua, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        for row in data[:400]:
            for n in str(row.get("name_value", "")).splitlines():
                n = n.strip().lower().rstrip(".")
                if n.endswith(dom) and "*" not in n:
                    names.add(n)
    except Exception:
        pass
    return names


def _dns_workers(engine):
    """Dedicated DNS concurrency. Resolver lookups are I/O-bound (network +
    OS resolver), so they get their own pool that is far larger than the
    general --threads figure (which paces HTTP/dir busting, not DNS).

    Precedence: {engine.dns_threads attr, config dns_threads} is taken as the
    exact worker count; otherwise scale `--threads` (4x, capped 64..400).
    Stealth mode always clamps to 16..64 for a low-noise sweep."""
    stealth = bool(getattr(engine, "_stealthed", False)) or \
        bool(getattr(engine.args, "stealth", False))
    explicit = None
    if hasattr(engine, "dns_threads") and engine.dns_threads:
        explicit = int(engine.dns_threads)
    elif engine.cfg("dns_threads", 0):
        explicit = int(engine.cfg("dns_threads"))
    if explicit:
        if stealth:
            return max(16, min(64, explicit))
        return min(400, max(16, explicit))
    base = int(getattr(engine.args, "threads", 0) or 0) or 40
    if stealth:
        return max(16, min(64, base))
    return min(400, max(64, base * 4))


def run(engine):
    t = engine.target
    dom = t.hostname.lstrip(".")
    if t.is_ip_literal:
        return
    found = {dom: ip for ip in [t.primary_ip] if ip}
    words = engine.subs_words() or ["www", "mail", "api", "dev", "test"]
    candidates = set("%s.%s" % (w, dom) for w in words)

    ct_future = None
    if engine.online:
        # Kick off CT-log harvesting in a background thread, then START the DNS
        # sweep immediately instead of serialising a 6s crt.sh round-trip in
        # front. A short wall-clock cap means an unreachable/rate-limited
        # crt.sh tallies nothing and delays nothing — wordlist-only proceeds.
        _pool = cf.ThreadPoolExecutor(max_workers=1)
        ct_future = (_pool, _pool.submit(_fetch_ct, dom, engine.http.next_ua()))

    cands = sorted(candidates)[:30000]
    live = _resolve_many(engine, cands, dom)

    if ct_future:
        pool, fut = ct_future
        try:
            extra = fut.result(timeout=3.0)
            if extra:
                names_seen = {h for h, _ in live}
                extra = extra - names_seen  # drop any already resolved
                if extra:
                    engine.log.info(
                        "[recon.subdomains] +%d extra names via CT logs"
                        % len(extra))
                    # resolve the CT-only names too, so every entry has a real IP
                    live += _resolve_many(engine, sorted(extra), dom)
        except Exception:
            _l = getattr(engine, "log", None)
            if _l is not None:
                try:
                    _l.debug("crt.sh time-boxed out - wordlist only")
                except Exception:
                    pass
        finally:
            pool.shutdown(wait=False)

    found.update({h: ip for h, ip in live if ip})
    engine.state.setdefault("subdomains", [{"host": h, "ip": found[h]}
                                           for h in sorted(found)])
    if found:
        live_list = [{"host": h, "ip": found[h]} for h in sorted(found)]
        listing = "\n".join("%-42s %s" % (e["host"], e["ip"])
                            for e in live_list[:60])
        extra = "" if len(live_list) <= 60 else \
            "\n... (%d total)" % len(live_list)
        engine.db.add_finding(Finding(
            t.display, "recon.subdomains", "recon", "info",
            "Subdomains discovered: %d" % len(live_list),
            detail="Enumerated via DNS wordlist%s" %
                   (" + Certificate Transparency logs"
                    if engine.online else ""),
            evidence=listing + extra, confidence="firm"))
        wildcard_test = "vjr-wildcard-%s.%s" % (engine.nonce(), dom)
        if _resolve(wildcard_test)[1]:
            engine.db.add_finding(Finding(
                t.display, "recon.subdomains", "recon", "info",
                "Wildcard DNS detected",
                detail="Every subdomain resolves; enumeration results may be "
                       "wildcard artifacts.", confidence="firm"))


def _resolve_many(engine, cands, dom):
    """Resolve a candidate list under high concurrency. ``ex.map`` streams the
    candidates lazily through a single pool of `dns_threads` workers (map only
    keeps ~workers lookups in flight), giving bounded backpressure even for an
    18k+ wordlist while saturating the resolver — far more throughput than the
    general HTTP thread count."""
    n_workers = _dns_workers(engine)
    total = len(cands)
    resolved = found = 0
    live = []
    with cf.ThreadPoolExecutor(max_workers=n_workers) as ex:
        for host, ip in ex.map(_resolve, cands):
            resolved += 1
            if ip:
                live.append((host, ip))
                found += 1
            if resolved % 100 == 0 or resolved == total:
                engine.progress(cur=resolved, total=total,
                                detail="recon.subdomains %d/%d" %
                                       (resolved, total))
    if found:
        engine.log.info("[recon.subdomains] %d/%d resolved (%d workers)"
                        % (found, total, n_workers))
    return live
