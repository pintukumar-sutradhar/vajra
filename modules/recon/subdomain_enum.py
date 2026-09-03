"""Vajra - subdomain enumeration: wordlist DNS brute + optional CT logs."""
import concurrent.futures as cf
import os
import socket
import struct
import urllib.request
import json

from core.database import Finding

# Direct-DNS fast path. OS getaddrinfo/gethostbyname is slow for brute sweeps:
# it resolves AAAA + A, folds in search domains, retries, and can hit a TCP
# fallback — each failing name can block a worker for many seconds even after
# setdefaulttimeout, because much of that work happens inside libc where the
# socket timeout doesn't apply. A raw single UDP A-query with a hard timeout we
# own is an order of magnitude faster for the (mostly NXDOMAIN) brute case, so
# we use it as the primary resolver and only fall back to the OS resolver if
# the direct channel proves unusable.
_DNS_TIMEOUT = 0.6
_DNS_NS = []            # populated lazily from resolv.conf
_DNS_NS_PROBED = False
_DNS_CHANNEL_OK = None  # tri-state: once True/False we trust it


def _ns_list():
    """Nameservers from /etc/resolv.conf, localhost/private/hostnames skipped
    (they're the slow path we're avoiding); caches the first parse."""
    global _DNS_NS, _DNS_NS_PROBED
    if _DNS_NS_PROBED:
        return list(_DNS_NS)
    _DNS_NS_PROBED = True
    out = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip().lower()
                if not line.startswith("nameserver"):
                    continue
                ns = line.split(None, 1)[-1].strip(" \t")
                if not ns:
                    continue
                try:
                    socket.inet_aton(ns)
                except OSError:
                    continue  # hostname, skip (hostname->IP adds a lookup)
                if ns.startswith("127.") or ns.startswith("::1") or \
                        ns.startswith("0.") or ns.startswith("fe80:"):
                    continue
                out.append(ns)
    except Exception:
        pass
    _DNS_NS = out
    return list(out)


def _build_query(host, qid):
    parts = host.rstrip(".").split(".")
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for p in parts:
        b = p.encode("ascii", "ignore")
        if len(b) > 63:
            return None
        q += struct.pack("B", len(b)) + b
    q += b"\x00" + struct.pack(">H", 1) + struct.pack(">H", 1)  # A, IN
    return q


def _skip_name(resp, off):
    """Skip a possibly-compressed DNS name; return offset past it or None."""
    while off < len(resp):
        ln = resp[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:  # compression pointer
            return off + 2
        off += 1 + ln
    return None


def _parse_a(resp, want_qid):
    """Return ``(ip_or_None, definitive)`` from a DNS response. ``definitive``
    is True when the server gave an authoritative negative answer (NXDOMAIN /
    no such A record) vs False on transient SERVFAIL/truncation we should not
    trust, so the caller can fall back to the OS resolver only when needed."""
    try:
        if len(resp) < 12:
            return None, False
        if struct.unpack(">H", resp[0:2])[0] != want_qid:
            return None, False
        rcode = resp[3] & 0x0F
        if rcode in (2,):  # SERVFAIL - transient, retry via OS resolver
            return None, False
        if rcode != 0:
            return None, True  # NXDOMAIN(3)/REFUSED(5)/other -> definitive no
        n_q, n_ans = struct.unpack(">HH", resp[4:8])
        off = 12
        for _ in range(n_q):
            off = _skip_name(resp, off)
            if off is None:
                return None, False
            off += 4
        for _ in range(n_ans):
            off = _skip_name(resp, off)
            if off is None:
                return None, False
            if off + 10 > len(resp):
                return None, False
            typ, _cls, _ttl, rdlen = struct.unpack(">HHIH", resp[off:off + 10])
            off += 10
            if typ == 1 and rdlen == 4 and off + 4 <= len(resp):
                return socket.inet_ntoa(resp[off:off + 4]), True
            off += rdlen
        return None, True  # NOERROR with no A -> definitive no
    except Exception:
        return None, False


def _direct_a(host):
    """Resolve `host` via a raw UDP A-query. Returns ``(ip_or_None, definitive)``
    (see _parse_a). Tries each configured nameserver under a hard timeout."""
    for ns in _ns_list():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(_DNS_TIMEOUT)
        try:
            qid = (os.getpid() ^ hash(host)) & 0xFFFF
            q = _build_query(host, qid)
            if q is None:
                return None, False
            sock.sendto(q, (ns, 53))
            data, _ = sock.recvfrom(1600)
            ip, definitive = _parse_a(data, qid)
            if definitive:
                return ip, True
            # transient (SERVFAIL/truncated) on this NS: try next NS
            continue
        except socket.timeout:
            continue
        except Exception:
            continue
        finally:
            sock.close()
    return None, False


def _probe_ns():
    """True if direct DNS answered a query authoritatively in a probe; if the
    direct channel is dead we stop trying it and use the OS resolver."""
    global _DNS_CHANNEL_OK
    if _DNS_CHANNEL_OK is not None:
        return _DNS_CHANNEL_OK
    ok = False
    for host in ("google.com", "cloudflare.com", "example.com"):
        try:
            ip, definitive = _direct_a(host)
            if definitive:
                ok = True
                break
        except Exception:
            continue
    _DNS_CHANNEL_OK = ok
    return ok


def _resolve(host):
    """Best-effort A lookup. Primary: a raw UDP DNS query with a hard timeout we
    own (fast, and immune to libc's un-bounded getaddrinfo work). A definitive
    NXDOMAIN/absent answer returns (host, None) immediately; only transient
    failures fall through to the slower OS resolver as a last resort. Both paths
    return quickly so every worker stays busy under high concurrency."""
    if _probe_ns():
        ip, definitive = _direct_a(host)
        if definitive:
            return host, ip
        # transient on all NS -> OS resolver last resort
    try:
        socket.setdefaulttimeout(1.5)
        ip = socket.gethostbyname(host)
        if ip:
            return host, ip
    except Exception:
        pass
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
    global _DNS_TIMEOUT
    t = engine.target
    dom = t.hostname.lstrip(".")
    if t.is_ip_literal:
        return
    _DNS_TIMEOUT = max(0.2, min(3.0,
                                float(engine.cfg("dns_timeout", 0.6))))
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
