"""VAJRA DNS reconnaissance."""
import socket
import subprocess
import shutil
import re

from core.database import Finding


def _dig(domain, rtype):
    for tool, args in (("dig", ["dig", "+short", rtype, domain]),
                       ("host", ["host", "-t", rtype, domain]),
                       ("nslookup", ["nslookup", "-type=" + rtype.lower(), domain])):
        if shutil.which(tool):
            try:
                out = subprocess.run(args, capture_output=True, text=True,
                                     timeout=10).stdout
                return [l.strip() for l in out.splitlines() if l.strip() and
                        not l.startswith(";")]
            except Exception:
                continue
    return []


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def run(engine):
    t = engine.target
    dom = t.hostname
    recs = {}
    for rt in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        vals = _dig(dom, rt) or []
        if vals:
            recs[rt] = vals[:12]
    a_ips = t.resolve()
    if not recs.get("A") and a_ips:
        recs["A"] = a_ips
    engine.state["dns"] = recs
    for ip in a_ips:
        rev = None
        try:
            rev = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        if rev:
            recs.setdefault("PTR", []).append("%s -> %s" % (ip, rev))
    if not recs:
        engine.db.add_finding(Finding(
            t.display, "recon.dns", "recon", "info",
            "No DNS records resolvable",
            detail="Host may be internal-only, firewalled DNS, or the resolver "
                   "is unreachable. Vajra continues using the literal address.",
            confidence="firm"))
        return
    summary = "\n".join("%-6s %s" % (k, ", ".join(v[:6])) for k, v in sorted(recs.items()))
    engine.db.add_finding(Finding(
        t.display, "recon.dns", "recon", "info", "DNS records enumerated",
        detail=summary, evidence=summary))
    ns = [x.lower() for x in recs.get("NS", [])]
    if any("cloudflare" in x for x in ns):
        engine.db.add_finding(Finding(
            t.display, "recon.dns", "recon", "info",
            "Domain uses Cloudflare nameservers",
            detail="Origin IP may be masked; direct-to-origin attacks require "
                   "historical DNS data.", confidence="possible"))
