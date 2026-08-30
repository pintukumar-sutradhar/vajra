"""VAJRA subdomain takeover (web.takeover): for every enumerated subdomain,
walk CNAME records; if the alias targets a known cloud/paas provider root and
the provider target does NOT resolve, the subdomain is dangling and can be
claimed. DNS-only check — indicates but does not confirm the takeover."""
import socket

from core.database import Finding

# provider CNAME -> (label, provider-verify-pattern)
TAKEOVER_ROOTS = {
    "s3.amazonaws.com": ("AWS S3 bucket (bucket gone)", "amazonaws.com"),
    "s3-website-us-east-1.amazonaws.com": ("AWS S3 static site", "amazonaws.com"),
    "github.io": ("GitHub Pages", "github.io"),
    "github.com": ("GitHub Pages", "github.io"),
    "herokuspace.com": ("Heroku", "herokudns"),
    "herokudns.com": ("Heroku legacy", "herokudns.com"),
    "azurewebsites.net": ("Azure App Service", "azurewebsites"),
    "trafficmanager.net": ("Azure Traffic Manager", "trafficmanager"),
    "cloudapp.net": ("Azure Cloud App (decommissioned)", "cloudapp.net"),
    "cloudfront.net": ("CloudFront CDN", "cloudfront.net"),
    "fastly.net": ("Fastly CDN", "fastly.net"),
    "netlify.app": ("Netlify", "netlify.app"),
    "vercel.app": ("Vercel", "vercel.app"),
    "pages.dev": ("Cloudflare Pages", "pages.dev"),
    "worker.dev": ("Cloudflare Workers", "worker.dev"),
    "zendesk.com": ("Zendesk (ticket center)", "zendesk.com"),
    "shopify.com": ("Shopify", "myshopify"),
    "salesforce.com": ("Salesforce", "salesforce.com"),
    "force.com": ("Salesforce (force.com)", "force.com"),
    "wordpress.com": ("WordPress.com", "wordpress.com"),
    "ghost.io": ("Ghost (io)", "ghost.io"),
    "bitbucket.io": ("Bitbucket Pages", "bitbucket.io"),
    "discourse.org": ("Discourse forum", "discourse"),
    "pantheonsite.io": ("Pantheon", "pantheonsite.io"),
    "readthedocs.io": ("Read the Docs", "readthedocs"),
}
# CNAME chains commonly ending in a dead-brand domain (legacy DNS dangling)
LEGACY_SUFFIX = ("azurewebsites.net", "cloudapp.net", "trafficmanager.net",
                 "herokudns.com", "ghost.io")


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None
    except Exception:
        return None


def _cname(host):
    """Raw DNS query for the CNAME of `host` (single-shot to 8.8.8.8)."""
    try:
        import struct
        hdr = struct.pack(">HHHHHH", 0x1122, 0x0100, 1, 0, 0, 0)
        q = b"".join(bytes([len(p)]) + p.encode()
                     for p in host.rstrip(".").split(".")) + b"\x00"
        qtype = struct.pack(">HH", 5, 1)  # CNAME IN
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(hdr + q + qtype, ("8.8.8.8", 53))
        data, _ = s.recvfrom(4096)
        s.close()
        return _parse_cname(data)
    except Exception:
        return None


def _parse_cname(data):
    """Extract the first CNAME target name from a DNS response."""
    try:
        idx = 12
        # skip question
        while idx < len(data):
            ln = data[idx]
            if ln == 0:
                idx += 1
                break
            idx += 1 + (ln if ln < 0xC0 else 0)
        cname = None
        lim = len(data) - 5
        while idx < lim:
            t = data[idx + 1]
            if t == 5:
                off = idx + 10
                target = []
                while off < len(data):
                    l2 = data[off]
                    if l2 == 0:
                        break
                    target.append(data[off + 1:off + 1 + l2].decode(
                        "ascii", "replace"))
                    off += 1 + l2
                cname = ".".join(target).lower()
                break
            rdlen = int.from_bytes(data[idx + 8:idx + 10], "big")
            idx += 10 + rdlen
        return cname
    except Exception:
        return None


def run(engine):
    t = engine.target
    subs = engine.state.get("subdomains") or []
    if not subs:
        engine.state.setdefault("no_subdomains", True)
        engine.log.warn("[takeover] no subdomains to CNAME-check")
        return
    checked = 0
    found = []
    for sub in subs[:40]:
        if isinstance(sub, dict):
            host = (sub.get("host") or sub.get("cname") or "").lower()
        else:
            host = str(sub).lower()
        if not host:
            continue
        if host in (t.display.lower(), t.hostname or ""):
            continue
        checked += 1
        if checked > 25:
            break
        cname = _cname(host)
        if not cname:
            continue
        root_key = None
        for root in TAKEOVER_ROOTS:
            if cname == root or cname.endswith("." + root) or \
                    cname.endswith(root):
                root_key = root
                break
        if not root_key:
            continue
        alive = _resolve(cname)
        if alive:
            continue
        label = TAKEOVER_ROOTS[root_key][0]
        sev = "high"
        if cname.endswith(LEGACY_SUFFIX):
            sev = "high"
        found.append((host, cname, label, sev))
        engine.db.add_finding(Finding(
            t.display, "web.takeover", "dangling-cname", sev,
            "Potential subdomain takeover: %s (dangling CNAME → %s)"
            % (host, cname),
            detail="%s -> %s (%s); provider target does not resolve, so the "
                   "record points at an unclaimed resource you can attempt to "
                   "register. Takes over the host + any cookies it sets." %
                   (host, cname, label),
            remediation="Remove obsolete DNS records or claim/own the target "
                        "resource; set up subdomain takeover monitoring.",
            confidence="possible"))
        engine.log.finding("[takeover] %s -> %s (dangling %s)"
                           % (host, cname, label))
    if not found and checked:
        engine.state.setdefault("takeover_checked", checked)
        engine.log.info("[takeover] %d subdomain(s) clean (no dangling CNAME)"
                        % checked)