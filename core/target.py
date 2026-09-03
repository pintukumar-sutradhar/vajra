"""Vajra - target model supporting IPs, CIDR ranges and URLs."""
import socket
import ipaddress
import re
from urllib.parse import urlparse

from core.utils import is_ip, normalize_url


class Target:
    def __init__(self, raw):
        raw = raw.strip().rstrip("/")
        self.raw = raw
        self.kind = "host"
        self.scheme = None
        self.url = None
        self.path = "/"
        self.port = None
        self.ips = []
        self.resolved = False

        if re_scheme(raw):
            self.kind = "url"
            norm = normalize_url(raw)
            p = urlparse(norm)
            self.scheme = p.scheme
            self.hostname = p.hostname or ""
            self.port = p.port or (443 if p.scheme == "https" else 80)
            self.path = p.path or "/"
            self.url = "%s://%s%s" % (p.scheme, p.netloc, p.path)
            if p.query:
                self.url += "?" + p.query
        else:
            self.kind = "host"
            self.hostname = raw.strip("[]")
            self.port = None

        self.ip_literal = is_ip(self.hostname) if self.kind != "cidr" else False
        if self.ip_literal:
            self.ips = [self.hostname.strip("[]")]
            self.resolved = True

        if self.kind == "url":
            self.display = self.url
        else:
            self.display = self.hostname

    @property
    def primary_ip(self):
        return self.ips[0] if self.ips else None

    @property
    def is_ip_literal(self):
        return bool(self.ip_literal)

    @property
    def is_domain(self):
        return (not self.is_ip_literal) and bool(self.hostname)

    def resolve(self, timeout=5.0):
        if self.resolved or not self.hostname:
            return self.ips
        old = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(timeout)
            # Resolve both IPv4 and IPv6
            infos = socket.getaddrinfo(self.hostname, None, socket.AF_UNSPEC)
            seen = []
            for fam, _typ, _proto, _canon, sockaddr in infos:
                ip = sockaddr[0]
                if "%" in ip:
                    ip = ip.split("%")[0]
                if ip not in seen:
                    seen.append(ip)
            self.ips = seen
            self.resolved = True
        except Exception:
            self.ips = []
        finally:
            socket.setdefaulttimeout(old)
        return self.ips

    @property
    def has_ipv6(self):
        return any(":" in ip and "." not in ip for ip in self.ips)

    def scan_host(self):
        # Prefer IPv6 if available, else IPv4, else hostname
        for ip in self.ips:
            if ":" in ip and "." not in ip:
                return ip
        return self.primary_ip or self.hostname

    def http_base(self):
        if self.kind == "url":
            return "%s://%s:%d" % (self.scheme, self.hostname, self.port)
        return None

    def __repr__(self):
        return "<Target %s kind=%s>" % (self.display, self.kind)


def re_scheme(raw):
    return raw.lower().startswith(("http://", "https://"))


def expand_targets(raw_value):
    targets = []
    value = raw_value.strip()
    if value.startswith("@"):
        path = value[1:]
        with open(path, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        for ln in lines:
            targets.extend(expand_single(ln))
        return dedupe(targets)
    for part in value.split(","):
        part = part.strip()
        if part:
            targets.extend(expand_single(part))
    return dedupe(targets)


def expand_single(raw):
    if raw.startswith("@"):
        return expand_targets(raw)
    if "/" in raw and not raw.lower().startswith(("http://", "https://")):
        try:
            return [Target(ip) for ip in expand_cidr(raw)]
        except ValueError:
            pass
    return [Target(raw)]


def dedupe(targets):
    seen = set()
    out = []
    for t in targets:
        key = t.raw.lower()
        if key not in seen:
            seen.add(key)
            out.append(t)
    return out
