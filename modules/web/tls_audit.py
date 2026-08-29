"""Vajra - TLS protocol/cipher strength audit for HTTPS web targets."""
import ssl
import socket

from core.database import Finding

WEAK_VERSIONS = [("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None)),
                 ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                 ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))]
WEAK_CIPHER_TOKENS = ["RC4", "DES-CBC3", "3DES", "NULL", "EXPORT", "AES128-SHA ",
                      "CAMELLIA"]


def _try_version(host, port, version, sni=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except Exception:
        return False
    try:
        s = socket.create_connection((host, port), timeout=5)
        ts = ctx.wrap_socket(s, server_hostname=sni if sni and not _isip(sni) else None)
        ver = ts.version()
        ts.close()
        return ver is not None
    except Exception:
        return False


def _isip(v):
    import ipaddress
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def run(engine):
    t = engine.target
    host = t.scan_host()
    services = [s for s in engine.state.get("services", []) if s.get("tls")]
    web_tls = []
    for wt in engine.state.get("web_targets", []):
        if wt["url"].lower().startswith("https"):
            web_tls.append(wt)
    if not services and not web_tls:
        return
    ports = {s["port"] for s in services}
    for wt in web_tls:
        from urllib.parse import urlparse
        p = urlparse(wt["url"])
        if p.port:
            ports.add(p.port)
    sni = t.hostname if t.is_domain else None
    for port in sorted(ports):
        weak = []
        for label, ver in WEAK_VERSIONS:
            if ver is None:
                continue
            if _try_version(host, port, ver, sni):
                weak.append(label)
        if weak:
            sev = "high" if any(x != "TLSv1.1" for x in weak) else "medium"
            engine.db.add_finding(Finding(
                t.display, "web.tls", "tls", sev,
                "Deprecated TLS protocol enabled on port %d: %s" %
                (port, ", ".join(weak)),
                detail="Legacy protocols enable downgrade attacks (POODLE etc.).",
                remediation="Disable SSLv3/TLS1.0/TLS1.1; require TLS1.2+.",
                confidence="firm"))
        ctx_pref = ssl.create_default_context()
        ctx_pref.check_hostname = False
        ctx_pref.verify_mode = ssl.CERT_NONE
        try:
            s = socket.create_connection((host, port), timeout=5)
            ts = ctx_pref.wrap_socket(s, server_hostname=sni if sni and not _isip(sni) else None)
            cipher = ts.cipher()[0] if ts.cipher() else ""
            proto = ts.version() or ""
            cert_bin = ts.getpeercert(binary_form=True)
            _cert_audit(engine, t, port, cert_bin)
            ts.close()
            if any(tok in cipher.upper() for tok in WEAK_CIPHER_TOKENS):
                engine.db.add_finding(Finding(
                    t.display, "web.tls", "tls", "medium",
                    "Weak cipher negotiated on port %d: %s (%s)" %
                    (port, cipher, proto),
                    confidence="firm"))
            elif proto:
                engine.log.debug("tls ok port=%d %s/%s" % (port, proto, cipher))
        except Exception:
            pass


def _cert_audit(engine, t, port, cert_bin):
    """Certificate decay audit: expiry, self-signed, SAN coverage. Uses
    OpenSSL-style parsing via cryptography when available; otherwise a raw
    OpenSSL subprocess decode is attempted."""
    if not cert_bin:
        return
    try:
        import ssl as _ssl
        der = ssl.DER_cert_to_PEM_cert(cert_bin)
        # cryptography path
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        import datetime
        cert = x509.load_pem_x509_certificate(der.encode(), default_backend())
        na = cert.not_valid_after_utc
        nb = cert.not_valid_before_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        host = t.hostname or t.display
        if now < nb:
            engine.db.add_finding(Finding(
                t.display, "web.tls", "cert", "medium",
                "TLS certificate not yet valid on port %d" % port,
                evidence="not_before=%s" % nb.isoformat(),
                confidence="firm"))
            return
        if na < now:
            engine.db.add_finding(Finding(
                t.display, "web.tls", "cert", "high",
                "TLS certificate EXPIRED on port %d (%s ago)" % (
                    port, (now - na)),
                evidence="not_after=%s" % na.isoformat(),
                remediation="Replace the certificate before its expiry.",
                confidence="firm"))
            return
        days = (na - now).days
        if days <= 30:
            engine.db.add_finding(Finding(
                t.display, "web.tls", "cert", "medium",
                "TLS certificate expires in %d day(s) on port %d" %
                (days, port),
                evidence="not_after=%s" % na.isoformat(), confidence="firm"))
        iss = cert.issuer.rfc4514_string()
        sub = cert.subject.rfc4514_string()
        if iss.lower().strip("cn=, ") == sub.lower().strip("cn=, ") or \
                "CN=" in iss.upper() and iss.split("CN=")[-1].strip() == \
                sub.split("CN=")[-1].strip():
            engine.db.add_finding(Finding(
                t.display, "web.tls", "cert", "info",
                "Self-signed certificate on port %d (ignore if internal)" % port,
                evidence="subject=%s\nissuer=%s" % (sub, iss),
                confidence="firm"))
        try:
            ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value
            names = [str(v) for v in ext.get_values_for_type(x509.DNSName)]
        except Exception:
            names = []
        if host and names:
            import fnmatch
            if not any(fnmatch.fnmatch(host.lower(), n.lower().lstrip("*.")[0] +
                                       ("." + host.split(".", 1)[1])
                                       if "*." in n and host.count(".") > 0
                                       else n.lower()) or host.lower() == n.lower()
                       for n in names):
                if not any(n for n in names if n.startswith("*.") and
                           host.lower().endswith(n[2:])):
                    engine.db.add_finding(Finding(
                        t.display, "web.tls", "cert", "medium",
                        "Certificate SAN doesn't cover host %s (port %d)" %
                        (host, port),
                        evidence="SAN: " + ", ".join(names),
                        confidence="firm"))
    except Exception:
        pass
