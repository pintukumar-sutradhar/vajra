"""Vajra - service detection, banner grabbing, TLS certificate analysis and
CVE correlation and certificate analysis."""
import socket
import ssl
import datetime
import tempfile
import os

from core.database import Finding
from core.intelligence import guess_service, is_http_port
from modules.network.probes import run_deep_probes

PROBE_TIMEOUT = 4.0


def _recv_some(sock, n=1024):
    sock.settimeout(3.0)
    data = b""
    try:
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data


def _probe_banner(host, port, force_http=False):
    probes = []
    if force_http or is_http_port(port) or port in (80, 443, 8080, 8443,
                                                    8000, 8008, 5000, 3000):
        probes.append(("GET / HTTP/1.1\r\nHost: %s\r\n"
                       "User-Agent: Mozilla/5.0 Vajra\r\n\r\n" % host).encode())
    elif port in (21, 22, 25, 110, 143, 587, 993, 995, 465):
        probes.append(None)
    elif port == 6379:
        probes.append(b"*1\r\n$4\r\nPING\r\n")
    else:
        probes.append(b"\r\n")
    best = b""
    for probe in probes:
        try:
            s = socket.create_connection((host, port), timeout=PROBE_TIMEOUT)
            if probe:
                s.sendall(probe)
            data = _recv_some(s)
            s.close()
            if data:
                best = data
                break
        except Exception:
            continue
    return best[:1024]


def _tls_info(host, port, server_name=None):
    info = {}
    sni = server_name or host
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((host, port), timeout=6.0)
        tls = ctx.wrap_socket(raw, server_hostname=sni if not _is_ip(sni) else None)
        der = tls.getpeercert(True)
        info["version"] = tls.version()
        info["cipher"] = tls.cipher()[0] if tls.cipher() else ""
        tls.close()
        if der:
            pem = ssl.DER_cert_to_PEM_cert(der)
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                f.write(pem)
                path = f.name
            try:
                parsed = ssl._ssl._test_decode_cert(path)
                subj = dict(x[0] for x in parsed.get("subject", []))
                issuer = dict(x[0] for x in parsed.get("issuer", []))
                info["subject"] = subj
                info["issuer"] = issuer
                info["notAfter"] = parsed.get("notAfter")
                san = [v for k, v in parsed.get("subjectAltName", ()) if k == "DNS"]
                info["san"] = san[:20]
            except Exception:
                pass
            finally:
                os.unlink(path)
        return info
    except Exception as e:
        info["error"] = repr(e)
        return info


def _is_ip(value):
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _days_left(not_after_str):
    if not not_after_str:
        return None
    try:
        dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        return (dt - datetime.datetime.utcnow()).days
    except Exception:
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(not_after_str)
            return (dt.replace(tzinfo=None) - datetime.datetime.utcnow()).days
        except Exception:
            return None


SERVICE_HINTS = [
    ("openssh", "ssh"), ("dropbear", "ssh"), ("ssh-", "ssh"),
    ("vsftpd", "ftp"), ("proftpd", "ftp"), ("pure-ftpd", "ftp"), ("220 ", "ftp"),
    ("smtp", "smtp"), ("postfix", "smtp"), ("220 mx", "smtp"),
    ("http/1.", "http"), ("server:", "http"), ("<html", "http"),
    ("redis", "redis"), ("-err ", "redis"),
    ("mysql", "mysql"), ("mongodb", "mongodb"),
    ("imap", "imap"), ("pop3", "pop3"), ("+ok", "pop3"),
    ("microsoft", "msrpc"), ("kerberos", "kerberos"),
]


def _probe_classify(banner):
    """A banner only "proves" a service when its text is a recognizable
    protocol greeting — never when it is arbitrary echoed junk (in which
    case the port stays 'unproven' instead of being handed a guessed name)."""
    if isinstance(banner, bytes):
        banner = banner.decode("utf-8", "replace")
    low = (banner or "").lower()
    return any(hint in low for hint, _name in SERVICE_HINTS)


def _smtp_relay_check(host, port):
    try:
        s = socket.create_connection((host, port), timeout=6)
        s.settimeout(5)
        f = s.makefile("rwb")
        f.readline()
        s.sendall(b"EHLO vjr.local\r\n")
        ehlo = b""
        while True:
            line = f.readline()
            if not line or line[3:4] == b" ":
                break
            ehlo += line
        s.sendall(b"MAIL FROM:<probe@vjr.local>\r\n")
        m = f.readline().decode("utf-8", "replace")
        s.sendall(b"RCPT TO:<victim@example.com>\r\n")
        rc = f.readline().decode("utf-8", "replace")
        s.sendall(b"QUIT\r\n")
        s.close()
        return rc.startswith("250"), (m.strip() + " | RCPT->" + rc.strip())
    except Exception as e:
        return False, repr(e)


def _ldap_rootdse(host):
    search = (
        bytes([0x30, 0x2B])                       # SEQUENCE
        + b"\x02\x01\x01"                        # messageID 1
        + bytes([0x63])                            # searchRequest tag
        + bytes([0x24])                            # len 36
        + b"\x04\x00"                             # baseObject ""
        + b"\x0a\x01\x00"                        # scope base
        + b"\x0a\x01\x00"                        # deref never
        + b"\x02\x01\x01"                        # sizeLimit 1
        + b"\x02\x01\x0a"                        # timeLimit 10
        + b"\x01\x01\xff"                         # typesOnly false
        + b"\x87\x0bobjectClass"                  # present filter
        + b"\x30\x00"                             # attributes {}
    )
    try:
        s = socket.create_connection((host, 389), timeout=5)
        s.settimeout(4)
        s.sendall(search)
        raw = s.recv(2048)
        s.close()
        txt = "".join(chr(b) for b in raw if 32 <= b < 127)
        if raw and ("supportedLDAPVersion" in txt or
                    "namingContexts" in txt or "dc=" in txt.lower()):
            return txt[:300]
    except Exception:
        pass
    return None


def run(engine):
    t = engine.target
    host = t.scan_host()
    open_ports = engine.state.get("open_ports", {})
    services = []
    url_hint = None
    if t.kind == "url" and t.port:
        url_hint = t.port
    for port, latency in sorted(open_ports.items()):
        svc = {"host": host, "port": port, "service": "unknown",
               "possible_service": guess_service(port) or None,
               "proven": False, "banner": "", "product": "", "version": "",
               "tls": False, "latency_ms": latency}
        use_tls = port in (443, 8443, 993, 995, 465, 992, 990)
        banner = ""
        force_http = url_hint is not None and port == url_hint and \
            t.scheme == "http"
        if not use_tls or force_http:
            banner = _probe_banner(host, port,
                                   force_http=force_http).decode(
                                       "utf-8", "replace").strip()
            low = banner.lower()
            for hint, name in SERVICE_HINTS:
                if hint in low:
                    svc["service"] = name
                    svc["proven"] = True
                    break
            if not banner and port in (443, 465, 993, 995):
                use_tls = True
        if use_tls or svc["service"] in ("https", "https-alt"):
            info = _tls_info(host, port, server_name=t.hostname if t.is_domain else None)
            if "error" not in info:
                svc["tls"] = True
                svc["tls_version"] = info.get("version", "")
                svc["cert"] = {k: v for k, v in info.items() if k != "error"}
                svc["proven"] = True
                svc["service"] = "https" if port in (443, 8443) else "tls"
                if not banner:
                    banner = "%s / cert CN=%s" % (
                        info.get("version", "TLS"),
                        info.get("subject", {}).get("commonName", "?"))
            else:
                if svc["service"] in ("unknown", "https"):
                    banner = banner or ""
        if banner:
            svc["banner"] = banner[:1000]
            provable = _probe_classify(banner) or svc["proven"]
            if provable:
                svc["proven"] = True
                prod_ver = _extract_prod_version(banner)
                if prod_ver:
                    svc["product"], svc["version"] = prod_ver
        if not svc["proven"] and svc["banner"]:
            svc["service"] = "unproven"
        elif not svc["proven"]:
            svc["service"] = "unknown"
        services.append(svc)
        engine.db.add_service(t.display, port, svc["service"], svc["banner"],
                              svc["product"], svc["version"], svc["tls"])
        label = "%-5d %-12s %s" % (port, svc["service"],
                                   svc["banner"][:90].replace("\n", " "))
        engine.log.finding("[service] %s (port open verified; %s)" % (
            label, "service confirmed by banner/handshake"
            if svc["proven"] else "service UNPROVEN — no protocol response"))
    engine.state["services"] = services

    for svc in services:
        if svc["port"] in (25, 587) and svc.get("banner"):
            relayed, detail = _smtp_relay_check(host, svc["port"])
            if relayed:
                engine.db.add_finding(Finding(
                    t.display, "network.services", "exposure", "high",
                    "OPEN MAIL RELAY on port %d" % svc["port"],
                    detail="External spoofed sender accepted for external "
                           "recipient; spam/phishing infrastructure value.",
                    evidence=detail[:500],
                    remediation="Restrict RCPT domains; require auth for "
                                "external delivery.", confidence="firm"))
        if svc["port"] == 389:
            dse = _ldap_rootdse(host)
            if dse:
                svc["deep_probe"] = "LDAP rootDSE anonymous read: " + dse

    try:
        notes = run_deep_probes(host, services)
    except Exception as e:
        notes = []
        engine.log.debug("deep probes failed: %r" % e)
    for n in notes:
        engine.log.info("[deep-probe] " + n)
    if notes:
        engine.db.add_finding(Finding(
            t.display, "network.services", "recon", "info",
            "Deep protocol handshake results (%d)" % len(notes),
            detail="Active handshakes beyond passive banners across "
                   "non-HTTP protocols.",
            evidence="\n".join(notes)[:4000], confidence="firm"))
    import re as _re
    for svc in services:
        dp = svc.get("deep_probe", "") or ""
        if "[NO AUTHENTICATION]" in dp:
            engine.db.add_finding(Finding(
                t.display, "exploit.creds", "exposure", "high",
                "VNC server allows connections WITHOUT authentication "
                "(port %d)" % svc["port"],
                detail="Full desktop control available anonymously.",
                evidence=dp, confidence="firm"))
        if "[UNAUTHENTICATED]" in dp:
            engine.db.add_finding(Finding(
                t.display, "exploit.creds", "exposure", "high",
                "Redis INFO disclosed without authentication (port %d)"
                % svc["port"],
                detail="Server internals, OS and memory layout leak to "
                       "anonymous clients.", evidence=dp[:600],
                confidence="firm"))
        mstat = _re.search(r"stat_lines=(\d+)", dp)
        if mstat and int(mstat.group(1)) > 0:
            engine.db.add_finding(Finding(
                t.display, "exploit.creds", "exposure", "medium",
                "Memcached statistics exposed without auth (port %d)"
                % svc["port"],
                detail="%d STAT variables disclose cache keys, network and "
                       "memory layout." % int(mstat.group(1)),
                confidence="firm"))

    intel_hits = []
    for svc in services:
        for hit in engine.intel.correlate_banner(svc["banner"]):
            intel_hits.append((svc, hit))
    for svc, hit in intel_hits:
        cves = ", ".join("%s(%s)" % (c["id"], c["cvss"] or "?") for c in hit["cves"][:5])
        top_cvss = max((c["cvss"] or 0) for c in hit["cves"])
        sev = "critical" if top_cvss >= 9 else ("high" if top_cvss >= 7 else "medium")
        engine.db.add_finding(Finding(
            t.display, "network.services", "cve-surface", sev,
            "Potentially vulnerable software on port %d: %s %s" %
            (svc["port"], hit["product"], hit["version"]),
            detail="Banner-matched known vulnerabilities: %s\n%s" %
                   (cves, "\n".join("- %s: %s" % (c["id"], c["desc"]) for c in hit["cves"][:6])),
            evidence="Banner: %s" % svc["banner"][:300],
            remediation="Update the affected component to a patched version; "
                        "verify exposure manually before exploitation attempts.",
            confidence="possible"))

    for svc in services:
        cert = svc.get("cert") or {}
        if svc.get("tls"):
            days = _days_left(cert.get("notAfter"))
            if days is not None:
                if days < 0:
                    engine.db.add_finding(Finding(
                        t.display, "web.tls", "tls", "high",
                        "Expired TLS certificate on port %d (%d days)" %
                        (svc["port"], -days),
                        evidence="notAfter=%s" % cert.get("notAfter")))
                elif days < 15:
                    engine.db.add_finding(Finding(
                        t.display, "web.tls", "tls", "medium",
                        "TLS certificate expiring soon on port %d (%d days)" %
                        (svc["port"], days), evidence=str(cert.get("notAfter"))))
            subj = cert.get("subject", {})
            issuer_cn = cert.get("issuer", {}).get("commonName", "")
            cn = subj.get("commonName", "")
            if issuer_cn and cn and issuer_cn.lower().replace("*", "") == \
                    cn.lower().replace("*", ""):
                engine.db.add_finding(Finding(
                    t.display, "web.tls", "tls", "high",
                    "Self-signed certificate on port %d" % svc["port"],
                    evidence="CN=%s issued by=%s" % (cn, issuer_cn)))


def _extract_prod_version(banner):
    patterns = [r"(openssh)[_ ](\d+[\w.]*)", r"(apache)/(\d+[\w.]*)",
                r"(nginx)/(\d+[\w.]*)", r"(microsoft-iis)/(\d+[\w.]*)",
                r"(vsftpd)[_ ]?(\d+[\w.]*)", r"(proftpd)[_ ](\d+[\w.]*)",
                r"(tomcat)/(\d+[\w.]*)", r"(php)/([\d.]+)",
                r"(werkzeug)/(\d+[\w.]*)", r"(python)/(\d+[\w.]*)",
                r"(simplehttp)/(\d+[\w.]*)", r"(jenkins)/?\s*\(?([\w.-]+)",
                r"(mysql)[_ ]?(\d+[\w.]*)", r"(postgresql)[_ ]?(\d+[\w.]*)"]
    import re
    for pat in patterns:
        m = re.search(pat, banner, re.I)
        if m:
            return m.group(1), m.group(2)
    return None
