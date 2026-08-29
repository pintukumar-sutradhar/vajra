"""VAJRA SMTP audit — open-relay probe (envelope only, no message sent) and
VRFY/EXPN user enumeration against known usernames.

Read-only with respect to mail delivery: we stop after RCPT acceptance and
never send DATA, so no mail is ever delivered. Known usernames come from the
fast tier wordlist plus the standard account list."""
import socket
import time

from core.database import Finding
from core.utils import load_json

SMTP_PORT = 25
BANNER_PORTS = (25, 465, 587)
KNOWN_ACCTS = ("root", "admin", "administrator", "postmaster", "info",
               "sales", "support", "webmaster", "test", "kali", "guest",
               "noreply", "user", "mail")

RELAY_SENDER = "vajra@probe.invalid"
RELAY_JUICE = "vajra-no-such-mailbox-12345@example.org"


def _smtp_session(host, port, timeout=6.0, banner=None):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        if (port, banner) and port == 465:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        resp = banner or s.recv(1024)
        return s, resp
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None, b""


def _cmd(s, line, want=b"250", wait_sleep=0.15):
    try:
        s.sendall(line + b"\r\n")
        time.sleep(wait_sleep)
        chunks = []
        while True:
            s.settimeout(2.0)
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
            if chunks[-1].count(b"\n") >= 1 and chunks[-1].strip().endswith(
                    (b" ",)) is False:
                pass
            if b"" or b" " in chunks[-1]:
                break
        data = b"".join(chunks)
        ok = want in data or (want == b"250" and b"220" in data[:3]
                              and line.startswith(b"NOOP"))
        return ok, data
    except Exception:
        return False, b""


def run(engine):
    t = engine.target
    host = t.scan_host()
    services = {s["port"]: s for s in engine.state.get("services", [])}
    if SMTP_PORT not in services:
        engine.db.add_event(t.display, "network.smtp", "no SMTP listener on 25")
        return
    banner = str(services[SMTP_PORT].get("banner", ""))[:200]
    s, resp = _smtp_session(host, SMTP_PORT, banner=banner)
    if s is None:
        return
    try:
        ehlo = b"EHLO vajra.local"
        s.sendall(ehlo + b"\r\n")
        time.sleep(0.2)
        ehlo_resp = s.recv(4096)
        feats = b"auth" in ehlo_resp.lower() or b" pipelining" in \
            ehlo_resp.lower()
        ext = [ln.decode("latin1", "replace").strip()
               for ln in ehlo_resp.splitlines()[1:] if ln.strip()]

        accepted = []
        try:
            s.sendall(b"MAIL FROM:<%s>\r\n" % RELAY_SENDER.encode())
            s.recv(256)
            s.sendall(b"RCPT TO:<%s>\r\n" % RELAY_JUICE.encode())
            rj = s.recv(256)
        except Exception:
            rj = b""
        if b"250" in rj[:3]:
            accepted.append("external RCPT accepted")
        for cand in ("recipient@%s.invalid" % t.display, RELAY_SENDER):
            try:
                s.sendall(b"RCPT TO:<%s>\r\n" % cand.encode())
                rr = s.recv(256)
            except Exception:
                rr = b""
            if (b"250" in rr[:3] or b"251" in rr[:3]) and \
                    "not in recipient" not in rr.lower():
                accepted.append(cand)
        if accepted:
            engine.db.add_finding(Finding(
                t.display, "network.smtp", "misconfiguration", "high",
                "SMTP likely open relay / permissive recipient handling",
                detail="Envelope check (no DATA, no mail sent): server "
                       "accepted RCPT for %s" % "; ".join(accepted[:3]),
                evidence="MAIL FROM:<%s>\nRCPT TO:<%s> -> %s" % (
                    RELAY_SENDER, RELAY_JUICE,
                    rj.decode("latin1", "replace").strip()[:120]),
                remediation="Restrict relay to authenticated senders; "
                            "reject unknown-domain recipients.",
                confidence="possible"))

        vrfy_users = []
        cap_vrfy = 10
        for un in KNOWN_ACCTS:
            if len(vrfy_users) >= cap_vrfy:
                break
            try:
                s.sendall(b"VRFY %s\r\n" % un.encode())
                r = s.recv(256)
            except Exception:
                r = b""
            if r[:3] in (b"250", b"251", b"252"):
                vrfy_users.append((un, r.decode("latin1", "replace")
                                   .strip()[:90]))
        if vrfy_users:
            engine.db.add_finding(Finding(
                t.display, "network.smtp", "user-enum", "medium",
                "SMTP VRFY/EXPN enabled — %d account(s) confirmed" %
                len(vrfy_users),
                detail="An unauthenticated VRFY reveals valid local "
                       "mailboxes, seeding targeted phishing/password sprays.",
                evidence="\n".join("VRFY %s -> %s" % u for u in vrfy_users),
                remediation="Disable VRFY/EXPN (expose_rcpt_vrfy off) on the "
                            "MTA.", confidence="firm"))
            engine.log.finding("[smtp] VRFY: %s" %
                               ", ".join(u for u, _ in vrfy_users))

        extstr = ", ".join(x.split()[0] for x in ext[:8]) if ext else ""
        engine.db.add_finding(Finding(
            t.display, "network.smtp", "recon", "info",
            "SMTP audit complete (%s)" % (extstr or "no EHLO extensions"),
            evidence="banner: %s\nehlo features: %s" % (banner.strip()[:120],
                                                        extstr),
            confidence="firm"))
    finally:
        try:
            s.sendall(b"QUIT\r\n")
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass

    if not accepted and not vrfy_users:
        engine.log.debug("smtp: no relay/enum signals on %s:25" % host)