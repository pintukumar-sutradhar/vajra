"""Vajra - WHOIS lookup via native binary, else raw port-43 protocol."""
import re
import socket

from core.database import Finding

IANA_WHOIS = "whois.iana.org"


def _raw_whois(server, query, timeout=8):
    try:
        s = socket.create_connection((server, 43), timeout=timeout)
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data.decode("utf-8", "replace"))
        s.close()
        return "\n".join(chunks)
    except Exception:
        return ""


def run(engine):
    t = engine.target
    dom = t.hostname
    if t.is_ip_literal:
        text = ""
        for srv in ("whois.arin.net", "whois.ripe.net"):
            text = _raw_whois(srv, "n + %s" % dom)
            if text:
                break
    else:
        text = _raw_whois(IANA_WHOIS, dom)
        m = re.search(r"whois:\s+(\S+)", text or "")
        server = m.group(1) if m else None
        if server:
            detailed = _raw_whois(server, dom)
            if detailed:
                text = detailed
    if not text:
        try:
            from core.utils import PROJECT_ROOT
            import subprocess
            if subprocess.run(["which", "whois"], capture_output=True).returncode == 0:
                text = subprocess.run(["whois", dom], capture_output=True,
                                      text=True, timeout=15).stdout
        except Exception:
            text = ""
    if not text:
        engine.db.add_event(t.display, "recon.whois", "no whois data reachable")
        return
    keys = ["registrar:", "creation date:", "created:", "expiry date:",
            "expires:", "registrant", "name server:", "orgname", "netname",
            "country", "org-tech-handle"]
    picked = []
    for line in text.splitlines():
        low = line.strip().lower()
        if any(low.startswith(k) for k in keys):
            picked.append(line.strip())
    summary = "\n".join(picked[:24]) or text[:1500]
    engine.db.add_finding(Finding(
        t.display, "recon.whois", "recon", "info", "WHOIS registration details",
        detail=summary, evidence=summary[:4000], confidence="firm"))
    exp = re.search(r"expir\w*[:\s]+(\S+)", text, re.I)
    if exp:
        engine.state.setdefault("whois", {})["expiry"] = exp.group(1)
