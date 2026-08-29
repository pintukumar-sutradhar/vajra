"""VAJRA UDP service prober — DNS CHAOS, NTP mode-3, SNMP sysDescr."""
import socket
import struct

from core.database import Finding


def _udp(host, port, payload, timeout=2.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (host, port))
        data, _addr = s.recvfrom(4096)
        s.close()
        return data
    except Exception:
        return b""


def probe_dns_version(host):
    tid = b"\x13\x37"
    flags = b"\x01\x00"
    qd = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"\x07version\x04bind\x00"
    qtail = b"\x00\x10\x00\x03"
    pkt = tid + flags + qd + qname + qtail
    raw = _udp(host, 53, pkt)
    txt = "".join(chr(b) for b in raw if 32 <= b < 127)
    if len(raw) > 20 and ("bind" in txt.lower() or "-" in txt[30:]):
        import re
        m = re.findall(r"[0-9]+\.[0-9A-Za-z.\-+]{1,24}", txt[24:])
        return "DNS CHAOS version.bind -> %s" % (m[0] if m else txt[28:60])
    return None


def probe_ntp(host):
    pkt = b"\x1b" + b"\x00" * 47
    raw = _udp(host, 123, pkt)
    if len(raw) >= 48:
        stratum = raw[1]
        refid = raw[12:16].decode("utf-8", "replace").strip("\x00")
        return "NTP reply — stratum=%d refid=%r" % (stratum, refid)
    return None


def probe_snmp(host):
    pkt = bytes.fromhex(
        "302902010004067075626c6963a01c02014b0201000201003011300f"
        "06092b060102010101000500")
    raw = _udp(host, 161, pkt)
    if raw.startswith(b"0") and len(raw) > 20:
        txt = "".join(chr(b) for b in raw if 32 <= b < 127)
        import re
        m = re.search(r"(Linux|Windows|Cisco|VMware|Juniper|MikroTik|"
                      r"FreeBSD|Darwin)[^\x00]{0,80}", txt)
        if m:
            return "SNMP public community — sysDescr: %s" % m.group(0)[:90]
        return "SNMP public community accepted (%d bytes)" % len(raw)
    return None


PROBES = [(53, probe_dns_version), (123, probe_ntp), (161, probe_snmp)]


def run(engine):
    t = engine.target
    if not getattr(engine.args, "udp", False) and engine.profile != "vast":
        return
    host = t.scan_host()
    notes = []
    for port, fn in PROBES:
        try:
            note = fn(host)
        except Exception:
            note = None
        if note:
            notes.append("%d/udp %s" % (port, note))
            engine.state.setdefault("udp_open", set()).add(port)
            engine.log.info("[udp] %d -> %s" % (port, note.split("->")[1][:70]))
    if notes:
        engine.db.add_finding(Finding(
            t.display, "network.udpprobe", "recon", "medium",
            "Responsive UDP services with information disclosure (%d)"
            % len(notes),
            detail="Enable --udp permanently in profiles that need it; "
                   "these services bypass TCP sweeps entirely.",
            evidence="\n".join(notes)[:3000], confidence="firm"))
    else:
        engine.db.add_event(t.display, "network.udpprobe", "no responses")
