"""VAJRA DNS zone-transfer (AXFR) check — tries a full zone transfer from
each authoritative nameserver. Uses dig when available; otherwise a raw DNS
query over TCP (stdlib). Read-only: zone transfers disclose internal host
names but send nothing destructive."""
import shutil
import socket
import struct
import subprocess
import time

from core.database import Finding


def _dig_axfr(ns, domain, timeout=12):
    try:
        out = subprocess.run(["dig", "@%s" % ns, domain, "AXFR", "+time=5",
                              "+tries=1", "+noall", "+answer"],
                             capture_output=True, text=True, timeout=timeout)
        lines = [l for l in out.stdout.splitlines() if l.strip()]
        if not lines:
            return None
        return lines[:200]
    except Exception:
        return None


def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("latin1")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _read_name(data, off):
    labels = []
    end_off = None
    for _ in range(20):
        l = data[off]
        if l & 0xC0 == 0xC0:
            ptr = ((l & 0x3F) << 8) | data[off + 1]
            if end_off is None:
                end_off = off + 2
            off = ptr
            continue
        off += 1
        if l == 0:
            return ".".join(labels) + ".", end_off if end_off is not None \
                else off
        labels.append(data[off:off + l].decode("latin1", "replace"))
        off += l
    return ".".join(labels) + ".", end_off


def _raw_axfr(ns_ip, domain, port=53, timeout=8):
    qid = int(time.time()) & 0xFFFF
    hdr = struct.pack(">HHHHHH", qid, 0x0000, 1, 0, 0, 0)
    q = _encode_name(domain) + struct.pack(">HH", 252, 1)
    msg = hdr + q
    pkt = struct.pack(">H", len(msg)) + msg
    s = socket.create_connection((ns_ip, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(pkt)
        blobs = []
        try:
            while len(blobs) < 8:
                ln = b""
                while len(ln) < 2:
                    ln += s.recv(2 - len(ln))
                (mlen,) = struct.unpack(">H", ln)
                if mlen == 0:
                    break
                body = b""
                while len(body) < mlen:
                    body += s.recv(mlen - len(body))
                blobs.append(body)
        except socket.timeout:
            pass
    finally:
        s.close()
    names, types = [], []
    for body in blobs:
        if len(body) < 12:
            continue
        (ancount,) = struct.unpack(">H", body[6:8])
        q = _encode_name(domain) + struct.pack(">HH", 252, 1)
        off = 12 + len(q)  # skip full question (name + qtype/qclass)
        for _ in range(ancount):
            if off >= len(body):
                break
            nm, off = _read_name(body, off)
            if off is None or off + 10 > len(body):
                break
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", body[off:
                                                                     off + 10])
            off += 10
            rd = body[off:off + rdlen]
            off += rdlen
            if rtype in (1, 2, 5, 6, 15, 28):
                if nm not in names:
                    names.append(nm)
                    types.append((rtype, nm))
    names = [n for n in names if n]
    ancount = sum(1 for b in blobs if len(b) >= 8 and
                  struct.unpack(">H", b[6:8])[0] > 0)
    if ancount >= 2 and len(names) >= 2:
        return names[:200], types
    return None


def run(engine):
    t = engine.target
    if not t.is_domain:
        return
    dom = t.hostname
    recs = engine.state.get("dns") or {}
    ns_list = recs.get("NS") if recs else None
    if not ns_list:
        engine.db.add_event(t.display, "recon.axfr",
                            "no NS records to attempt zone transfer against")
        return
    if shutil.which("dig"):
        ns = [x for x in ns_list if "." in str(x) and not x.startswith(";")]
        if not ns:
            return
        lines = _dig_axfr(ns[0], dom)
        if not lines:
            engine.db.add_event(t.display, "recon.axfr",
                                "transfer refused/empty (%s)" % ns[0])
            return
        names = sorted({l.split()[0] for l in lines if l.split()})
        engine.db.add_finding(Finding(
            t.display, "recon.axfr", "info-leak", "high",
            "DNS zone transfer enabled (%s) — %d record(s) disclosed" %
            (ns[0], len(names)),
            detail="The authoritative nameserver discloses the entire DNS "
                   "zone; internal hostnames feed subdomain/lateral attacks.",
            evidence="\n".join(names[:60]),
            remediation="Restrict AXFR to trusted operators on all "
                        "authoritative servers.", confidence="firm"))
        engine.state["axfr"] = {"ns": ns[0], "names": names}
        engine.log.finding("[axfr] %s: %d names from %s" %
                           (dom, len(names), ns[0]))
        return
    for ns in ns_list[:4]:
        try:
            ip = socket.gethostbyname(str(ns).strip("."))
        except Exception:
            continue
        try:
            res = _raw_axfr(ip, dom)
        except Exception:
            res = None
        if res:
            names, _types = res
            engine.db.add_finding(Finding(
                t.display, "recon.axfr", "info-leak", "high",
                "DNS zone transfer enabled (%s) — %d record(s) disclosed" %
                (ns, len(names)),
                detail="Raw DNS AXFR over TCP succeeded from the target's "
                       "own resolver path.",
                evidence="\n".join(names[:60]),
                remediation="Restrict AXFR to trusted operators.",
                confidence="firm"))
            engine.state["axfr"] = {"ns": str(ns), "names": names}
            engine.log.finding("[axfr] %s: %d names via %s" %
                               (dom, len(names), ns))
            return
    engine.db.add_event(t.display, "recon.axfr",
                        "zone transfer refused by all authoritative NS")