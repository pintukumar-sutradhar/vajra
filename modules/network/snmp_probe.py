"""VAJRA network.snmp_probe — SNMPv1 community-string sweep + system info.

Pure-stdlib BER encoder for an SNMPv1 GET (sysDescr .1.1.0, sysName .5.0,
sysUpTime .3.0). Runs only when the UDP probe already responded on 161/udp
(cond udp:161, which itself requires --udp or the vast profile). Each
candidate community is tried with a short timeout, so a closed/filtered
stack costs seconds; a live one answers on the first default strings.

Read-only: never issues SNMP SETs."""
import socket
import struct
import time

from core.database import Finding
from core.utils import load_json

MAX_COMMUNITIES = 10
PYL_KIND = {0: "unknown/implicit", 1: "octets", 2: "oid", 4: "ip", 5: "counter32",
            6: "gauge", 7: "time-ticks", 8: "opaque", 9: "nsap", 128: "string"}
# suffices: sysDescr.1.1.0  sysName.1.5.0  sysUpTime.1.3.0
SUFFICES = {b"\x2b\x06\x01\x02\x01\x01\x01\x00": "sysDescr",
            b"\x2b\x06\x01\x02\x01\x01\x05\x00": "sysName",
            b"\x2b\x06\x01\x02\x01\x01\x03\x00": "sysUpTime"}


def _len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0x7F]) + out
        n >>= 7
    return bytes([0x80 | len(out)]) + out


def _tlv(tag, payload):
    return bytes([tag]) + _len(len(payload)) + payload


def _oid_bytes(subids):
    out = b""
    for sid in subids:
        if sid < 128:
            out += bytes([sid])
        else:
            stack = []
            while sid:
                stack.insert(0, sid & 0x7F)
                sid >>= 7
            out += bytes([stack[0] | 0x80]) + bytes(stack[1:])
    return out


def _int(n):
    if n < 0x80:
        return bytes([n])
    return b"\x80" if n < 0x8100 else _int(n >> 7) + bytes([n & 0x7F])


def snmp_get(community, suffix, reqid=None):
    """Build a fully BER-encoded SNMPv1 GetRequest PDU. Returns bytes."""
    reqid = reqid if reqid is not None else int(time.time() * 1000) & 0x7FFFFFFF
    oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"  # fallback sysDescr
    if suffix:
        oid = suffix
    vb = _tlv(0x30, _tlv(0x06, oid) + b"\x05\x00")
    vbl = _tlv(0x30, vb)
    pdu = _tlv(0xA0, _tlv(0x02, _int(reqid)) + b"\x02\x01\x00\x02\x01\x00" + vbl)
    msg = _tlv(0x30, b"\x02\x01\x00" + _tlv(0x04, community) + pdu)
    return msg


def _pdu_inner(pdu):
    """Strip any TLV header, returning (inner, ok) where inner is the
    payload and `ok` reflects a well-formed length field."""
    if not pdu or len(pdu) < 2:
        return None, False
    ln = pdu[1]
    n = 0
    if ln & 0x80:
        n = ln & 0x7F
        if n <= 0 or 2 + n > len(pdu):
            return None, False
        ln = int.from_bytes(pdu[2:2 + n], "big")
    return pdu[2 + n:2 + n + ln], True


def _parse_get_response(pkt):
    """Best-effort: return (reqid_ok, error_status, oid_name, value).
    Walks BER strictly inside each SEQUENCE. Rejects anything malformed."""
    try:
        if not pkt or pkt[0] != 0x30:
            return None
        body = pkt[2 + (pkt[1] & 0x7F):] if pkt[1] >= 0x80 else pkt[2:]
        ver, off = _walk_tag(body, 0, 0x02)
        if ver is None:
            return None
        comm, off = _walk_tag(body, off, 0x04)
        pdu, off = _walk_header(body, off)
        if not pdu or pdu[0] not in (0xA0, 0xA1, 0xA2):
            return None
        pb, ok = _pdu_inner(pdu)
        if not ok:
            return None
        rid, o = _walk_tag(pb, 0, 0x02)
        if rid is None:
            return None
        es, o = _walk_tag(pb, o, 0x02)
        es = None if es is None else int.from_bytes(es, "big")
        ei, o = _walk_tag(pb, o, 0x02)
        vbmsghdr, o = _walk_header(pb, o)          # varbind-list SEQUENCE
        vbm, ok2 = _pdu_inner(vbmsghdr) if vbmsghdr else (None, False)
        if not ok2:
            return None
        vbhdr, ov = _walk_header(vbm, 0)           # first varbind SEQUENCE
        vb, ok3 = _pdu_inner(vbhdr) if vbhdr else (None, False)
        if not ok3:
            return None
        oid, ow = _walk_tag(vb, 0, 0x06)
        if oid is None:
            return None
        val, _ = _walk_any(vb, ow)
        return (True, es, oid, val)
    except Exception:
        return None


def _peek_len(data, off):
    if off + 2 > len(data):
        return None, off
    ln = data[off + 1]
    n = 0
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[off + 2:off + 2 + n], "big")
    return ln, n


def _walk_header(data, off):
    ln, n = _peek_len(data, off)
    if ln is None:
        return None, off
    end = off + 2 + n + ln
    return data[off:end], end


def _walk_tag(data, off, want):
    ln, n = _peek_len(data, off)
    if ln is None:
        return None, off
    tag, payload = data[off], data[off + 2 + n:off + 2 + n + ln]
    return (payload if tag == want else None), off + 2 + n + ln


def _walk_any(data, off):
    ln, n = _peek_len(data, off)
    if ln is None:
        return None, off
    return data[off + 2 + n:off + 2 + n + ln], off + 2 + n + ln


def _udp_get(host, community, suffix, timeout=1.5, port=161):
    req = snmp_get(community, suffix)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(req, (host, port))
        raw, _ = s.recvfrom(4096)
        parsed = _parse_get_response(raw)
        if not parsed or not parsed[0]:
            return None
        _ok, err, oid, val = parsed
        if err not in (0, None):
            return None
        txt = "".join(chr(c) for c in val if 32 <= c < 127).strip()
        name = SUFFICES.get(oid, "oid:%s" % oid.hex())
        return name, txt or (val.hex() if val else ""), oid
    except Exception:
        return None
    finally:
        s.close()


def _device_hint(descr):
    import re
    m = re.search(r"(Linux|Windows|Cisco IOS|Cisco|VMware|ESXi|Juniper"
                  r"|FreeBSD|OpenBSD|MikroTik|Ubiquiti|UBNT|Synology"
                  r"|NAS|FortiGate|Palo Alto|Check Point|D-Link|Netgear"
                  r"|TP-Link|router|switch)[^\r\n]{0,70}", descr)
    return m.group(0).strip() if m else ""


def run(engine):
    t = engine.target
    host = t.scan_host()
    if 161 not in {int(x) for x in engine.state.get("udp_open", [])}:
        engine.db.add_event(t.display, "network.snmp", "no 161/udp response")
        return
    try:
        cfg = load_json("intel/community_strings.json")
        words = (cfg.get("wordlist") or cfg.get("default") or ["public"])
    except Exception:
        words = ["public", "private"]
    hit = []
    for c in words[:MAX_COMMUNITIES]:
        r = _udp_get(host, c, b"\x2b\x06\x01\x02\x01\x01\x01\x00")
        if r:
            hit.append((c, r))
            break
    if not hit:
        for c in words[1:MAX_COMMUNITIES]:
            r = _udp_get(host, c, b"\x2b\x06\x01\x02\x01\x01\x01\x00")
            if r:
                hit.append((c, r))
                break
    if not hit:
        engine.db.add_event(t.display, "network.snmp",
                            "no SNMP community accepted on 161/udp")
        return
    community, (name, descr, _oid) = hit[0]
    extra = []
    for suffix in (b"\x2b\x06\x01\x02\x01\x01\x05\x00",
                   b"\x2b\x06\x01\x02\x01\x01\x03\x00"):
        r = _udp_get(host, community, suffix)
        if r and r[1]:
            extra.append("%s: %s" % (r[0], r[1][:80]))
    hint = _device_hint(descr)
    sev = "medium"
    if community.lower() in ("public", "private"):
        sev = "high"
    detail = "SNMPv1 read access accepted with community %r (sysDescr: %s)." \
             % (community, descr[:160])
    if extra:
        detail += "\n" + "\n".join(extra)
    engine.db.add_finding(Finding(
        t.display, "network.snmp", "exposure", sev,
        "SNMP community %r accepted (%s)" % (community,
                                             hint or "read-only access"),
        detail=detail,
        evidence="GET %s.%s" % (community, name),
        remediation="Disable SNMP or restrict communities to RFC 3826/SNMPv3 "
                    "authPriv; change defaults immediately.",
        confidence="firm"))
    engine.state["snmp"] = {"community": community,
                            "sysdescr": descr[:300] or None}
    engine.log.finding("[snmp] %s/161 community=%r %s" %
                       (host, community, hint))


if __name__ == "__main__":
    # standalone self-check: BER encode a GET and parse a canned response
    req = snmp_get(b"public", b"\x2b\x06\x01\x02\x01\x01\x01\x00")
    assert req.startswith(b"\x30") and b"\x04\x06public" in req, "bad GET"
    resp = (b"\x30\x1c\x02\x01\x00\x04\x06public\xa2\x15\x02\x01\x0f"
            b"\x02\x01\x00\x02\x01\x00\x30\x0a\x30\x08\x06\x08"
            b"\x2b\x06\x01\x02\x01\x01\x01\x00\x04\x00")
    parsed = _parse_get_response(resp)
    assert parsed and parsed[0] and parsed[1] == 0, parsed
    print("snmp_probe self-check OK:", parsed)
    print("raw GET:", req.hex())