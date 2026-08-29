"""VAJRA deep protocol probes — active handshake parsing for non-HTTP
services discovered across the full 65535-port sweep."""
import socket
import struct

from core.intelligence import guess_service


def _tcp(host, port, payload=None, wait=3.0, recv_len=1024):
    try:
        s = socket.create_connection((host, port), timeout=min(wait, 5.0))
        s.settimeout(wait)
        if payload:
            s.sendall(payload)
        data = b""
        if payload is not None or True:
            try:
                while len(data) < recv_len:
                    chunk = s.recv(recv_len - len(data))
                    if not chunk:
                        break
                    data += chunk
            except Exception:
                pass
        s.close()
        return data
    except Exception:
        return b""


def probe_mysql(host, port):
    raw = _tcp(host, port)
    if len(raw) > 30 and raw[0] != 0xFF and (raw[4:10] or b"").isascii():
        ver = raw[5:].split(b"\x00")[0]
        try:
            return "MySQL greeting version=%s" % ver.decode("utf-8", "replace")
        except Exception:
            pass
    return None


def probe_vnc(host, port):
    raw = _tcp(host, port)
    if raw.startswith(b"RFB "):
        ver = raw[:12].decode("utf-8", "replace").strip()
        sec = _tcp(host, port, raw[:12], wait=2.0)
        authtypes = []
        if sec:
            n = sec[0] if isinstance(sec[0], int) else 0
            types = [b for b in sec[1:1 + max(0, min(n, 8))]]
            names = {0: "Invalid", 1: "None", 2: "VNC-auth"}
            authtypes = [names.get(t, str(t)) for t in types]
        extra = ""
        if authtypes == ["None"] or (authtypes and authtypes[0] == "None"):
            extra = " [NO AUTHENTICATION]"
        return "%s security=%s%s" % (ver, ",".join(authtypes) or "?", extra)
    return None


def probe_memcached(host, port):
    raw = _tcp(host, port, b"version\r\nstats settings\r\n", wait=2.5)
    txt = raw.decode("utf-8", "replace")
    if "VERSION" in txt:
        lines = txt.splitlines()
        ver = next((l for l in lines if l.startswith("VERSION")), "")
        stats = sum(1 for l in lines if l.startswith("STAT"))
        return "%s stat_lines=%d%s" % (ver, stats,
                                       "" if stats else " [no stats exposed]")
    return None


def probe_postgres(host, port):
    sslreq = struct.pack("!ii", 8, 80877103)
    r = _tcp(host, port, sslreq, wait=2.5)
    if r[:1] in (b"S", b"N"):
        mode = {"S": "SSL supported", "N": "SSL rejected"}.get(r[:1].decode(), "?")
        return "PostgreSQL protocol (%s)" % mode
    return None


def probe_mssql(host, port):
    prelogin = bytes.fromhex(
        "1201000800010000000000") + bytes.fromhex(
        "000001000000") + bytes.fromhex(
        "0102010000000000000000000000")
    packet = bytes([len(prelogin) + 8 >> 8 & 0xFF, len(prelogin) + 8 & 0xFF,
                    0x01, 0x00]) + prelogin
    raw = _tcp(host, port, packet, wait=3.0)
    if raw and raw[0] == 0x04:
        idx = raw.find(bytes([0x00, 0x15, 0x00, 0x06]))
        if idx >= 0 and idx + 10 <= len(raw):
            v_hi = int.from_bytes(raw[idx + 4:idx + 6], "big")
            v_mid = int.from_bytes(raw[idx + 6:idx + 8], "big")
            v_lo = int.from_bytes(raw[idx + 8:idx + 10], "big")
            return "MSSQL server version %d.%d.%d (prelogin)" % (v_hi, v_mid, v_lo)
        return "TDS prelogin response (%d bytes)" % len(raw)
    return None


def probe_mongo(host, port):
    doc = struct.pack("<i", 19) + b"\x10ismaster\x00\x01\x00\x00\x00\x00"
    coll = b"admin.$cmd\x00"
    body = struct.pack("<i", 2004) + b"\x00" * 4 + coll + \
        struct.pack("<i", 0) + struct.pack("<i", -1) + doc
    total = 16 + len(body) - 4
    pkt = struct.pack("<i", 16 + len(body)) + b"\x01\x02\x03\x04" + \
        b"\x00" * 4 + body[4:]
    raw = _tcp(host, port, pkt, wait=3.0)
    txt = raw.decode("utf-8", "replace")
    import re
    m = re.search(r"version.{0,4}?([\d.]+)", txt)
    if "ismaster" in txt or m:
        return "MongoDB isMaster reply version=%s" % (
            m.group(1) if m else "unknown")
    return None


def probe_smb(host, port):
    nbss = struct.pack(">I", 44)[1:] + b"\x00"
    smb2 = (
        b"\xfeSMB" + b"\x40\x00" + b"\x00\x00" +
        b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" +
        b"\x1f\x00\x00\x00\x00\x00\x00\x00" +
        b"\x00\x00\x00\x00\x00\x00\x00\x00" +
        b"\xff\xfe\x00\x00" + b"\x00\x00\x00\x00" +
        b"\x18\x00" + b"\x00\x00" +
        b"\x00\x00\x00\x00"
    )
    pkt = nbss + struct.pack(">H", len(smb2)) + b"\x00\x00" + smb2
    raw = _tcp(host, port, pkt, wait=3.0)
    if raw[:4] == b"\xfeSMB":
        dialect = raw[4 + 4:4 + 6]
        ver = "%d.%d" % (dialect[0] // 16, dialect[0] % 16) if dialect else "?"
        return "SMB%s negotiation accepted" % ("2.x" if True else "")
    if raw and len(raw) > 36 and raw[4:8] == b"\xffSMB":
        return "SMB1 negotiate response"
    return None


def probe_rdp(host, port):
    x224 = bytes.fromhex(
        "030000130ee000000000000100080003000000")
    raw = _tcp(host, port, x224, wait=3.0)
    if raw[:3] == b"\x03\x00\x00":
        proto = int.from_bytes(raw[11:15], "little") if len(raw) >= 15 else 0
        modes = {0: "Standard RDP", 1: "TLS",
                 2: "CredSSP/NLA", 3: "TLS+CredSSP"}
        return "RDP connection confirmed — security=%s" % modes.get(proto, str(proto))
    return None


def probe_redis_extra(host, port):
    raw = _tcp(host, port, b"*1\r\n$4\r\nINFO\r\n", wait=2.5)
    txt = raw.decode("utf-8", "replace")
    if txt.startswith("$"):
        import re
        vm = re.search(r"redis_version:([\d.]+)", txt)
        mm = re.search(r"os:(\w+)", txt)
        return "Redis INFO leak version=%s os=%s%s" % (
            vm.group(1) if vm else "?", mm.group(1) if mm else "?",
            " [UNAUTHENTICATED]" if "requirepass" not in txt else "")
    return None


def probe_rpcbind(host, port):
    call = bytes.fromhex(
        "00000280000000020000000000000000000000000000000200000000")
    raw = _tcp(host, port, call, wait=2.5)
    if len(raw) >= 24:
        progs = (len(raw) - 24) // 20
        return "RPC portmap responded (~%d program entries)" % max(1, progs)
    return None


PROBES = {
    3306: probe_mysql,
    5900: probe_vnc,
    11211: probe_memcached,
    5432: probe_postgres,
    1433: probe_mssql,
    27017: probe_mongo,
    445: probe_smb,
    3389: probe_rdp,
    6379: probe_redis_extra,
    111: probe_rpcbind,
}


def run_deep_probes(host, services):
    """Enrich service dicts with deep-probe intel; returns list of strings."""
    notes = []
    for svc in services:
        port = svc["port"]
        fn = PROBES.get(port)
        if not fn:
            continue
        try:
            note = fn(host)
        except Exception:
            note = None
        if note:
            svc.setdefault("deep_probe", note)
            notes.append("%d/%s -> %s" % (port, guess_service(port) or "?", note))
    return notes
