"""VAJRA SMB / NFS share enumeration — read-only listing of what a host
exposes to anonymous or guest users.

Uses external read-only tooling when present (consistent with the AD modules):
  - nmap --script smb-enum-shares,smb-protocols       (read-only)
  - smbclient -L //host -N / -U guest                 (read-only)
  - showmount -e host                                  (NFS read-only)
When no SMB tooling is installed, a pure-stdlib SMBv1 walker attempts the
same anonymous listing through the LANMAN RAP NetShareEnum transaction
(\\PIPE\\LANMAN, level 1) — the same call smbclient makes."""
import shutil
import socket
import struct
import subprocess

from core.database import Finding
from core.utils import which_tool

SMB_PORTS = (139, 445)
NFS_PORTS = (2049,)

try:
    from modules.ad.smb_recon import _smb1_pkt, _smb1_hdr, _smb1_negotiate, \
        _parse_negotiate
    HAVE_BRICKS = True
except Exception:
    HAVE_BRICKS = False


def _run(args, timeout=25):
    try:
        out = subprocess.run(args, capture_output=True, text=True,
                             timeout=timeout)
        return (out.stdout + "\n" + out.stderr).strip()
    except Exception:
        return ""


def _smb_enum(engine, host):
    if which_tool("nmap"):
        out = _run(["nmap", "-Pn", "-n", "-p", "445,139", "--script",
                    "smb-enum-shares,smb-protocols,smb-security-mode",
                    host])
        if out and "SHARES" in out or out and "| smb-enum-shares" in out:
            return ("nmap", out)
    for cli in (which_tool("smbclient"),):
        if cli:
            for cred in (["-N"], ["-U", "guest%"]):
                out = _run([cli, "-L", "//%s" % host, "-g"] + cred)
                if out and ("Disk" in out or "IPC" in out or
                            "IPC$" in out):
                    return ("smbclient", out)
    return (None, "")


def _nfs_enum(engine, host):
    sm = which_tool("showmount")
    if not sm:
        return (None, "")
    out = _run([sm, "-e", host])
    if out and ("/" in out or "Export list" in out):
        return ("showmount", out)
    return (None, "")


# ---- native SMBv1 anonymous walker (fallback when no SMB tooling) --------
# Session:  NEGOTIATE -> SESSION_SETUP_ANDX (anonymous) -> TREE_CONNECT_ANDX
#           IPC$ -> TRANSACTION \PIPE\LANMAN with a RAP NetShareEnum level-1
#           request (opcode 0x0000, DCANON "WrLeh", return "B13BWz").

def _s1_session_setup():
    if not HAVE_BRICKS:
        return None
    words = (b"\xff\x00"            # andx cmd + reserved
             + struct.pack("<H", 0x0000)   # andx offset
             + struct.pack("<H", 0xFFFF)   # max buffer
             + struct.pack("<H", 0x0002)   # max mpx
             + struct.pack("<H", 0x0000)   # vc number
             + b"\x00" * 4                  # session key
             + struct.pack("<H", 0x0000)   # security blob len (anon)
             + struct.pack("<H", 0x0000)   # reserved
             + b"\x00" * 4)                 # capabilities
    body = _smb1_hdr(0x73, mid=0x0001) + bytes([len(words) // 2]) + \
        words + struct.pack("<H", 0)
    return _smb1_pkt(body)


def _s1_tree_connect(host, uid):
    path = ("\\\\%s\\IPC$\x00" % host).encode("ascii")
    words = (b"\xff\x00" + struct.pack("<H", 0x0000)
             + struct.pack("<H", 0x0000) + struct.pack("<H", 0x0000))
    body = _smb1_hdr(0x75, mid=0x0002, uid=uid) + \
        bytes([len(words) // 2]) + words + \
        struct.pack("<H", len(path)) + b"" + path
    return _smb1_pkt(body)


def _s1_trans_share_enum(port=445):
    """Build SMB_COM_TRANSACTION carrying the RAP NetShareEnum level-1 call."""
    name = b"\\PIPE\\LANMAN\x00"
    params = (struct.pack("<H", 0x0000) + b"WrLeh\x00" + b"B13BWz\x00" +
              struct.pack("<H", 0x0001) + struct.pack("<H", 0x1000))
    words = (struct.pack("<H", 0) + struct.pack("<H", 0)
             + struct.pack("<H", 8) + struct.pack("<H", 0x1000)
             + b"\x00\x00"                  # max_setup + reserved
             + struct.pack("<H", 0)         # flags
             + struct.pack("<I", 5000)      # timeout
             + struct.pack("<H", 0)         # reserved
             + struct.pack("<H", len(params))
             + struct.pack("<H", 76)        # param offset (hdr+wc+words+bcc+name)
             + struct.pack("<H", 0)         # data count (param-carried)
             + struct.pack("<H", 95)        # data offset
             + b"\x00\x00")                 # setup_count + reserved
    body = _smb1_hdr(0x25, mid=0x0003) + bytes([len(words) // 2]) + words + \
        struct.pack("<H", len(name) + len(params)) + name + params
    return _smb1_pkt(body)


def _s1_recv(s, buf, timeout=6):
    s.settimeout(timeout)
    try:
        while len(buf) < 4:
            d = s.recv(4 - len(buf))
            if not d:
                return None
            buf += d
        mlen = (buf[1] << 16 | buf[2] << 8 | buf[3]) + 4
        while len(buf) < mlen:
            d = s.recv(mlen - len(buf))
            if not d:
                return None
            buf += d
        frame, buf = buf[:mlen], buf[mlen:]
        return frame, buf
    except socket.timeout:
        return None


def _s1_status(frame):
    if not frame or frame[4:8] != b"\xffSMB":
        return None
    return int.from_bytes(frame[9:13], "little")


def _native_share_enum(host, port=445):
    """Anonymous SMBv1 NetShareEnum. Returns (shares, detail) or (None, err)."""
    if not HAVE_BRICKS:
        return None, "SMB1 bricks unavailable (modules.ad.smb_recon failed)"
    try:
        s = socket.create_connection((host, port), timeout=6)
    except Exception as e:
        return None, "connect failed: %s" % e
    try:
        buf = b""
        s.sendall(_smb1_negotiate())
        r = _s1_recv(s, buf)
        if not r or not _parse_negotiate(r[0]).get("saw_smb"):
            return None, "no SMBv1 negotiate reply"
        buf = r[1]
        s.sendall(_s1_session_setup())
        r = _s1_recv(s, buf)
        if not r:
            return None, "no session-setup reply"
        frame, buf = r
        uid = int.from_bytes(frame[32:34], "little")
        if _s1_status(frame) not in (0, None):
            return None, "anonymous session rejected"
        s.sendall(_s1_tree_connect(host, uid))
        r = _s1_recv(s, buf)
        if not r:
            return None, "no tree-connect reply"
        frame, buf = r
        tid = int.from_bytes(frame[28:30], "little")
        if _s1_status(frame) not in (0, None):
            return None, "IPC$ tree-connect rejected"
        s.sendall(_s1_trans_share_enum())
        r = _s1_recv(s, buf)
        if not r:
            return None, "no transaction reply"
        frame, buf = r
        if _s1_status(frame) not in (0, None):
            return None, "transaction denied"
        return _s1_parse_response(frame), None
    except Exception as e:
        return None, "walker error: %s" % e
    finally:
        try:
            s.close()
        except Exception:
            pass


def _s1_parse_response(frame):
    """Parse a TRANSACTION response body: params (rc/converter/counts) and
    the RAP ShareInfo1 array (20-byte strides). Tolerant on remark offsets."""
    if len(frame) < 36:
        return []
    wc = frame[36]
    if wc < 10:
        return []
    words = frame[37:37 + 20]
    data_count = int.from_bytes(words[14:16], "little")
    data_off = int.from_bytes(words[16:18], "little")
    param_off = int.from_bytes(words[10:12], "little")
    if data_count <= 0 or data_off <= 0:
        return []
    base = 4  # nbss
    params = frame[base + param_off:base + param_off + 8]
    if len(params) < 8:
        return []
    rc = int.from_bytes(params[0:2], "little")
    if rc not in (0, None):
        return []
    entries = int.from_bytes(params[4:6], "little")
    data = frame[base + data_off:base + data_off + data_count]
    if not data:
        return []
    if len(data) % 20 and entries * 20 > len(data):
        entries = len(data) // 20
    shares = []
    for i in range(min(entries, len(data) // 20)):
        rec = data[i * 20:i * 20 + 20]
        name = rec[0:13].split(b"\x00")[0].decode("latin1", "replace")
        stype = int.from_bytes(rec[14:16], "little")
        if not name or not all(32 <= ord(ch) < 127 and ch not in "\x7f"
                               for ch in name):
            break
        kind = {0x0000: "disk", 0x0001: "print", 0x0002: "comm",
                0x0003: "ipc"}.get(stype & 0xFFFF, "other")
        shares.append("%s (%s)" % (name, kind))
    # any printable name scan fallback if records were unaligned
    if not shares and entries <= 0:
        return shares
    return shares


def _try_native(engine, host):
    """Native SMBv1 anonymous RAP share walk. Returns True when the host
    responded (even if only IPC$); the caller records findings itself."""
    port = 445 if 445 in {s["port"] for s in engine.state.get("services", [])} \
        else 139
    shares, err = _native_share_enum(host, port)
    if err:
        engine.db.add_event(engine.target.display, "network.shares",
                            "native SMBv1 walk: %s" % err)
        return False
    if shares:
        plain = [sh.split(" (")[0] for sh in shares]
        engine.db.add_finding(Finding(
            engine.target.display, "network.shares", "exposure", "medium",
            "SMB shares readable anonymously (native SMBv1 RAP walk)",
            detail="NetShareEnum level-1 over \\\\PIPE\\\\LANMAN disclosed "
                   "%d share(s) without credentials." % len(shares),
            evidence="\n".join(shares[:40]),
            remediation="Disable anonymous/guest SMB access; enforce "
                        "least-privilege ACLs; consider SMBv1 off.",
            confidence="firm"))
        engine.state["smb_shares"] = plain[:60]
        engine.log.finding("[shares] SMB(native): %s" % ", ".join(plain[:8]))
    return True


def run(engine):
    t = engine.target
    host = t.scan_host()
    services = {s["port"]: s for s in engine.state.get("services", [])}
    any_smb = any(p in services for p in SMB_PORTS)
    any_nfs = any(p in services for p in NFS_PORTS)
    if not any_smb and not any_nfs:
        engine.db.add_event(t.display, "network.shares",
                            "no SMB/NFS listener detected")
        return

    if any_smb:
        tool, out = _smb_enum(engine, host)
        if not tool:
            engine.log.info("[shares] no smb tooling — native SMBv1 fallback")
        if tool:
            lines = [l for l in out.splitlines() if l.strip()]
            paths = []
            writable = []
            for l in lines:
                if "Disk" in l:
                    parts = l.split()
                    share = next((p for p in parts if p.startswith("\\\\")
                                  or p.startswith("//")), parts[0] if parts
                                 else "")
                    paths.append(share)
                if any(k in l.lower() for k in ("rw,", "full access",
                                                "read-write")):
                    writable.append(l[:100])
            sev = "high" if writable else "medium"
            engine.db.add_finding(Finding(
                t.display, "network.shares", "exposure", sev,
                "SMB shares readable anonymously (%s)" % tool,
                detail="%d share(s) enumerated without credentials%s." % (
                    len(paths),
                    " — several appear writable" if writable else ""),
                evidence="\n".join((paths or lines)[:30]),
                remediation="Disable anonymous/guest SMB access; enforce "
                            "least-privilege ACLs; fire at NTLMv2.",
                confidence="firm" if paths else "possible"))
            engine.state["smb_shares"] = paths[:60]
            engine.log.finding("[shares] SMB: %s" % ", ".join(
                (paths or ["<unknown>"])[:6]))
        elif _try_native(engine, host):
            pass
        else:
            engine.db.add_event(
                t.display, "network.shares",
                "SMB anonymous share check inert — install nmap/samba-client "
                "or allow the native SMBv1 fallback (denied by host)")

    if any_nfs:
        tool, out = _nfs_enum(engine, host)
        if tool:
            exports = [l.strip() for l in out.splitlines()
                       if l.strip() and not l.startswith(("Export", "-------"))
                       and l.strip() != ""]
            risky = [e for e in exports
                     if any(k in e.lower() for k in ("no_root_squash",
                                                     "rw,"))]
            engine.db.add_finding(Finding(
                t.display, "network.shares", "exposure",
                "high" if risky else "medium",
                "NFS exports browsable (showmount -e)",
                detail="Export list revealed%s." % (
                    " — includes risky options (no_root_squash / world rw)"
                    if risky else ""),
                evidence="\n".join(exports[:40]),
                remediation="Export specific IPs; use root_squash; prefer "
                            "Kerberized NFS.",
                confidence="firm" if exports else "possible"))
            engine.state["nfs_exports"] = exports[:40]
            engine.log.finding("[shares] NFS: %d export(s)" % len(exports))
        else:
            engine.db.add_event(t.display, "network.shares",
                                "NFS export check skipped — install "
                                "nfs-common (showmount)")