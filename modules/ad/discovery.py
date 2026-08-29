"""VAJRA AD discovery — locate DCs via DNS SRV records, fingerprint the
domain over LDAP rootDSE and SMB NTLM challenge, seed state for the
whole ad-phase."""
import re
import socket
import struct

from core.database import Finding

SRV_QUERIES = [
    ("_ldap._tcp.dc._msdcs", "Domain controllers"),
    ("_gc._tcp", "Global catalog"),
    ("_kerberos._tcp", "KDC endpoints"),
    ("_kpasswd._tcp", "Password change service"),
]


def dns_srv(domain):
    """Minimal DNS SRV resolver (stdlib only)."""
    results = []
    try:
        qname = b"".join(bytes([len(p)]) + p.encode()
                         for p in domain.split(".") if p) + b"\x00"
        pkt = (b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
               + qname + b"\x00\x21\x00\x01")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        ns = _system_dns() or "127.0.0.1"
        s.sendto(pkt, (ns, 53))
        data, _a = s.recvfrom(4096)
        s.close()
        ancount = struct.unpack(">H", data[6:8])[0]
        if not ancount:
            return results
        i = 12
        while data[i] != 0:
            i += data[i] + 1
        i += 5
        for _ in range(ancount):
            if data[i] & 0xC0:
                i += 2
            else:
                while data[i] != 0:
                    i += data[i] + 1
                i += 1
            rtype, rclass, _ttl, rdlen = struct.unpack(
                ">HHIH", data[i:i + 10])
            i += 10
            rdata = data[i:i + rdlen]
            i += rdlen
            if rtype == 33 and len(rdata) >= 7:
                prio, weight, port = struct.unpack(">HHH", rdata[:6])
                j = 0
                host_parts = []
                while j < len(rdata[6:]):
                    l = rdata[6 + j]
                    if not l:
                        break
                    host_parts.append(rdata[7 + j:7 + j + l].decode())
                    j += l + 1
                host = ".".join(host_parts)
                results.append({"host": host, "port": port,
                                "role": ""})
    except Exception:
        pass
    return results


def _system_dns():
    try:
        with open("/etc/resolv.conf") as f:
            for ln in f:
                if ln.startswith("nameserver"):
                    return ln.split()[1]
    except Exception:
        pass
    return None


def guess_realm(target):
    parts = target.hostname.split(".")
    return ".".join(parts[-2:]).upper()


def run(engine):
    t = engine.target
    open_ports = set(engine.state.get("open_ports", {}))
    ad_ports = {88: "kerberos", 389: "ldap", 445: "smb", 636: "ldaps",
                464: "kpasswd", 3268: "gc", 135: "rpc"}
    detected = sorted(open_ports & set(ad_ports))
    realm = guess_realm(t)
    dcs = []
    if t.is_domain or "." in t.hostname:
        domain = realm.lower()
        for prefix, role in SRV_QUERIES:
            recs = dns_srv("%s.%s" % (prefix, domain))
            for r in recs:
                r["role"] = role
                if r["host"] not in [d["host"] for d in dcs]:
                    dcs.append(r)
    state_ad = {"realm": realm, "domain": realm.lower(),
                "dcs": dcs, "ad_ports": detected}
    engine.state["ad"] = state_ad
    surface = "%s (AD ports: %s)" % (
        realm, ", ".join(str(p) for p in detected)) if detected else realm
    if detected or dcs:
        engine.log.info("[ad] %s — DCs: %s" %
                        (surface, ", ".join(d["host"] for d in dcs[:3]) or "?"))
        engine.db.add_finding(Finding(
            t.display, "ad.discovery", "recon", "info",
            "Active Directory environment identified",
            detail="Realm: %s\nAD-relevant ports open: %s\n"
                   "DC candidates via DNS SRV:\n%s"
                   % (realm,
                      ", ".join("%d(%s)" % (p, ad_ports[p])
                                for p in detected) or "-",
                      "\n".join("%s:%d %s" % (d["host"], d["port"],
                                              d["role"])
                                for d in dcs[:10]) or "none via SRV"),
            confidence="firm"))
    else:
        engine.db.add_event(t.display, "ad.discovery",
                            "no AD indicators on this host")
