#!/usr/bin/env python3
"""dnsrecon — DNS enumeration: records, transfers, subdomain brute-force with
brute/wordlist, and a takeover signal check hint.

usage:  dnsrecon.py -t example.com
        dnsrecon.py -t example.com -w wordlists/subs_common.txt
        dnsrecon.py -t example.com -r 8.8.8.8
"""
import argparse
import re
import socket
import sys
import threading

try:
    from _core import c, ok, err, hr, data
except ImportError:
    from tools._core import c, ok, err, hr, data

RDATA_RE = re.compile(
    r"^[^\s]+\s+\d+\s+IN\s+([A-Z]+)\s+(.+)$")


def query(name, rtype, server=None, timeout=4):
    """Raw TCP DNS query (works even where dig is absent)."""
    import struct
    if not name.endswith("."):
        name += "."
    rid = 0x4A42
    hdr = struct.pack("!HHHHHH", rid, 0x0100, 1, 0, 0, 0)
    qn = b""
    for part in name.split("."):
        if not part:
            continue
        qn += bytes([len(part)]) + part.encode()
    qn += b"\x00"
    q = hdr + qn + struct.pack("!HH", rtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    ns = server or "8.8.8.8"
    try:
        s.connect((ns, 53))
        s.sendall(struct.pack("!H", len(q)) + q)
        ln = struct.unpack("!H", s.recv(2))[0]
        buf = b""
        while len(buf) < ln:
            c2 = s.recv(ln - len(buf))
            if not c2:
                break
            buf += c2
    except Exception:
        s.close()
        return []
    s.close()
    out = []
    try:
        # cheap name decompress for answer/extra sections
        idx = len(q)
        def rdn(off):
            labels, ptr = [], off
            while True:
                l = buf[ptr]
                if l & 0xC0:
                    ptr2 = int.from_bytes(buf[ptr:ptr + 2], "big") & 0x3FFF
                    ptr += 2
                    rl, ptr3 = ptr, ptr2
                    return ".".join(labels) + (("." + ".".join(
                        _walk(buf, ptr2))) if True else ""), ptr
                ptr += 1
                if l == 0:
                    return ".".join(labels), ptr
                labels.append(buf[ptr:ptr + l].decode("ascii",
                                                       "replace"))
                ptr += l
        def _walk(b, off):
            ls = []
            while True:
                l = b[off]
                if l & 0xC0:
                    off2 = int.from_bytes(b[off:off + 2], "big") & 0x3FFF
                    return ls + _walk(b, off2)
                off += 1
                if l == 0:
                    return ls
                ls.append(b[off:off + l].decode("ascii", "replace"))
                off += l
        while idx + 12 <= len(buf):
            name_s, idx2 = rdn(idx)
            if len(buf) < idx2 + 10:
                break
            rtype_, cls, ttl, rdln = struct.unpack(
                "!HHIH", buf[idx2:idx2 + 10])
            idx = idx2 + 10
            if idx + rdln > len(buf):
                break
            rdata = buf[idx:idx + rdln]
            idx += rdln
            if rtype_ in (1, 5, 2, 28, 16, 33, 15):
                if rtype_ == 1:
                    txt = socket.inet_ntoa(rdata)
                elif rtype_ == 28:
                    txt = socket.inet_ntop(socket.AF_INET6, rdata)
                elif rtype_ == 5 or rtype_ == 2:
                    labels = []
                    off = 0
                    while off < len(rdata):
                        l = rdata[off]
                        if l & 0xC0:
                            p2 = int.from_bytes(rdata[off:off + 2],
                                                "big") & 0x3FFF
                            labels.append(".".join(_walk(buf, p2)))
                            break
                        off += 1
                        if l == 0:
                            break
                        labels.append(rdata[off:off + l].decode("ascii",
                                                                "replace"))
                        off += l
                    txt = ".".join(labels)
                else:
                    txt = rdata.decode("ascii", "replace")
                out.append((rtype_, txt))
    except Exception:
        pass
    return out


TYPE_NAMES = {1: "A", 5: "CNAME", 2: "NS", 28: "AAAA", 16: "TXT",
              33: "SRV", 15: "MX"}


def main():
    ap = argparse.ArgumentParser(prog="dnsrecon")
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("-r", "--resolver", default="8.8.8.8")
    ap.add_argument("--threads", type=int, default=40)
    args = ap.parse_args()

    if args.wordlist:
        results, lock = [], threading.Lock()
        threads = []

        def brute(sub):
            hits = query(sub, 1, args.resolver)
            if hits:
                with lock:
                    results.append((sub, hits[0][1]))

        with open(args.wordlist, encoding="utf-8", errors="replace") as f:
            subs = [ln.strip() for ln in f if ln.strip()]
        hr()
        print(c("brute-forcing %d subdomains of %s" % (len(subs),
                                                       args.target), bold=True))
        batch = []
        for s in subs:
            th = threading.Thread(target=brute,
                                  args=(s + "." + args.target,), daemon=True)
            th.start()
            batch.append(th)
            if len(batch) >= args.threads:
                for t in batch:
                    t.join()
                batch = []
        for t in batch:
            t.join()
        if not results:
            err("no subdomains resolve")
        else:
            ok("%d subdomain(s) resolve" % len(results))
            for sub, ip in sorted(results):
                print("  %-46s %s" % (sub, ip))
        return 0

    hr()
    print(c("DNS record enumeration for %s (resolver %s)" %
            (args.target, args.resolver), bold=True))
    found = False
    for rtype, label in ((1, "A"), (2, "NS"), (15, "MX"), (16, "TXT"),
                         (5, "CNAME"), (28, "AAAA"), (33, "SRV")):
        rows = query(args.target, rtype, args.resolver)
        for _, val in rows:
            found = True
            print("  %-6s %s" % (c(label, bold=True), val))
    if not found:
        err("no records (target may not resolve, or empty zone)")
    return 0 if found else 2


if __name__ == "__main__":
    sys.exit(main())