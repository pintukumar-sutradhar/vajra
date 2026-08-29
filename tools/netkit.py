#!/usr/bin/env python3
"""netkit — asynchronous TCP/UDP port scanner + banner grabber with an
intel-informed service/risk table.

usage:  netkit.py -t HOST|CIDR      scan top-1000
        netkit.py -t HOST -p 1-1024 -T 400
        netkit.py -t HOST -p 80,443 --banner -j
"""
import argparse
import socket
import sys
import threading
import time

try:
    from _core import c, ok, err, data, load_json
except ImportError:
    from tools._core import c, ok, err, data, load_json

PORTS_TOP = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
             995, 1723, 3306, 3389, 5900, 8000, 8080, 8443]
SERVICE_TABLE = load_json("intel/ports.json", {}).get("known_ports", {})


def expand(spec, cap=None):
    out = []
    for part in str(spec or "top").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if part == "top":
            out = list(PORTS_TOP)
            continue
        if part.isdigit():
            n = int(part)
            if 0 < n <= 65535:
                out.append(n)
        elif "-" in part:
            try:
                a, b = map(int, part.split("-", 1))
                out.extend(range(a, min(b, 65535) + 1))
            except Exception:
                pass
    uniq, seen = [], set()
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq if not cap else uniq[:cap]


def hosts_for(spec):
    import ipaddress
    if "/" in spec:
        return [str(ip) for ip in ipaddress.ip_network(
            spec, strict=False).hosts()]
    return [spec]


def probe(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((ip, port))
        if rc != 0:
            return None
        return port
    finally:
        s.close()


def grab(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(b"\r\n")
        b = b""
        try:
            b = s.recv(256)
        except Exception:
            pass
        txt = b.decode("utf-8", "replace").strip()[:120]
        return txt or "(no banner)"
    except Exception:
        return None
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(prog="netkit")
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("-p", "--ports", default="top")
    ap.add_argument("-T", "--threads", type=int, default=400)
    ap.add_argument("--timeout", type=float, default=0.6)
    ap.add_argument("-b", "--banner", action="store_true")
    ap.add_argument("-J", "--json", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    ports = expand(args.ports)
    lock = threading.Lock()
    found, threads = [], []

    def work(host, plist):
        def one(p):
            if probe(host, p, args.timeout) is not None:
                with lock:
                    found.append(p)

        batch = []
        for p in plist:
            th = threading.Thread(target=one, args=(p,), daemon=True)
            th.start()
            batch.append(th)
            if len(batch) >= args.threads:
                for t in batch:
                    t.join()
                batch = []
        for t in batch:
            t.join()

    t0 = time.time()
    for host in hosts_for(args.target):
        work(host, ports)
    found.sort()
    if args.json:
        import json
        print(json.dumps(
            {"target": args.target, "ports": found,
             "elapsed": round(time.time() - t0, 2)}))
        return 0
    print(c("open ports for %s (%d probed):" % (args.target, len(ports)),
            bold=True))
    if not found:
        err("none open")
        return 0
    for p in found:
        meta = SERVICE_TABLE.get(str(p), {})
        who = meta.get("service", "unknown")
        risk = meta.get("risk", "-")
        line = "  %-6d %-18s risk=%s" % (p, who, risk)
        if args.banner:
            bn = grab(args.target, p, args.timeout)
            line += "  %s" % (c(bn, color=None, dim=True) if bn else "(no banner)")
        print(line)
    ok("%s open, %.1fs" % (len(found), time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())