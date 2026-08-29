#!/usr/bin/env python3
"""rawhttp — craft raw HTTP requests (Host override, smuggling-style tests,
pipelining) against a host:debugging aid.

usage:  rawhttp.py -t host -P 80 -m GET /admin -H 'Host: evil.com'
        rawhttp.py -t host -P 443 --tls -m POST /login -b 'user=x'
        rawhttp.py -t host -P 80 --raw 'GET / HTTP/1.1...'
"""
import argparse
import base64
import socket
import ssl
import sys
import time

try:
    from _core import c, ok, err, hr
except ImportError:
    from tools._core import c, ok, err, hr


def _connect_hop(spec):
    ph, _, pp = spec.partition(":")
    return {"type": "http", "host": ph, "port": int(pp or 8080)}


def main():
    ap = argparse.ArgumentParser(prog="rawhttp")
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("-P", "--port", type=int, default=80)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("-m", "--method", default="GET")
    ap.add_argument("path", nargs="?", default="/")
    ap.add_argument("-H", "--header", action="append", default=[])
    ap.add_argument("-b", "--body")
    ap.add_argument("--raw", help="full request line block (overrides -m/path)")
    ap.add_argument("--socks5", default=None,
                    help="route the TCP connect through a SOCKS5 proxy "
                         "(host:port)")
    ap.add_argument("--connect-proxy", default=None,
                    help="route the TCP connect through an HTTP CONNECT "
                         "proxy (host:port)")
    ap.add_argument("--timeout", type=float, default=6)
    ap.add_argument("--host-override")
    ap.add_argument("--http10", action="store_true", help="force HTTP/1.0")
    args = ap.parse_args()

    if args.raw:
        req = args.raw.encode("latin1")
        if not req.endswith(b"\r\n\r\n") and not req.endswith(b"\n\n"):
            req += b"\r\n\r\n"
    else:
        body = (args.body or "").encode("latin1")
        version = "HTTP/1.0" if args.http10 else "HTTP/1.1"
        host = args.host_override or args.target
        lines = ["%s %s %s" % (args.method, args.path or "/", version),
                 "Host: %s:%d" % (host, args.port)]
        for h in args.header:
            lines.append(h)
        lines.append("Connection: close")
        if body:
            lines.append("Content-Length: %d" % len(body))
        req = ("\r\n".join(lines) + "\r\n\r\n").encode("latin1") + body

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    try:
        t0 = time.time()
        if args.socks5:
            try:
                from core.http_client import socks5_connect
                s = socks5_connect(args.socks5, args.target, args.port,
                                   timeout=args.timeout)
            except Exception as e:
                err("socks5 connect failed: %r" % e)
                return 1
        elif args.connect_proxy:
            try:
                from core.tcp_pivot import connect_via_chain
                s = connect_via_chain(
                    args.target, args.port,
                    [_connect_hop(args.connect_proxy)])
                s.settimeout(args.timeout)
            except Exception as e:
                err("CONNECT proxy failed: %r" % e)
                return 1
        else:
            s.connect((args.target, args.port))
        if args.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=args.target)
        s.sendall(req)
        resp = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
    except Exception as e:
        err("transport error: %r" % e)
        s.close()
        return 1
    s.close()
    hr()
    head, _, bodyb = resp.partition(b"\r\n\r\n")
    if resp.startswith(b"HTTP/"):
        status = head.split(b"\r\n")[0].decode("latin1", "replace")
        print(c("%s  (%.0fms, %d bytes)" % (status,
                                            (time.time() - t0) * 1000,
                                            len(resp)), bold=True))
        for line in head.split(b"\r\n")[1:]:
            print(c("  %s" % line.decode("latin1", "replace"), dim=True))
        print("  ---")
        print(bodyb.decode("latin1", "replace")[:4000])
    elif not resp:
        err("no response")
        return 1
    else:
        print(resp.decode("latin1", "replace")[:2000])
    return 0


if __name__ == "__main__":
    sys.exit(main())