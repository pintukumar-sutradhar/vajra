#!/usr/bin/env python3
"""pivot — chain-aware TCP pivot / SOCKS5 pivot server.

Operational modes:
  pivot.py --listen :1080 --upstream socks5://dmz:1080      local SOCKS5
       server that fans every CONNECT through the upstream chain.
  pivot.py --probe t:22 --upstream http://proxy:3128        verify a chain
       can reach t:22 (echoes "banner-ish" bytes or prints OK).
  pivot.py --tunnel --local :8080 --remote 10.0.1.5:445
       --upstream socks5://dmz:1080                        static local
       forward of a remote port through the chain.

Chain spec: comma-separated hops  socks5://host:port  http://host:port
            (http optional @user:pass), last hop reaches the target.
"""
import argparse
import socket
import sys

sys.path.insert(0, "/home/kali/Projects/Vajra")

try:
    from tools._core import c, ok, err, hr
    from core.tcp_pivot import (PivotProxy, connect_via_chain, parse_chain,
                                _splice)
except ImportError:
    from tools._core import c, ok, err, hr
    from core.tcp_pivot import (PivotProxy, connect_via_chain, parse_chain,
                                _splice)


def main():
    ap = argparse.ArgumentParser(prog="pivot")
    ap.add_argument("--listen", default=None,
                    help="host:port to serve a local SOCKS5 pivot on")
    ap.add_argument("--upstream", default=None,
                    help="proxy chain spec (socks5://h:p,http://h:p)")
    ap.add_argument("--probe", default=None,
                    help="target host:port to verify the chain against")
    ap.add_argument("--tunnel", action="store_true",
                    help="static port forward")
    ap.add_argument("--local", default=None, help="bind host:port (tunnel)")
    ap.add_argument("--remote", default=None, help="remote host:port (tunnel)")
    args = ap.parse_args()

    if not args.probe and not args.listen and not args.tunnel:
        ap.print_help()
        return 0
    chain = parse_chain(args.upstream) if args.upstream else None

    if args.probe:
        host, _, port = args.probe.partition(":")
        t0 = __import__("time").time()
        try:
            with connect_via_chain(host, int(port or 1), chain,
                                   timeout=8.0) as s:
                s.settimeout(4.0)
                s.sendall(b"\r\n")
                try:
                    banner = s.recv(128)
                except socket.timeout:
                    banner = b""
                el = (__import__("time").time() - t0) * 1000
                if banner:
                    ok("%s:%s reachable through chain (%.0fms): %s"
                       % (host, port, el, banner[:64]))
                else:
                    ok("%s:%s reachable through chain (%.0fms)" %
                       (host, port, el))
        except Exception as e:
            err("chain to %s:%s failed: %r" % (host, port, e))
            return 1
        return 0

    if args.tunnel:
        if not args.local or not args.remote:
            err("--tunnel needs --local and --remote")
            return 1
        lh, _, lp = args.local.partition(":")
        rh, _, rp = args.remote.partition(":")
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((lh or "127.0.0.1", int(lp)))
        srv.listen(8)
        ok("static tunnel %s -> %s:%s via chain" %
           (args.local, rh, rp))
        import threading
        while True:
            conn, _ = srv.accept()
            threading.Thread(
                target=lambda c: _forward_one(c, rh, int(rp), chain),
                daemon=True).start()

    if args.listen:
        lh, _, lp = args.listen.partition(":")
        px = PivotProxy(host=lh or "0.0.0.0", port=int(lp or 1080),
                        upstream=chain)
        px.daemon = True
        px.start()
        hr()
        ok("SOCKS5 pivot up on %s:%d%s" %
           (lh or "0.0.0.0", px.port or lp,
            ("  upstream[%d hop(s)]" % len(chain)) if chain else ""))
        if chain:
            print("  chain: %s" % ", ".join(
                "%s://%s:%d" % (h.get("type"), h.get("host"), h.get("port"))
                for h in chain))
        try:
            px.join()
        except KeyboardInterrupt:
            pass
        px.stop()
        return 0
    return 0


def _forward_one(conn, rhost, rport, chain):
    try:
        if chain:
            target = connect_via_chain(rhost, rport, chain)
        else:
            target = socket.create_connection((rhost, rport), timeout=8)
        _splice(conn, target)
    except Exception:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())