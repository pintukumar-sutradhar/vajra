#!/usr/bin/env python3
"""hashid — identify common password-hash formats from a single string.

usage:  hashid.py '$P$B123456...'     one hash
        hashid.py -f hashes.txt       read many
        hashid.py --brief              shortest match only
"""
import argparse
import re
import sys

CATALOG = [
    (re.compile(r"^\$2[aby]\$\d{2}\$[./0-9A-Za-z]{53}$"), ["bcrypt ($2a/$2b/$2y)"]),
    (re.compile(r"^\$2[xy]\$\d{2}\$[./0-9A-Za-z]{53}$"), ["bcrypt ($2x/$2y)"]),
    (re.compile(r"^\$6\$.{2,16}\$[./0-9A-Za-z]{86}$"), ["sha512crypt ($6)"]),
    (re.compile(r"^\$5\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}$"), ["sha256crypt ($5)"]),
    (re.compile(r"^\$1\$.{0,8}\$[./0-9A-Za-z]{22}$"), ["MD5 crypt ($1)"]),
    (re.compile(r"^\$apr1\$.{0,8}\$[./0-9A-Za-z]{22}$"), ["Apache MD5 ($apr1)"]),
    (re.compile(r"^\$P\$.{31}$"), ["phpass (WordPress)"]),
    (re.compile(r"^\$H\$.{31}$"), ["phpass (phpBB)"]),
    (re.compile(r"^sha1\$[A-Za-z0-9]{5}\$[./0-9A-Za-z]{28}$"), ["Django SHA-1"]),
    (re.compile(r"^sha256\$[A-Za-z0-9]{5}\$[./0-9A-Za-z]{43}$"), ["Django SHA-256"]),
    (re.compile(r"^pbkdf2_sha256\$\d+\$[A-Za-z0-9=]+\$[A-Za-z0-9+/=]{44}$"),
     ["Django PBKDF2-SHA256"]),
    (re.compile(r"^\$argon2(id?|i)\$.*$"), ["Argon2 (id/i)"]),
    (re.compile(r"^\{SSHA\}[A-Za-z0-9+/=]{28,}$"), ["OpenLDAP SSHA"]),
    (re.compile(r"^\{SHA\}[A-Za-z0-9+/=]{28}$"), ["OpenLDAP SHA1"]),
    (re.compile(r"^\{MD5\}[A-Za-z0-9+/=]{24}$"), ["OpenLDAP MD5"]),
    (re.compile(r"^[a-f0-9]{32}$", re.I), ["MD5", "NTLM (if 32 hex)"]),
    (re.compile(r"^[a-f0-9]{40}$", re.I), ["SHA1", "MySQL5 (if user 16b, else 40)"]),
    (re.compile(r"^[a-f0-9]{56}$", re.I), ["SHA224"]),
    (re.compile(r"^[a-f0-9]{64}$", re.I), ["SHA256", "RIPEMD-160? (no)", "bcrypt-pbkdf?"]),
    (re.compile(r"^[a-f0-9]{96}$", re.I), ["SHA384"]),
    (re.compile(r"^[a-f0-9]{128}$", re.I), ["SHA512"]),
    (re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$"), ["NTLM (user-salt)"]),
    (re.compile(r"^\*[0-9A-F]{40}$"), ["MySQL *41"]),
    (re.compile(r"^[0-9a-fA-F]{16}$"), ["DES crypt hex? （or MySQL pre-4.1)"]),
    (re.compile(r"^[./0-9A-Za-z]{13}$"), ["DES crypt (13 salt+crypt chars)"]),
    (re.compile(r"^[./0-9A-Za-z]{13,24}$"), ["Extended DES (`_...`) or BSDi"]),
]


def identify(hashstr):
    matches = []
    for rx, names in CATALOG:
        if rx.match(hashstr.strip()):
            matches.extend(names)
    if not matches:
        matches.append("unknown / unsupported format")
    return matches


def main():
    ap = argparse.ArgumentParser(prog="hashid")
    ap.add_argument("hash", nargs="?", help="single hash string")
    ap.add_argument("-f", "--file")
    ap.add_argument("-b", "--brief", action="store_true")
    args = ap.parse_args()

    entries = []
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            entries = [ln.strip() for ln in f if ln.strip()]
    elif args.hash:
        entries = [args.hash]
    else:
        ap.print_help()
        return 1
    for h in entries:
        res = identify(h)
        shown = res if not args.brief else [res[0]]
        print("  %-60s -> %s" % (h[:60], "; ".join(shown)))
    return 0


if __name__ == "__main__":
    sys.exit(main())