#!/usr/bin/env python3
"""depcheck — honest capability matrix for VAJRA modules.

setup.sh installs everything and symlinks `vajra` globally, so there is no
`pip install .`: this tool instead tells you, for THIS environment, which
optional Python deps / external binaries each module can actually use, and
which degrade gracefully to a stdlib fallback. Run before an engagement so a
module never silently under-delivers:

    python3 tools/depcheck.py
"""
import importlib.util
import shutil
import sys

PROBES = [
    # (feature, python_module_or_None, binary_or_None, enabled_by_default)
    ("Native async connect port scan", None, None, True),
    ("SYN scan (root+scapy)", "scapy", None, False),
    ("HTTP client (requests)", "requests", None, False),
    ("SSH credential loot (paramiko)", "paramiko", None, False),
    ("SOCKS5 pivot proxy", "requests", None, False),
    ("Sharp/remote stagers (openssl/torsocks)", None, "openssl", False),
    ("External port scan (masscan/nmap)", None, "nmap", False),
    ("External port scan raw (masscan)", None, "masscan", False),
    ("AD command channel (impacket family)", None, "impacket-psexec", False),
    ("Kerberoast / AS-REP (impacket GetUserSPNs)",
     None, "impacket-GetUserSPNs", False),
    ("ADCS ESC1-8 audit (certipy-ad)", None, "certipy", False),
    ("Cloud post-ex provider CLI (aws)", None, "aws", False),
    ("Cloud post-ex provider CLI (az)", None, "az", False),
    ("Cloud post-ex provider CLI (gcloud)", None, "gcloud", False),
    ("Reverse-session listener (nc/netcat/torsocks)", None, "nc", False),
    ("Local AI (ollama --ai)", "ollama", "ollama", False),
]

BIN_ALT = {
    "ip": None, "openssl": None, "nc": ("nc", "ncat", "netcat"),
    "impacket-psexec": ("impacket-psexec", "psexec.py"),
    "impacket-GetUserSPNs": ("impacket-GetUserSPNs", "GetUserSPNs.py"),
}


def _mod(name):
    return importlib.util.find_spec(name) is not None


def _bin(name):
    cands = BIN_ALT.get(name) or (name,)
    if isinstance(cands, str):
        cands = (cands,)
    return any(shutil.which(c) for c in cands)


def main():
    print("VAJRA dependency / capability matrix\n" + "-" * 58)
    mod_ok = bin_ok = 0
    for feature, mod, bin_, _default in PROBES:
        if mod:
            ok = _mod(mod)
            note = "python: %s" % mod if not ok else "python: installed"
        elif mod is None and bin_:
            ok = _bin(bin_)
            note = "binary: %s" % bin_ if not ok else "binary: present"
        else:
            ok, note = True, "stdlib"
        mod_ok += int(ok)
        flag = "[OK] " if ok else "[ --]"
        print(" %s %-54s %s" % (flag, feature + ":", note))
    print("-" * 58)
    print("%d/%d optional capabilities usable (others fall back to stdlib)"
          % (mod_ok, len(PROBES)))
    print("note: every module degrades gracefully — VAJRA runs on stdlib only;\n"
          "      these extras unlock the deeper intrusive passes.")


if __name__ == "__main__":
    sys.exit(main())
