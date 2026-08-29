"""Vajra - OS fingerprinting via ICMP TTL and banner heuristics."""
import subprocess
import shutil
import re

from core.database import Finding

BANNER_OS = [
    ("ubuntu", "Linux (Ubuntu)"), ("debian", "Linux (Debian)"),
    ("centos", "Linux (CentOS)"), ("almalinux", "Linux"),
    ("freebsd", "FreeBSD"), ("openbsd", "OpenBSD"),
    ("microsoft-iis", "Windows"), ("win32", "Windows"),
    ("microsoft httpapi", "Windows"), ("windows", "Windows"),
    ("darwin", "macOS"), ("cisco", "Cisco IOS"), ("fortigate", "FortiOS"),
]


def _ping_ttl(host):
    if not shutil.which("ping"):
        return None
    args = ["ping", "-c", "1", "-W", "2", host]
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=8).stdout
        m = re.search(r"ttl[=:]\s*(\d+)", out, re.I)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return None


def ttl_guess(ttl):
    if ttl is None:
        return None
    if ttl >= 250:
        return ("Solaris/AIX/Cisco (TTL 255)", 40)
    if ttl >= 190:
        return ("Windows (TTL ~128)", 65)
    if ttl >= 120:
        return "Windows (TTL ~128)", 65
    if ttl >= 60:
        return "Linux/macOS/BSD (TTL ~64)", 70
    return None


def run(engine):
    t = engine.target
    host = t.scan_host()
    guesses = {}
    ttl = _ping_ttl(host)
    g = ttl_guess(ttl)
    if g:
        guesses[g[0]] = g[1]
    banners = " ".join(s.get("banner", "").lower() for s in engine.state.get("services", []))
    for hint, name in BANNER_OS:
        if hint in banners:
            guesses[name] = max(guesses.get(name, 0), 85)
    if not guesses:
        engine.db.add_event(t.display, "network.osfp", "no os signal")
        return
    best = max(guesses.items(), key=lambda kv: kv[1])
    engine.state["os_guess"] = best[0]
    engine.log.info("OS guess: %s (confidence %d%%)" % best)
    engine.db.add_finding(Finding(
        t.display, "network.osfp", "recon", "info",
        "OS fingerprint: %s (~%d%% confidence)" % best,
        detail="Signals: TTL=%s; banner heuristics." % ttl,
        confidence="possible"))
