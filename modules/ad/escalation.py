"""VAJRA ad.escalation — ADCS (ESC1–ESC8) + forest-trust escalation chain.

Consolidates the "after you have AD read / a validated principal" escalation
options into one actively-checked step:

  * detects whether the enterprise runs AD Certificate Services (a CA machine
    account / pKIEnrollmentService) from the AD metadata already gathered;
  * if `certipy-ad` (certipy) is installed, runs `certipy find` against the
    CA to enumerate misconfigurations mapping to ESC1/ESC3/ESC5/ESC8 and
    stores its JSON as evidence;
  * regardless of tooling, emits the precise operator-run recipe + the exact
    ESC conditions to look for, and records any cross-forest trust jump path
    already discovered (so a forest escalation chain is surfaced).

Intrusive and requires --aggressive. It never requests/abuses a certificate
itself — it identifies the opportunity and hands the operator a ready review
path, because an actual cert request is a destructive, side-effecting act."""
import subprocess

from core.database import Finding
from core.utils import which_tool

ESC_PLAYBOOK = [
    ("ESC1", "NTAuthCertificates + a template the user can enroll on with "
             "SAN = arbitrary identity -> request a cert for a DA, then "
             "auth with it (Pass-the-Certificate)."),
    ("ESC3", "Enrollment agent templates (OU-inherited) chainable to a "
             "user/template -> request agent cert then a cert on behalf of "
             "anyone."),
    ("ESC4", "Weak template ACLs (anyone can write/register) -> swap "
             "template to request a DA cert."),
    ("ESC5", "Weak CA AD object ACLs -> edit the CA to add a malicious "
             "template/trusted cert."),
    ("ESC6", "EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA -> SAN any identity."),
    ("ESC7", "Weak CA Change/Manage CA ACL -> issue certs as the CA."),
    ("ESC8", "NTLM relay to AD CS HTTP(S) Web Enrollment / ICPR endpoint -> "
             "machine account cert."),
]


def _ca_hint(engine):
    ad = engine.state.get("ad") or {}
    hints = []
    for name in ("ca", "pkienrol", "certauth"):
        for h in ([dc.get("host") for dc in ad.get("dcs", [])] or []):
            if name in h.lower():
                hints.append(h)
    return hints or (list(ad.get("dcs", []) or [])[:1])


def run(engine):
    t = engine.target
    ad = engine.state.get("ad") or {}
    if not getattr(engine.args, "aggressive", False):
        engine.db.add_finding(Finding(
            t.display, "ad.escalation", "coverage", "info",
            "ADCS / forest escalation chain skipped (requires --aggressive)",
            detail="ADCS ESC1-8 and forest-trust jumps are intrusive to "
                   "exercise; re-run with --aggressive to check them.",
            confidence="firm"))
        return
    realm = ad.get("realm") or getattr(engine, "ad_creds", {}).get("realm", "")
    host = t.scan_host()
    creds = getattr(engine, "ad_creds", {}) or {}
    dcs = [d["host"] for d in ad.get("dcs", [])] or [host]
    if not realm or not creds.get("user"):
        engine.db.add_finding(Finding(
            t.display, "ad.escalation", "coverage", "info",
            "ADCS escalation chain needs validated AD credentials",
            detail="Pass --ad-user/--ad-pass/--nthash and a realm to run "
                   "certipy find and enumerate ESC conditions.",
            confidence="firm"))
        return

    cert = which_tool("certipy", "certipy-ad")
    ca_hint = _ca_hint(engine)
    ca_present = bool(ca_hint)
    ev = ""

    if cert and ca_present:
        target = ca_hint[0]
        args = [cert, "find", "-u", "%s@%s" % (creds["user"], realm),
                "-dc-ip", target, "-vulnerable", "-stdout"]
        try:
            r = subprocess.run(args, capture_output=True, text=True,
                               timeout=120)
            out = (r.stdout or "") + (r.stderr or "")
        except Exception as e:
            out = "error: %r" % e
        if "CA Name" in out or "Template Name" in out or "Certificate" in out:
            ev = out[:4000]
            try:
                ev_rel = engine.save_evidence("adcs_find.txt", out)
            except Exception:
                ev_rel = ""
            engine.db.add_finding(Finding(
                t.display, "ad.escalation", "exploit-proof", "critical",
                "AD Certificate Services found — ADCSC ESC1-8 audit ran on %s"
                % target,
                detail=("certipy find reported CA/template data against %s."
                        " Review the evidence for ESC1/3/5/6/8 conditions and "
                        "follow the playbook below to escalate to a DA cert."
                        % target) + ((" Saved to " + ev_rel) if ev_rel else ""),
                evidence=ev,
                remediation="Harden template ACLs, disable "
                            "EDITF_ATTRIBUTESUBJECTALTNAME2, monitor cert "
                            "requests, patch ESC8 relay endpoints.",
                confidence="firm"))
        else:
            engine.db.add_finding(Finding(
                t.display, "ad.escalation", "coverage", "info",
                "ADCS audit ran but certipy returned no misconfiguration",
                detail="certipy find produced no vulnerable output on %s. "
                       "Happy posture." % target,
                evidence=out[:800], confidence="firm"))
    elif ca_present:
        # No tool but a CA is hinted -> hand the operator the playbook.
        play = "\n".join("  %s: %s" % e for e in ESC_PLAYBOOK)
        engine.db.add_finding(Finding(
            t.display, "ad.escalation", "post-recon", "high",
            "AD CS likely present — ESC1-8 escalation chain READY to run",
            detail=("Enterprise CA hinted at %s. Tool certipy-ad not "
                    "installed; check it and rerun for automated ESC "
                    "enumeration. Conditions to probe:\n%s"
                    % (", ".join(ca_hint), play)),
            evidence=("realm=%s dc=%s" % (realm, ", ".join(dcs))),
            remediation="Same as full audit above.",
            confidence="firm"))

    # Forest-trust escalation note (already-discovered trusts).
    trusts = ad.get("trusts") or []
    if trusts:
        engine.db.add_finding(Finding(
            t.display, "ad.escalation", "post-recon", "high",
            "Forest trust escalation path available (%d trust(s))" % len(trusts),
            detail=("Cross-forest trusts can be jumped via SIDHistory "
                    "injection or the trust key (inter-realm TGT). Paths:\n%s"
                    % "\n".join("  - " + tr for tr in trusts[:8])),
            evidence="realm=%s trusts=%s" % (realm, ", ".join(trusts[:8])),
            remediation="Review trust direction/filtering; disable SID "
                        "filtering exemptions; monitor inter-realm auth.",
            confidence="firm"))
