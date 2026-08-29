"""VAJRA compliance layer — map findings to CIS / NIST CSF / PCI DSS controls
and generate a prioritized remediation playbook. Pure data + templates; the
selftest asserts every registered module resolves to at least a control."""
from core.database import SEV_RANK

# module -> {cis: [ids], nist: [function:category codes], pci: [req codes]}
# Fallback rows cover any module not enumerated below (add more over time).
MAP = {
    "recon.dns": {"cis": ["CIS 3.1.3"], "nist": ["DE.CM-4"], "pci": ["2.2"]},
    "recon.whois": {"cis": ["CIS 3.1.1"], "nist": ["RS.MA-1"], "pci": ["2.2"]},
    "recon.subdomains": {"cis": ["CIS 3.1.2"], "nist": ["RS.MA-1"],
                         "pci": ["2.2"]},
    "recon.emails": {"cis": ["CIS 3.1.1"], "nist": ["PR.DS-2"], "pci": ["6.5.1"]},
    "recon.axfr": {"cis": ["CIS 3.2"], "nist": ["PR.DS-2"], "pci": ["2.2"]},
    "network.portscan": {"cis": ["CIS 4.1"], "nist": ["DE.CM-8"],
                         "pci": ["11.1"]},
    "network.services": {"cis": ["CIS 4.1.1"], "nist": ["RS.MA-1"],
                         "pci": ["11.2.1"]},
    "network.udpprobe": {"cis": ["CIS 4.1.1"], "nist": ["DE.CM-4"],
                         "pci": ["11.1"]},
    "network.osfp": {"cis": ["CIS 4.1.1"], "nist": ["DE.CM-8"],
                     "pci": ["11.1"]},
    "network.service_exposure": {"cis": ["CIS 3.3"],
                                 "nist": ["PR.AC-4", "PR.PT-4"],
                                 "pci": ["2.2.1"]},
    "network.smtp": {"cis": ["CIS 3.3"], "nist": ["PR.DS-2"], "pci": ["6.5.1"]},
    "network.shares": {"cis": ["CIS 3.3"], "nist": ["PR.AC-4"],
                       "pci": ["2.2.1"]},
    "network.snmp": {"cis": ["CIS 3.3"], "nist": ["PR.AC-4"], "pci": ["2.3"]},
    "network.brute": {"cis": ["CIS 5.1.3"], "nist": ["PR.AC-1", "DE.CM-4"],
                      "pci": ["8.1.3", "8.2"]},
    "web.auth_login": {"cis": ["CIS 5.1"], "nist": ["PR.AC-1"],
                       "pci": ["8.1"]},
    "web.crawl": {"cis": ["CIS 4.1"], "nist": ["DE.CM-8"],
                  "pci": ["11.1"]},
    "web.dirbuster": {"cis": ["CIS 4.1"], "nist": ["DE.CM-8"],
                      "pci": ["11.1"]},
    "web.headers": {"cis": ["CIS 3.5"], "nist": ["DE.CM-8"], "pci": ["6.5"]},
    "web.tls": {"cis": ["CIS 3.10"], "nist": ["PR.DS-2"], "pci": ["2.3"]},
    "web.waf": {"cis": ["CIS 3.5"], "nist": ["DE.CM-8"], "pci": ["6.5.3"]},
    "web.tech": {"cis": ["CIS 3.9"], "nist": ["DE.CM-8"], "pci": ["6.2"]},
    "web.js": {"cis": ["CIS 3.6"], "nist": ["DE.CM-4"], "pci": ["6.5.1"]},
    "web.ssrf_scan": {"cis": ["CIS 6.1"], "nist": ["PR.DS-2"],
                      "pci": ["6.5.4"]},
    "web.ssrf_pivot": {"cis": ["CIS 3.3"], "nist": ["PR.AC-4"],
                       "pci": ["2.2.1"]},
    "web.race": {"cis": ["CIS 6.1"], "nist": ["DE.CM-8"], "pci": ["6.5.4"]},
    "web.jwt_audit": {"cis": ["CIS 6.1"], "nist": ["DE.CM-4"],
                      "pci": ["6.5.4"]},
    "web.graphql_probe": {"cis": ["CIS 6.1"], "nist": ["DE.CM-4"],
                          "pci": ["6.5.4"]},
    "web.vulnscan": {"cis": ["CIS 6.3"], "nist": ["PR.DS-6"],
                     "pci": ["6.5"]},
    "web.policy": {"cis": ["CIS 3.5"], "nist": ["PR.AT-5"], "pci": ["6.5.3"]},
    "web.upload": {"cis": ["CIS 6.2"], "nist": ["PR.DS-6"], "pci": ["6.5.1"]},
    "web.takeover": {"cis": ["CIS 3.1.2"], "nist": ["PR.DS-2"],
                     "pci": ["2.2"]},
    "web.wiretests": {"cis": ["CIS 3.6"], "nist": ["PR.DS-2"],
                      "pci": ["6.5"]},
    "web.loot": {"cis": ["CIS 3.3"], "nist": ["PR.DS-5"], "pci": ["3.2"]},
    "web.api": {"cis": ["CIS 3.4"], "nist": ["DE.CM-4"], "pci": ["6.5.4"]},
    "web.cloud": {"cis": ["CIS 1.1"], "nist": ["DE.AE-2"], "pci": ["2.2"]},
    "exploit.creds": {"cis": ["CIS 5.2"], "nist": ["PR.AC-1"],
                      "pci": ["8.2.1"]},
    "exploit.exploit": {"cis": ["CIS 6.1"], "nist": ["PR.PT-4"],
                        "pci": ["6.5"]},
    "exploit.spray": {"cis": ["CIS 5.1.3"], "nist": ["PR.AC-1"],
                      "pci": ["8.1.4"]},
    "exploit.verify": {"cis": ["CIS 6.3"], "nist": ["DE.CM-4"],
                       "pci": ["6.5"]},
    "exploit.form_brute": {"cis": ["CIS 5.1.3"], "nist": ["PR.AC-1"],
                           "pci": ["8.1.6"]},
    "ad.discovery": {"cis": ["CIS 3.1"], "nist": ["DE.CM-8"], "pci": ["2.2"]},
    "ad.smb_recon": {"cis": ["CIS 12.1"], "nist": ["DE.CM-8"],
                     "pci": ["2.2"]},
    "ad.kerberos": {"cis": ["CIS 6.3"], "nist": ["PR.AC-4"],
                    "pci": ["8.2.4"]},
    "ad.ldap_enum": {"cis": ["CIS 5.4"], "nist": ["PR.AC-4"],
                     "pci": ["8.2"]},
    "ad.spray": {"cis": ["CIS 5.1.3"], "nist": ["PR.AC-1"],
                 "pci": ["8.1.4"]},
    "ad.movement": {"cis": ["CIS 5.3"], "nist": ["PR.AC-4"],
                    "pci": ["8.1"]},
    "ad.privesc_ops": {"cis": ["CIS 5.4"], "nist": ["PR.AC-4"],
                       "pci": ["8.1"]},
    "ad.power": {"cis": ["CIS 5.4", "CIS 5.3"], "nist": ["PR.AC-4"],
                 "pci": ["8.2"]},
    "post.recon": {"cis": ["CIS 5.4"], "nist": ["PR.DS-5"], "pci": ["3.2"]},
    "post.loot": {"cis": ["CIS 3.3"], "nist": ["PR.DS-5"], "pci": ["3.2"]},
}

_FALLBACK = {"cis": ["CIS 3.3"], "nist": ["DE.CM-8"], "pci": ["6.5"]}

TITLES = {
    "critical": "Resolve today. Direct, externally-triggerable compromise.",
    "high": "Resolve this sprint. High likelihood of exploitation.",
    "medium": "Schedule this release. Exploitation requires conditions.",
    "low": "Informational hardening.",
    "info": "Notes only.",
}


def controls_for(module):
    return MAP.get(module, dict(_FALLBACK))


def remediate(findings):
    """Group findings into a prioritized playbook.
    Returns list of sections: {'severity', 'priority', 'items': [...]}."""
    order = ["critical", "high", "medium", "low", "info"]
    sections = []
    for sev in order:
        items = [f for f in findings if f.get("severity") == sev]
        if not items:
            continue
        seen = set()
        rows = []
        for f in items:
            key = (f.get("module"), f.get("title"))
            if key in seen:
                continue
            seen.add(key)
            ctrl = controls_for(f.get("module", ""))
            rows.append({
                "module": f.get("module"),
                "title": f.get("title"),
                "remediation": f.get("remediation") or
                               "Review and remediate per configuration baseline.",
                "cis": ctrl["cis"], "nist": ctrl["nist"], "pci": ctrl["pci"],
            })
        sections.append({"severity": sev, "priority": TITLES.get(sev, ""),
                         "items": rows})
    return sections


def markdown_playbook(sections):
    lines = ["# Remediation Playbook", "",
             "Prioritized by severity; control cross-references: CIS Benchmark, "
             "NIST CSF, PCI DSS 4.0.", ""]
    for sec in sections:
        lines.append("## %s — %s" % (sec["severity"].upper(),
                                     sec["priority"]))
        lines.append("")
        for it in sec["items"]:
            lines.append("- **%s** (%s)" % (it["title"], it["module"]))
            lines.append("  - Remediation: %s" % it["remediation"])
            refs = []
            if it["cis"]:
                refs.append("CIS: %s" % ", ".join(it["cis"]))
            if it["nist"]:
                refs.append("NIST CSF: %s" % ", ".join(it["nist"]))
            if it["pci"]:
                refs.append("PCI DSS: %s" % ", ".join(it["pci"]))
            if refs:
                lines.append("  - Controls: " + " | ".join(refs))
        lines.append("")
    return "\n".join(lines)