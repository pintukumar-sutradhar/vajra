"""VAJRA attack-path + finding-correlation layer.

Deterministic, evidence-grounded. Everything here is derived ONLY from data
already collected during the engagement (findings, services, credentials,
web-auth state, AD intel). It never invents a step that is not backed by at
least one supporting finding or a concrete collected asset/credential.

Two responsibilities:

1. ``correlate_findings`` — merge findings from different modules that describe
   the same underlying issue on the same target (dedup, Priority 3) and expose
   them as a single correlated cluster carrying every detection source, so a
   report does not flood the reader with N duplicates of one problem.

2. ``build_attack_paths`` — connect the collected facts into realistic attack
   chains (start -> steps -> destination), each with prerequisites, the
   evidence that supports every step, a confidence, the privilege gained and a
   MITRE technique (Priorities 4, 5, 16, 22).
"""

from core.database import SEV_RANK, SEV_BY_RANK, CONFIDENCE_NORM

# Map a concise canonical issue key to a human-readable label + MITRE technique.
# Used to normalise different module titles that describe the same problem.
CANONICAL = {
    "xss": ("Stored/Reflected XSS", "T1059.007"),
    "sqli": ("SQL injection", "T1190"),
    "command_injection": ("OS command injection", "T1059.003"),
    "rce": ("Remote code execution", "T1203"),
    "ssti": ("Server-side template injection", "T1059.007"),
    "xxe": ("XML external entity", "T1200"),
    "lfi": ("Local/remote file inclusion", "T1005"),
    "pathtraversal": ("Path traversal", "T1083"),
    "ssrf": ("Server-side request forgery", "T1190"),
    "idor": ("Insecure direct object reference", "T1213"),
    "bola": ("Broken object-level authorization", "T1213"),
    "weakcreds": ("Weak/default credentials", "T1078"),
    "authbypass": ("Authentication bypass", "T1078"),
    "deserialization": ("Insecure deserialization", "T1203"),
    "upload": ("Unrestricted file upload", "T1608.002"),
    "header": ("Missing/insecure security header", "T1195"),
    "clickjacking": ("Clickjacking", "T1021"),
    "cors": ("Misconfigured CORS", "T1550"),
    "tls": ("Weak TLS configuration", "T1573"),
    "cve": ("Known vulnerable software (CVE)", "T1190"),
    "smb_ms17": ("EternalBlue / MS17-010 (SMB)", "T1210"),
    "smb_signing": ("SMB signing disabled", "T1558"),
    "kerberoast": ("Kerberoasting", "T1558.003"),
    "asrep": ("AS-REP roasting", "T1558.004"),
    "adcs": ("ADCS certificate abuse", "T1649"),
    "dacl": ("Dangerous ACL/DACL", "T1222"),
    "dcsync": ("DCSync / credential dumping", "T1003.006"),
    "risky_check": ("Risk token / privileged exposure", "T1078"),
    "cloud_key": ("Exposed cloud credential", "T1552"),
    "bucket": ("Misconfigured cloud storage", "T1613"),
    "secrets": ("Sensitive information disclosure", "T1552"),
    "openredirect": ("Open redirect", "T1566.002"),
    "csrf": ("Cross-site request forgery", "T1204"),
    "jwt": ("JWT weakness", "T1606.002"),
}

# Keyword -> canonical key. Kept independent of severity so a weak signal can
# be correlated with a stronger one from another module.
KW = [
    ("command injection", "command_injection"), ("cmd injection", "command_injection"),
    ("command execution", "command_injection"), ("rce", "rce"), ("remote code", "rce"),
    ("code execution", "rce"), ("reveal", "rce"), ("webshell", "rce"),
    ("sql injection", "sqli"), ("sqli", "sqli"), ("sql inj", "sqli"),
    ("nosql injection", "sqli"),
    ("xss", "xss"), ("cross-site scripting", "xss"),
    ("ssti", "ssti"), ("template injection", "ssti"), ("template literal", "ssti"),
    ("xxe", "xxe"), ("xml external", "xxe"), ("xml entity", "xxe"),
    ("local file inclusion", "lfi"), ("remote file inclusion", "lfi"),
    ("lfi", "lfi"), ("rfi", "lfi"),
    ("path traversal", "pathtraversal"), ("directory traversal", "pathtraversal"),
    ("ssrf", "ssrf"), ("server-side request forgery", "ssrf"),
    ("idor", "idor"), ("insecure direct object", "idor"),
    ("bola", "bola"), ("broken object-level", "bola"),
    ("default credential", "weakcreds"), ("default cred", "weakcreds"),
    ("weak credential", "weakcreds"), ("weak password", "weakcreds"),
    ("easily brute", "weakcreds"), ("default password", "weakcreds"),
    ("default username", "weakcreds"), ("guessable", "weakcreds"),
    ("authentication bypass", "authbypass"), ("auth bypass", "authbypass"),
    ("login bypass", "authbypass"),
    ("deserialization", "deserialization"), ("deserialise", "deserialization"),
    ("file upload", "upload"), ("upload", "upload"),
    ("security header", "header"), ("http header", "header"),
    ("missing header", "header"), ("x-frame-options", "clickjacking"),
    ("clickjacking", "clickjacking"), ("frame-ancestors", "clickjacking"),
    ("cors", "cors"), ("cross-origin", "cors"),
    ("weak tls", "tls"), ("tls", "tls"), ("ssl", "tls"), ("ssl/tls", "tls"),
    ("heartbleed", "cve"), ("shellshock", "cve"), ("cve-", "cve"),
    ("known cve", "cve"), ("vulnerable version", "cve"), ("outdated", "cve"),
    ("ms17", "smb_ms17"), ("eternalblue", "smb_ms17"), ("smb1", "smb_ms17"),
    ("smbv1", "smb_ms17"), ("smb signing", "smb_signing"),
    ("kerberoast", "kerberoast"), ("as-rep", "asrep"), ("asrep", "asrep"),
    ("roast", "kerberoast"),
    ("adcs", "adcs"), ("certificate", "adcs"), ("esc1", "adcs"), ("esc2", "adcs"),
    ("dacl", "dacl"), ("acl", "dacl"), ("writeowner", "dacl"), ("writedacl", "dacl"),
    ("dc-sync", "dcsync"), ("dcsync", "dcsync"), ("ntds", "dcsync"),
    ("risk token", "risky_check"), ("high risk", "risky_check"),
    ("cloud key", "cloud_key"), ("aws", "cloud_key"), ("azure", "cloud_key"),
    ("gcp", "cloud_key"), ("sts", "cloud_key"),
    ("bucket", "bucket"), ("s3", "bucket"), ("gcs", "bucket"),
    ("sensitive", "secrets"), ("secret", "secrets"), ("private key", "secrets"),
    ("token", "secrets"), ("api key", "secrets"), ("password in", "secrets"),
    ("open redirect", "openredirect"),
    ("csrf", "csrf"), ("cross-site request forgery", "csrf"),
    ("jwt", "jwt"), ("json web token", "jwt"),
]


def canonical_key(title):
    """Return the canonical issue key (or None) for a finding title/body."""
    blob = (title or "").lower()
    for kw, key in KW:
        if kw in blob:
            return key
    return None


def _norm_target(target):
    t = (target or "").strip().lower()
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    return t


def _max_sev(findings):
    best = "info"
    for f in findings:
        s = (f.get("severity") or "info").lower()
        if s in SEV_RANK and SEV_RANK[s] > SEV_RANK.get(best, 0):
            best = s
    return best


def _max_conf(findings):
    best = "tentative"
    for f in findings:
        c = CONFIDENCE_NORM.get((f.get("confidence") or "").lower(), "tentative")
        if c == "certain":
            return "certain"
        if c == "firm":
            best = "firm"
    return best


def correlate_findings(findings):
    """Merge findings that describe the same underlying issue on the same
    target. Returns a list of clusters:

        {key, label, technique, target, severity, confidence,
         sources, tile_count, evidence_count, titles}

    Findings with an unknown canonical key (or severity 'info') are returned
    as singleton clusters so nothing is silently dropped.
    """
    clusters = {}
    single = []
    for f in findings:
        if (f.get("severity") or "info").lower() == "info":
            single.append(_singleton(f))
            continue
        key = canonical_key(f.get("title", ""))
        if not key:
            single.append(_singleton(f))
            continue
        tgt = _norm_target(f.get("target", "?"))
        ck = (key, tgt)
        if ck not in clusters:
            label, technique = CANONICAL.get(
                key, (key.replace("_", " ").title(), "T1190"))
            clusters[ck] = {
                "key": key, "label": label, "technique": technique,
                "target": f.get("target", "?"), "findings": []}
        clusters[ck]["findings"].append(f)
    out = []
    for c in clusters.values():
        fs = c.pop("findings")
        out.append({
            "key": c["key"], "label": c["label"],
            "technique": c["technique"], "target": c["target"],
            "severity": _max_sev(fs), "confidence": _max_conf(fs),
            "sources": sorted({x.get("module", "?") for x in fs}),
            "title_count": len(fs),
            "evidence_count": sum(
                1 for x in fs if (x.get("evidence") or "").strip()),
            "titles": [x.get("title", "") for x in fs],
        })
    out.sort(key=lambda c: -SEV_RANK.get(c["severity"], 0))
    return out + single


def _singleton(f):
    return {
        "key": None, "label": (f.get("title", "") or "finding").strip(),
        "technique": None, "target": f.get("target", "?"),
        "severity": (f.get("severity") or "info").lower(),
        "confidence": (f.get("confidence") or "tentative").lower(),
        "sources": [f.get("module", "?")], "title_count": 1,
        "evidence_count": 1 if (f.get("evidence") or "").strip() else 0,
        "titles": [f.get("title", "")],
    }


# ---------------------------------------------------------------------------
# Attack-path building
# ---------------------------------------------------------------------------

def _services_on(state, ports):
    """Return services matching any of `ports` (int list)."""
    out = []
    for s in state.get("services") or []:
        try:
            if int(s.get("port")) in ports:
                out.append(s)
        except (TypeError, ValueError):
            continue
    return out


def _has_findings(findings, *keys):
    """True if any correlated canonical key (or singleton title match) exists
    among findings for any of the given keys."""
    blob = " ".join((f.get("title", "") + " " + f.get("detail", "")).lower()
                    for f in findings)
    for k in keys:
        if canonical_key(blob) == k or k in blob:
            return True
    return False


def _any_creds(state):
    creds = state.get("creds") or []
    return len(creds) > 0


def _has_web_auth(state):
    wa = state.get("web_auth") or {}
    return bool(wa.get("established"))


def _sev_to_badge(sev):
    return sev


def build_attack_paths(state, findings):
    """Return a list of evidence-grounded attack paths (Priorities 5, 16).

    Each path:

        {start, destination, severity, confidence, technique,
         privilege_gained, prerequisites, steps:[{title, technique,
         evidence:[...]}], evidence_notes}

    A path is only produced when every step is backed by a finding or a
    concrete collected asset/credential. Nothing is fabricated.
    """
    paths = []
    findings = list(findings or [])

    def titles_for(blob_needle):
        return [f.get("title", "") for f in findings
                if blob_needle.lower() in
                (f.get("title", "") + " " + f.get("detail", "")).lower()][:4]

    creds = state.get("creds") or []
    web_auth = (state.get("web_auth") or {}).get("established")
    ad = state.get("ad") or {}
    domain = ad.get("domain") or ""
    forest = ad.get("forest") or ad.get("rootdomain") or domain
    open_ports = state.get("open_ports") or {}

    # --- Web credential reuse -> sensitive data -----------------------------
    if web_auth and _has_findings(findings, "secrets", "lfi", "pathtraversal"):
        web_ports = ", ".join(str(p) for p in sorted(open_ports)[:4])
        paths.append({
            "start": ("Authenticated web session (%s)" % web_ports
                      if web_ports else "Authenticated web app"),
            "destination": "Sensitive application data",
            "severity": "high",
            "confidence": _max_conf(findings),
            "technique": "T1078",
            "privilege_gained": "Authenticated user context",
            "prerequisites": ["Working login / session established",
                              "No authorization check on sensitive endpoint"],
            "steps": [
                {"title": "Login / session established",
                 "technique": "T1078",
                 "evidence": titles_for("login") or ["authenticated web session"]},
                {"title": "Sensitive data read by authenticated user",
                 "technique": "T1552",
                 "evidence": titles_for("secret") or titles_for("file read")},
            ],
            "evidence_notes": "Every step is tied to a collected finding.",
        })

    # --- Weak / default creds -> service compromise -------------------------
    if _any_creds(state):
        weak = [f for f in findings
                if canonical_key(f.get("title", "")) == "weakcreds"]
        target_ports = [p for p in (open_ports or {})
                        if p in (22, 23, 21, 445, 3389, 5432, 3306, 6379)]
        if weak or target_ports:
            paths.append({
                "start": "Exposed management service%s" % (
                    " (%s)" % ", ".join(map(str, target_ports[:5]))
                    if target_ports else ""),
                "destination": "Valid credentials obtained",
                "severity": "high" if weak else "medium",
                "confidence": _max_conf(weak) if weak else "tentative",
                "technique": "T1078",
                "privilege_gained": "Valid account on the service",
                "prerequisites": ["Reachable service",
                                  "Guessed or default credential accepted"],
                "steps": [
                    {"title": "Credential found / brute-forced",
                     "technique": "T1110",
                     "evidence": titles_for("default") or titles_for("brute")},
                    {"title": "Credentials validated against service",
                     "technique": "T1078",
                     "evidence": titles_for("valid") or titles_for("credential")},
                ],
                "evidence_notes": "Credential object recorded in state.",
            })

    # --- Credential reuse -> lateral movement ------------------------------
    if creds and len(open_ports) >= 2:
        paths.append({
            "start": "Compromised local host",
            "destination": "Additional reachable internal host(s)",
            "severity": "high",
            "confidence": _max_conf(findings),
            "technique": "T1021.002",
            "privilege_gained": "Access on another host/service",
            "prerequisites": ["Collected credential(s)",
                              "Multiple reachable services"],
            "steps": [
                {"title": "Credential harvested",
                 "technique": "T1003",
                 "evidence": titles_for("credential") or titles_for("hash")},
                {"title": "Credential reused against another host",
                 "technique": "T1078",
                 "evidence": ["%d credential(s) in state" % len(creds)],
                },
            ],
            "evidence_notes": "Driven by collected creds + open services.",
        })

    # --- AD: weak creds -> domain-compromise --------------------------------
    if domain:
        domain_finding = _has_findings(findings, "adcs", "dcsync", "kerberoast",
                                       "dacl", "smb_signing", "asrep")
        paths.append({
            "start": "Subject: %s" % (web_auth and "authenticated user" or
                                      "domain user"),
            "destination": "Domain %s compromise%s" % (
                domain, (" / forest %s" % forest) if forest and forest != domain
                else ""),
            "severity": "critical" if domain_finding else "high",
            "confidence": "certain" if _has_findings(findings, "dcsync") else
                          ("firm" if domain_finding else "tentative"),
            "technique": "T1482",
            "privilege_gained": "Domain admin / DC-equivalent access",
            "prerequisites": ["Valid domain credentials",
                              "One exploitable AD control (ACL/ADCS/SPN)"] if
                             domain_finding else
                             ["Valid domain credentials",
                              "Continue enumeration toward a control"],
            "steps": [
                {"title": "Domain discovered / creds bind",
                 "technique": "T1482",
                 "evidence": titles_for("domain") or ["domain=%s" % domain]},
                {"title": "Kerberoast / AS-REP / DACL / ADCS abuse",
                 "technique": "T1558",
                 "evidence": titles_for("kerberoast") or titles_for("dacl")
                             or titles_for("adcs") or titles_for("dc-sync")},
                {"title": "Elevate to domain-level privilege",
                 "technique": "T1078",
                 "evidence": titles_for("domain admin") or
                             titles_for("dc-sync")},
            ],
            "evidence_notes": "AD trust/domain facts from collected AD intel.",
        })

    # --- Post-exploitation: pivot / persistence / exfil ---------------------
    if (state.get("channels") or _has_findings(findings, "rce", "command_injection")
            or titles_for("pivot") or titles_for("persistence")):
        paths.append({
            "start": "Seed foothold on a target",
            "destination": "Long-lived foothold + data exfiltration",
            "severity": "high",
            "confidence": _max_conf(findings),
            "technique": "T1071",
            "privilege_gained": "Persistent remote access / outbound channel",
            "prerequisites": ["Execution primitive (RCE/channel)",
                              "Egress path for data"],
            "steps": [
                {"title": "Initial execution",
                 "technique": "T1059",
                 "evidence": titles_for("rce") or titles_for("execution")},
                {"title": "Pivot / persistence established",
                 "technique": "T1098" if titles_for("persistence") else "T1090",
                 "evidence": titles_for("pivot") or titles_for("persistence")},
                {"title": "Sensitive data staged / exfiltrated",
                 "technique": "T1041",
                 "evidence": titles_for("exfil") or titles_for("loot")},
            ],
            "evidence_notes": "Backed by post-exploitation findings.",
        })

    return _rank_paths(paths)


def _rank_paths(paths):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(paths, key=lambda p: order.get(p["severity"], 5))


def attack_path_md(paths):
    """Render attack paths as Markdown."""
    if not paths:
        return "No evidence-grounded attack paths were derived.\n"
    lines = ["%d evidence-grounded attack path(s):" % len(paths), ""]
    for i, p in enumerate(paths, 1):
        lines.append("### Path %d — %s -> %s" % (i, p["start"],
                                                 p["destination"]))
        lines.append("")
        lines.append("- **Severity:** %s  **Confidence:** %s  "
                     "**Privilege gained:** %s" %
                     (p["severity"], p["confidence"],
                      p.get("privilege_gained", "-")))
        lines.append("- **Technique:** %s" % p.get("technique", "-"))
        if p.get("prerequisites"):
            lines.append("- **Prerequisites:** %s" %
                         "; ".join(p["prerequisites"]))
        lines.append("")
        lines.append("| Step | Technique | Evidence |")
        lines.append("|---|---|---|")
        for step in p["steps"]:
            ev = "; ".join(step.get("evidence", [])) or "-"
            lines.append("| %s | %s | %s |" % (step["title"],
                                               step.get("technique", "-"),
                                               ev[:160]))
        lines.append("")
        if p.get("evidence_notes"):
            lines.append("_%s_" % p["evidence_notes"])
            lines.append("")
    return "\n".join(lines)

# Alias so report/engine imports read naturally.
render_md = attack_path_md
