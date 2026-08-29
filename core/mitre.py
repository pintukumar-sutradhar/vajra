"""VAJRA MITRE ATT&CK mapping — every finding is tagged with technique IDs
so reports speak the language threat-intel and SOC teams expect."""

# (module_prefix, category_keyword/title_keyword) -> (technique, name)
EXPLICIT = {
    ("network.portscan", None): ("T1046", "Network Service Discovery"),
    ("network.services", None): ("T1046", "Network Service Discovery"),
    ("network.osfp", None): ("T1018", "Remote System Discovery"),
    ("network.brute", None): ("T1110", "Brute Force"),
    ("exploit.creds", None): ("T1110", "Brute Force"),
    ("exploit.exploit", None): ("T1210", "Exploitation of Remote Services"),
    ("exploit.verify", None): ("T1190", "Exploit Public-Facing Application"),
    ("post.recon", None): ("T1033", "System Owner/User Discovery"),
    ("recon.dns", None): ("T1590", "Gather Victim Network Information"),
    ("recon.whois", None): ("T1592", "Gather Victim Host Information"),
    ("recon.subdomains", None): ("T1593", "Search Open Websites/Domains"),
    ("recon.emails", None): ("T1589", "Gather Victim Identity Information"),
    ("web.crawl", None): ("T1595.001", "Scanning IP Blocks/Websites"),
}

CATEGORY_MAP = {
    "cve-surface": ("T1190", "Exploit Public-Facing Application"),
    "verified-exposure": ("T1190", "Exploit Public-Facing Application"),
    "exposure": ("T1190", "Exploit Public-Facing Application"),
    "credentials": ("T1110", "Brute Force"),
    "web-vuln": ("T1190", "Exploit Public-Facing Application"),
    "misconfiguration": ("T1562.004", "Impair Defenses: Disable Cloud Logs"),
    "hardening": ("T1562.001", "Impair Defenses: Downgrade Attack Surface"),
    "secrets": ("T1552", "Unsecured Credentials"),
    "info-disclosure": ("T1592", "Gather Victim Host Information"),
    "post-exploit": ("T1005", "Data from Local System"),
    "defense": ("T1595", "Active Scanning"),
    "tls": ("T1600", "Weaken Encryption"),
    "osint": ("T1589", "Gather Victim Identity Information"),
}

TITLE_KEYWORDS = [
    ("ms17-010", "T1210", "Exploitation of Remote Services"),
    ("smbv1 dialect", "T1210", "Exploitation of Remote Services"),
    ("kerberos user enumeration", "T1087.002", "Domain Account"),
    ("as-rep roastable", "T1558.004", "ASREP Roasting"),
    ("ntlm fingerprint", "T1018", "Remote System Discovery"),
    ("ldap enumeration", "T1087.002", "Domain Account"),
    ("ad password spray", "T1110.003", "Password Spraying"),
    ("active directory environment", "T1018", "Remote System Discovery"),
    ("reverse session", "T1059", "Command and Scripting Interpreter"),
    ("command execution", "T1059.004", "Unix Shell"),
    ("sql injection exploited", "T1005", "Data from Local System"),
    ("authentication bypassed", "T1078", "Valid Accounts"),
    ("credentials cracked", "T1110.001", "Password Guessing"),
    ("anonymous ftp", "T1078.001", "Default Accounts"),
    ("redis exposed", "T1552.001", "Credentials In Files"),
    ("docker api", "T1610", "Deploy Container"),
    ("kubelet", "T1610", "Deploy Container"),
    ("mqtt anonymous", "T1552", "Unsecured Credentials"),
    ("vnc without authentication", "T1078.001", "Default Accounts"),
    ("directory listing", "T1083", "File and Directory Discovery"),
    ("git repository", "T1552.001", "Credentials In Files"),
    ("environment file", "T1552.001", "Credentials In Files"),
    ("hardcoded secrets", "T1552.001", "Credentials In Files"),
    ("tomcat manager", "T1505.003", "Web Shell"),
    ("jenkins script console", "T1059.009", "Groovy"),
    ("actuator exposed", "T1552", "Unsecured Credentials"),
    ("path traversal", "T1083", "File and Directory Discovery"),
    ("local file inclusion", "T1083", "File and Directory Discovery"),
    ("open redirect", "T1566.002", "Spearphishing Link"),
    ("cross-site scripting", "T1059.007", "JavaScript/JScript"),
    ("template injection", "T1059", "Command and Scripting Interpreter"),
    ("nosql operator", "T1190", "Exploit Public-Facing Application"),
    ("crlf", "T1098? ", "Account Manipulation"),
    ("swagger", "T1592", "Gather Victim Host Information"),
    ("spring boot actuator", "T1552", "Unsecured Credentials"),
    ("expired tls", "T1600.001", "Reduce Key Space"),
    ("self-signed certificate", "T1600.001", "Reduce Key Space"),
    ("deprecated tls", "T1600.001", "Reduce Key Space"),
    ("security header", "T1562.001", "Impair Defenses"),
    ("cors", "T1557", "Adversary-in-the-Middle"),
    ("email addresses exposed", "T1589.002", "Email Addresses"),
    ("subdomain", "T1593.002", "Search Engines"),
    ("waf identified", "T1595", "Active Scanning"),
]


def lookup(module, category="", title=""):
    mod_key = module.split(".")[-1]
    for (m, _c), pair in EXPLICIT.items():
        if m.split(".")[-1] == mod_key:
            return pair
    pair = CATEGORY_MAP.get(category)
    if pair and "? " not in pair[0]:
        return pair
    tl = (title or "").lower()
    for kw, tid, name in TITLE_KEYWORDS:
        if kw in tl and "? " not in tid:
            return (tid, name)
    if pair:
        return pair
    return ("T1595", "Active Scanning")
