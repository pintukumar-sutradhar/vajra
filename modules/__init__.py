"""Vajra - module registry. Each module exposes run(engine)."""

MODULES = []


def register(name, phase, func_path, desc, cond="always", profile_skip=None):
    MODULES.append({
        "name": name,
        "phase": phase,
        "func": func_path,
        "desc": desc,
        "cond": cond if isinstance(cond, list) else [cond],
        "profile_skip": profile_skip or [],
    })


register("recon.dns", "recon", "modules.recon.dns_recon",
         "DNS records, forward/backward lookups", cond=["domain"])

register("recon.whois", "recon", "modules.recon.whois_lookup",
         "WHOIS registration data (raw protocol fallback)", cond=["domain"])

register("recon.subdomains", "recon", "modules.recon.subdomain_enum",
         "Subdomain enumeration via DNS + CT logs", cond=["domain"])

register("recon.emails", "web", "modules.recon.email_harvest",
         "Email harvesting from crawled pages", cond=["url"])

register("recon.axfr", "recon", "modules.recon.axfr",
         "DNS zone-transfer (AXFR) attempt from authoritative NS",
         cond=["domain"])

register("network.portscan", "net", "modules.network.port_scanner",
         "Async TCP port scan with latency metrics", cond=["always"],
         profile_skip=["webonly"])

register("network.services", "net", "modules.network.service_detect",
         "Banner grabbing, protocol probing, TLS certs, CVE correlation",
         cond=["ports_open"], profile_skip=["webonly"])

register("network.udpprobe", "net", "modules.network.udp_probe",
         "UDP service probes: DNS CHAOS / NTP / SNMP sysDescr",
         cond=["always"], profile_skip=["webonly"])

register("network.osfp", "net", "modules.network.os_fingerprint",
         "OS fingerprinting via TTL + banner heuristics",
         cond=["ports_open"], profile_skip=["webonly"])

register("network.service_exposure", "net",
         "modules.network.service_exposure",
         "Unauthenticated exposure sweeps: Redis without AUTH, open Docker API "
         "and Docker Swarm, Memcached stats, Elasticsearch/InfluxDB/CouchDB "
         "unauth, ZooKeeper/Consul/etcd open, Kafka/K8s/WebLogi-c-ish console "
         "detections, SMTP banner",
         cond=["ports_open"], profile_skip=["recon"])

register("network.smtp", "net", "modules.network.smtp_check",
         "SMTP audit: open-relay envelope check (no mail sent) + VRFY/EXPN "
         "user enumeration",
         cond=["ports:25"], profile_skip=["recon"])

register("network.shares", "net", "modules.network.share_enum",
         "SMB + NFS share enumeration (read-only nmap/smbclient/showmount, "
         "plus a native SMB1 RAP NetShareEnum fallback)",
         cond=["ports:139,445,2049"], profile_skip=["recon"])

register("network.snmp", "net", "modules.network.snmp_probe",
         "SNMPv1 read: community-string sweep + sysDescr/sysName capture "
         "(pure BER encoder, no SETs)",
         cond=["udp:161"], profile_skip=["recon"])

register("network.brute", "exploit", "modules.network.brute_forcer",
         "Credential brute-force (FTP/SSH/HTTP basic/forms)",
         cond=["ports_open"], profile_skip=[])

register("web.auth_login", "web", "modules.web.auth_logic",
         "Authenticated-scan bootstrap: OTP/TOTP-aware login, session cookie "
         "adoption, CSRF handling",
         cond=["has_web"])

register("web.crawl", "web", "modules.web.crawler",
         "Async BFS crawler collecting pages/forms/emails/JS",
         cond=["has_web"])

register("web.dirbuster", "web", "modules.web.dir_buster",
         "Directory and sensitive-file discovery",
         cond=["has_web"])

register("web.headers", "web", "modules.web.header_audit",
         "Security header and cookie hardening audit",
         cond=["has_web"])

register("web.tls", "web", "modules.web.tls_audit",
         "TLS/certificate strength audit",
         cond=["has_web_tls"])

register("web.waf", "web", "modules.web.waf_detect",
         "WAF / edge protection fingerprinting",
         cond=["has_web"])

register("web.tech", "web", "modules.web.tech_fingerprint",
         "Web technology and CMS fingerprinting",
         cond=["has_web"])

register("web.js", "web", "modules.web.js_analysis",
         "JavaScript secret/endpoint analysis",
         cond=["has_web"])

register("web.ssrf_scan", "web", "modules.web.ssrf_scan",
         "SSRF detection incl. cloud-metadata endpoints",
         cond=["has_web"])

register("web.ssrf_pivot", "web", "modules.web.ssrf_pivot",
         "Internal port scan through a confirmed SSRF (read-only loopback "
         "probe)",
         cond=["has_web"], profile_skip=[])

register("web.race", "web", "modules.web.race_check",
         "Race-condition / TOCTOU checks on state-change POST surfaces",
         cond=["has_forms"], profile_skip=[])

register("web.jwt_audit", "web", "modules.web.jwt_audit",
         "JWT decode + alg=none + weak-secret attacks",
         cond=["has_web"])

register("web.graphql_probe", "web", "modules.web.graphql_probe",
         "GraphQL introspection & IDE discovery",
         cond=["has_web"])

register("web.vulnscan", "web", "modules.web.vuln_scanner",
         "Injection suite: XSS, SQLi (incl. boolean-blind), LFI, RCE, SSTI, "
         "redirects, XXE/JSON-body, HPP, Host-header, CRLF",
         cond=["has_web"])

register("web.policy", "web", "modules.web.policy_check",
         "Rate-limiting / lockout probing on login surfaces",
         cond=["has_web"])

register("web.upload", "web", "modules.web.upload_check",
         "File-upload tests: multipart, traversal/double-ext filename, "
         "stored content retrievability",
         cond=["has_forms"])

register("web.takeover", "web", "modules.web.takeover_check",
         "Dangling-CNAME subdomain takeover indicators",
         cond=["has_subdomains"], profile_skip=[])

register("web.wiretests", "web", "modules.web.wiretests",
         "Wire tests: WebSocket upgrade, CL.TE/TE.CL smuggling signal, "
         "deserialization markers",
         cond=["has_web"])

register("web.loot", "web", "modules.web.sensitive_files",
         "Sensitive-file checklist: VCS metadata, .env, backups, phpinfo, "
         "actuator, admin panels",
         cond=["has_web"])

register("web.api", "web", "modules.web.api_module",
         "OpenAPI/Swagger discovery, endpoint inventory + IDOR/CSRF sweep, "
         "JWKS algo-confusion, OAuth/OIDC metadata audit",
         cond=["has_web"], profile_skip=[])

register("web.cloud", "web", "modules.web.cloud_check",
         "Public bucket exposure scan (S3 / GCS / Azure Blob) via read-only "
         "listing probes",
         cond=["always"], profile_skip=[])

register("exploit.creds", "exploit", "modules.exploit.default_creds",
         "Default credentials and unauth admin panels",
         cond=["has_web_or_services"])

register("exploit.exploit", "exploit", "modules.exploit.exploitation",
         "ACTIVE exploitation: SQLi extraction, RCE channels, auth bypass",
         cond=["has_web"])

register("exploit.spray", "exploit", "modules.exploit.spray",
         "Lockout-aware password spraying (deep tier)",
         cond=["ports_open"], profile_skip=["quick", "stealth", "webonly"])

register("exploit.verify", "exploit", "modules.exploit.known_exploits",
         "Safe verification probes for known CVE exposures",
         cond=["always"])

register("exploit.form_brute", "exploit", "modules.exploit.form_brute",
         "Web login-form brute-force against app auth systems (aggressive)",
         cond=["has_web"], profile_skip=[])

register("ad.discovery", "ad", "modules.ad.discovery",
         "DC discovery via DNS SRV + LDAP/SMB surface",
         cond=["always"], profile_skip=["webonly"])

register("ad.smb_recon", "ad", "modules.ad.smb_recon",
         "Compact SMB exploitation: NTLM fingerprint, SMBv1 dialect, "
         "MS17-010 verdict, PTH capable auth check",
         cond=["ports:445"], profile_skip=["webonly"])

register("ad.kerberos", "ad", "modules.ad.kerberos",
         "Kerberos: unauth user enum + AS-REP roasting; kerberoasting "
         "with any valid credentials",
         cond=["has_ad"], profile_skip=["webonly"])

register("ad.ldap_enum", "ad", "modules.ad.ldap_enum",
         "LDAP mining dual-pass: unauth users/SPN/LAPS/desc; auth adds "
         "adminCount/delegation/no-preauth/computers/trusts",
         cond=["has_ad"], profile_skip=["webonly"])

register("ad.spray", "ad", "modules.ad.spray",
         "Lockout-aware AD password spraying over SMB NTLMv2",
         cond=["has_ad"], profile_skip=["webonly", "quick", "stealth"])

register("ad.movement", "ad", "modules.ad.movement",
         "Lateral movement: validated creds -> psexec/wmiexec/smbexec/atexec "
         "command channel (unlocks post.recon); NTLM-relay + potato guidance",
         cond=["has_ad"], profile_skip=["webonly"])

register("ad.privesc_ops", "ad", "modules.ad.privesc_ops",
         "Privilege-scalation ops: SYSVOL/GPP cred theft, ZeroLogon probe, "
         "DC-Sync NTDS dump, bounded offline hashcat crack",
         cond=["has_ad"], profile_skip=["webonly"])

register("ad.power", "ad", "modules.ad.power",
         "Attack-depth beyond hashes: authenticated LDAP DACL risk analysis "
         "(BloodHound-lite) + golden/silver ticket forgery playbook + "
         "cross-realm trust-jump notes",
         cond=["has_ad"], profile_skip=["webonly"])

register("post.loot", "post", "modules.post.loot",
         "Post-compromise loot survey: high-value secret file check over "
         "an established SSH credential (read-only)",
         cond=["ports:22"], profile_skip=["webonly", "quick"])

register("post.recon", "post", "modules.post.system_recon",
         "Post-exploitation system recon through established channels",
         cond=["has_channels"])

PHASE_ORDER = ["recon", "net", "web", "exploit", "ad", "post"]


def get_modules():
    return MODULES


def find(name):
    for m in MODULES:
        if m["name"] == name:
            return m
    return None
