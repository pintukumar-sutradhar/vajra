"""VAJRA intelligence engine — service mapping, banner-driven CVE correlation,
attack-path planning and narrative risk summarization."""
import re
import json

from core.utils import load_json
from core.database import SEV_WEIGHT


PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 26: "smtp",
    37: "time", 53: "domain", 67: "dhcps", 69: "tftp", 79: "finger", 80: "http",
    81: "http", 88: "kerberos", 106: "pop3pw", 110: "pop3", 111: "rpcbind",
    113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 144: "news", 161: "snmp",
    162: "snmptrap", 179: "bgp", 199: "smux", 389: "ldap", 427: "svploc",
    443: "https", 444: "snpp", 445: "microsoft-ds", 465: "smtps", 513: "login",
    514: "shell", 515: "printer", 543: "klogin", 544: "kshell", 548: "afp",
    554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 646: "ldp",
    873: "rsync", 902: "vmware-auth", 993: "imaps", 995: "pop3s", 1080: "socks",
    1099: "java-rmi", 1194: "openvpn", 1337: "waste", 1433: "ms-sql-s",
    1434: "ms-sql-m", 1494: "citrix-ica", 1521: "oracle", 1720: "h323q931",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2181: "zookeeper", 2222: "ssh-alt", 2375: "docker", 2376: "dockers",
    3000: "http-dev", 3128: "squid-http", 3260: "iscsi", 3268: "globalcatLDAP",
    3306: "mysql", 3389: "ms-wbt-server", 3690: "svn", 4444: "krb524",
    4848: "glassfish", 5000: "http-alt", 5037: "adb", 5060: "sip", 5061: "sips",
    5222: "xmpp", 5353: "mdns", 5432: "postgresql", 5555: "adb-hl", 5631: "pcanywhere",
    5672: "amqp", 5601: "kibana", 5800: "vnc-http", 5900: "vnc", 5984: "couchdb",
    5985: "winrm", 5986: "winrm-ssl", 6379: "redis", 6667: "irc", 7001: "weblogic",
    7002: "weblogic-ssl", 8000: "http-alt", 8008: "http-alt", 8009: "ajp13",
    8080: "http-proxy", 8081: "http-alt", 8181: "http-alt", 8443: "https-alt",
    8500: "consul", 8888: "http-alt", 9000: "cslistener", 9042: "cassandra",
    9090: "websm", 9092: "kafka", 9100: "jetdirect", 9160: "cassandra-thrift",
    9200: "elasticsearch", 9300: "elasticsearch-cl", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongod", 27018: "mongod", 50070: "hadoop-namenode",
    61616: "activemq", 49152: "msrpc-epm",
}

HTTP_PORTS = {80, 81, 443, 591, 2082, 2083, 2095, 2096, 3000, 4443, 4567, 5000,
              5985, 6278, 7001, 8000, 8008, 8010, 8020, 8042, 8080, 8081, 8088,
              8090, 8181, 8222, 8280, 8443, 8500, 8530, 8888, 8899, 9000, 9080,
              9090, 9200, 9443, 10000}


def guess_service(port):
    return PORT_SERVICES.get(port)


def is_http_port(port):
    return port in HTTP_PORTS or (port in PORT_SERVICES and
                                  str(PORT_SERVICES[port]).startswith("http")) or \
        port > 1024 and False


VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,4})")


def parse_version(v):
    m = VERSION_RE.search(str(v))
    if not m:
        return None
    parts = [int(x) for x in m.group(1).split(".")]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def version_cmp(a, b):
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    return (pa > pb) - (pa < pb)


class RangeCheck:
    def __init__(self, expr):
        expr = str(expr).strip()
        self.op = "=="
        self.ver = None
        for op in ("<=", ">=", "==", "<", ">"):
            if expr.startswith(op):
                self.op = op
                self.ver = expr[len(op):]
                return
        if expr.split("#")[0].lower() in ("any", "*", "unknown"):
            self.op = "any"
            return
        self.ver = expr

    def match(self, ver):
        if self.op == "any":
            return True
        c = version_cmp(ver, self.ver)
        if c is None:
            return False
        return {"<": c < 0, "<=": c <= 0, "==": c == 0,
                ">": c > 0, ">=": c >= 0}[self.op]


class Intelligence:
    def __init__(self, path=None):
        self.cve_db = {}
        try:
            raw = load_json("intel/cve_db.json")
            self.cve_db = raw.get("products", raw) if isinstance(raw, dict) else {}
        except Exception:
            self.cve_db = {}

    def correlate_banner(self, banner):
        """Return list of dicts: product, version, cves[{id,desc,cvss}]."""
        if not banner:
            return []
        bl = banner.lower()
        results = []
        for prod_key, meta in self.cve_db.items():
            aliases = [prod_key] + list(meta.get("aliases", []))
            hit_alias = None
            for al in aliases:
                alw = al.lower()
                m = re.search(r"(?<![a-z0-9])" + re.escape(alw),
                              bl) if alw else None
                if m:
                    idx = m.start()
                    tail = banner[idx:idx + len(al) + 40]
                    hit_alias = (al, tail)
                    break
            if not hit_alias:
                continue
            vm = VERSION_RE.search(hit_alias[1][len(hit_alias[0]):])
            version = vm.group(1) if vm else ""
            cves = []
            for rng, entries in meta.get("ranges", {}).items():
                rc = RangeCheck(rng)
                if not rc.match(version):
                    continue
                if not isinstance(entries, list):
                    entries = [entries]
                for entry in entries:
                    parts = str(entry).split("|")
                    cid = parts[0].strip()
                    desc = parts[1].strip() if len(parts) > 1 else ""
                    cvss = float(parts[2]) if len(parts) > 2 else None
                    cves.append({"id": cid, "desc": desc, "cvss": cvss})
            if cves:
                cves.sort(key=lambda c: (c["cvss"] or 0), reverse=True)
                results.append({"product": meta.get("product", prod_key),
                                "version": version, "cves": cves})
        return results

    def plan_web_targets(self, target, services):
        web = []
        if target.kind == "url":
            web.append({"url": "%s://%s:%d%s" % (target.scheme, target.hostname,
                                                 target.port, target.path),
                        "primary": True})
        seen = set()
        for svc in services:
            if svc.get("service") in ("http", "https") or svc["port"] in HTTP_PORTS:
                scheme = "https" if svc["port"] == 443 or svc.get("tls") else "http"
                u = "%s://%s:%d/" % (scheme, svc["host"], svc["port"])
                if u not in seen and u != (web[0]["url"] if web else None):
                    seen.add(u)
                    web.append({"url": u, "primary": False})
        return web

    def suggest_modules(self, state):
        suggestions = []
        ports = {s["port"] for s in state.get("services", [])}
        if any(p in HTTP_PORTS or p in (80, 443, 8080, 8443, 8000, 8008, 5000, 3000) for p in ports):
            suggestions += ["web.crawl", "web.dirbuster", "web.headers",
                            "web.tech", "web.waf", "web.vulnscan", "web.js"]
        if 21 in ports:
            suggestions.append("network.brute")
        if 22 in ports:
            suggestions.append("network.brute")
        if any(p in HTTP_PORTS for p in ports):
            suggestions.append("exploit.default_creds")
        suggestions.append("exploit.verify_probes")
        return suggestions

    def score(self, findings):
        # Risk score weights severity by evidence confidence: proof-tested
        # ("certain") findings weigh most, pure signals ("tentative") least.
        conf_w = {"certain": 1.4, "firm": 1.2, "tentative": 1.0}
        total = sum(SEV_WEIGHT.get(f["severity"], 0)
                    * conf_w.get(f.get("confidence"), 1.0)
                    for f in findings)
        return min(100.0, round(total, 1))

    def summarize(self, stats, findings, services, targets):
        """Plain-language executive summary for non-technical readers."""
        lines = []
        crit = stats.get("critical", 0)
        high = stats.get("high", 0)
        med = stats.get("medium", 0)
        low = stats.get("low", 0)
        tgt = ", ".join(t.get("display", "?") for t in targets) or "N/A"
        lines.append(
            "What was checked: %d computer system(s) (%s) were examined for "
            "weaknesses that an outsider could use to break in, steal data "
            "or disrupt service."
            % (len(targets), tgt))
        if crit or high:
            if crit and high:
                level = "%d critical and %d serious" % (crit, high)
            elif crit:
                level = "%d critical" % crit
            else:
                level = "%d serious" % high
            lines.append(
                "Bottom line: %s weakness(es) were found. This is urgent — "
                "at least one could let an attacker take control of the "
                "system or steal data. Treat fixing them as an emergency "
                "and re-test when done." % level)
        elif med:
            lines.append(
                "Bottom line: no emergency-level weaknesses were found, but "
                "several medium concerns were detected. They should be "
                "fixed on a planned schedule before the system is exposed "
                "to users.")
        else:
            lines.append(
                "Bottom line: automated checks could not confirm any "
                "exploitable weakness. This is good news, but not a "
                "guarantee of safety — a manual expert review is still "
                "advised.")
        counts = []
        if crit:
            counts.append("%d critical" % crit)
        if high:
            counts.append("%d serious" % high)
        if med:
            counts.append("%d medium" % med)
        if low:
            counts.append("%d minor" % low)
        lines.append("Severity summary: %d finding(s) in total (%s)."
                     % (len(findings), ", ".join(counts)
                        if counts else "no confirmed issues"))
        if crit or high:
            top = sorted([f for f in findings
                          if f["severity"] in ("critical", "high")],
                         key=lambda f: SEV_RANK_ORDER[f["severity"]])[:4]
            lines.append("Most important findings (fix first):")
            for f in top:
                lines.append("  - [%s] %s" % (f["severity"].upper(),
                                              _plain_title(f["title"])))
        elif med:
            top = sorted([f for f in findings
                          if f["severity"] == "medium"],
                         key=lambda f: f["title"])[:4]
            lines.append("Medium concerns to schedule:")
            for f in top:
                lines.append("  - [medium] %s" % _plain_title(f["title"]))
        return "\n".join(lines)


    def next_actions(self, state, findings):
        """Campaign planner: ordered next-best actions from current intel."""
        actions = []
        blob = " | ".join(f["title"].lower() for f in findings)
        waf = state.get("waf")
        if "sql injection" in blob:
            actions.append("extract database fingerprint via UNION chain")
        if "command injection" in blob or state.get("channels"):
            actions.append("establish execution channel + post-exploit recon")
        if state.get("forms"):
            actions.append("attempt authentication bypass + credential attacks")
        if "tomcat manager" in blob:
            actions.append("app-server deployment RCE (needs --aggressive)")
        if any("ssrf" in f["module"] for f in findings):
            actions.append("pivot from SSRF into cloud metadata")
        if any(f["module"] == "web.jwt_audit" for f in findings):
            actions.append("forge JWTs with cracked/none algorithms")
        if any("graphql" in f["title"].lower() for f in findings):
            actions.append("mine introspected schema for mutations")
        if any(f["module"].startswith("ad.") for f in findings):
            actions.append("extend AD chain: kerberoast -> DCSync review")
        if waf and waf != "none":
            actions.append("evasion chains engaged against %s" % waf)
        if not actions:
            actions.append("deepen fuzzing on discovered parameters")
        return actions


SEV_RANK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _plain_title(t):
    t = (t or "").strip()
    return t if len(t) <= 96 else t[:93].rstrip() + "..."
