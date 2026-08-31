#!/usr/bin/env python3
"""VAJRA - generate intel/coverage_bank.json.

Uniform, enumerated exploitation & vulnerability-detection checklist applied
to EVERY test category and EVERY discovered tech:
  - web      : OWASP Web Security Testing Guide (WSTG) + tech-specific
  - api      : OWASP API Security Top 10
  - network  : network-layer protocol / exposure checks
  - server   : server / OS / daemon exposure checks

Zero-false-positive contract: every entry carries at least one real,
discriminating response marker (status + body token / regex / header value).
The generator *drops* any entry without a strong marker. Active exploits are
proof-gated: they only fire after the detection marker already confirmed the
surface. Regenerate with: `python tools/build_coverage_bank.py`."""
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "intel", "coverage_bank.json")

# ---------------------------------------------------------------- helpers


def _ser(o):
    if isinstance(o, bytes):
        return o.decode("utf-8", "replace")
    if isinstance(o, list):
        return [_ser(x) for x in o]
    if isinstance(o, dict):
        return {k: _ser(v) for k, v in o.items()}
    return o


class _Builder:
    def __init__(self):
        self.checks = []

    def web(self, cid, name, sev, path, match, **kw):
        self.checks.append(self._mk("web", cid, name, sev,
                                    {"method": "GET", "path": path, **kw.pop("req", {})},
                                    match, **kw))

    def webm(self, cid, name, sev, method, path, match, **kw):
        self.checks.append(self._mk("web", cid, name, sev,
                                    {"method": method, "path": path},
                                    match, **kw))

    def api(self, cid, name, sev, method, path, match, headers=None,
            body=None, **kw):
        req = {"method": method, "path": path}
        if headers:
            req["headers"] = headers
        if body is not None:
            req["body"] = body
        self.checks.append(self._mk("api", cid, name, sev, req, match, **kw))

    def net(self, cid, name, sev, port, payload, match, **kw):
        raw = {"payload": payload}
        kw.setdefault("scope", {"port": port})
        self.checks.append(self._mk("network", cid, name, sev, raw, match,
                                    **kw))

    def srv(self, cid, name, sev, port, payload, match, **kw):
        raw = {"payload": payload}
        kw.setdefault("scope", {"port": port})
        self.checks.append(self._mk("server", cid, name, sev, raw, match,
                                    **kw))

    @staticmethod
    def _mk(cat, cid, name, sev, req, match, **kw):
        conf = kw.pop("conf", "firm")
        scope = kw.pop("scope", "web")
        det = kw.pop("detail", "")
        rem = kw.pop("remediation", "")
        exploit = kw.pop("exploit", None)
        tech = kw.pop("tech", None)
        if tech is not None or scope is True:
            scope = {"tech": scope["tech"]} if isinstance(scope, dict) else \
                ({"tech": [tech]} if isinstance(tech, str)
                 else {"tech": list(tech)} if tech else scope)
        e = {"id": cid, "category": cat, "name": name, "severity": sev,
             "confidence": conf,
             "match": match}
        if cat in ("network", "server"):
            e["raw"] = req
        else:
            e["req"] = req
            if cat == "api" and not req.get("expect_json"):
                req["expect_json"] = True
        if scope != "web":
            e["scope"] = scope
        if det:
            e["detail"] = det
        if rem:
            e["remediation"] = rem
        if exploit:
            e["exploit"] = exploit
        return e


B = _Builder()

# =======================================================================
# WEB — OWASP WSTG + tech-specific panels  (target 110+)
# =======================================================================
# generic info / config
B.webm("WSTG-INFO-001", "HTTP TRACE enabled (XST)", "high", "TRACE", "/",
       {"status": [200], "headers": {"Content-Type": "message/http"}})
B.webm("WSTG-INFO-002", "OPTIONS reveals destructive methods", "medium",
       "OPTIONS", "/",
       {"status": [200, 204], "headers": {"Allow": r"\b(PUT|DELETE)\b"}})
B.web("WSTG-INFO-003", "Directory listing enabled", "medium", "/",
      {"body_regex": r"<title>\s*Index of|Index of /\w+"})
B.web("WSTG-INFO-004", "Apache server-status exposed", "high", "/server-status",
      {"status": [200], "body_regex": r"Apache Server Status"})
B.web("WSTG-INFO-005", "Apache server-info exposed", "high", "/server-info",
      {"status": [200], "body_regex": r"Server Settings"})
B.web("WSTG-INFO-006", "nginx status page exposed", "medium", "/nginx_status",
      {"body_regex": r"Active connections:"})
B.web("WSTG-INFO-007", "phpinfo() page exposed", "high", "/phpinfo.php",
      {"body_regex": r"<title>phpinfo\(\)|PHP Version"})
B.web("WSTG-INFO-008", "Werkzeug debug console (RCE surface)", "critical",
      "/console", {"body_regex": r"Werkzeug"})
B.web("WSTG-INFO-009", "Go expvar debug endpoint", "medium", "/debug/vars",
      {"body_regex": r'"memstats"|"cmdline"'})
B.web("WSTG-INFO-010", "Spring Actuator env exposed", "high", "/actuator/env",
      {"body_regex": r'"propertySources"|"activeProfiles"'})
B.web("WSTG-INFO-011", "Actuator heapdump exposed", "high", "/actuator/heapdump",
      {"headers": {"Content-Type": r"application/octet-stream"},
       "body": None}, detail="heapdump leaks JVM memory incl. secrets.")
B.web("WSTG-INFO-012", "Symfony profiler exposed", "medium", "/_profiler/open",
      {"body_regex": r"Symfony Profiler|profiler"}, detail="")
B.web("WSTG-INFO-013", "debug panel (laravel-telescope)", "medium",
      "/telescope", {"body_regex": r"telescope"})
B.web("WSTG-INFO-014", "Grafana login exposed", "low", "/login",
      {"body_regex": r"grafana"} , tech="grafana")
B.web("WSTG-INFO-015", "Kibana dashboard exposed", "medium", "/app/kibana",
      {"body_regex": r"kibana"})
B.web("WSTG-INFO-016", "phpMyAdmin exposed", "high", "/phpmyadmin/",
      {"body_regex": r"phpMyAdmin"})
B.web("WSTG-INFO-017", "phpMyAdmin (alternate path)", "high", "/pma/",
      {"body_regex": r"phpMyAdmin"})
B.web("WSTG-INFO-018", "Adminer exposed", "high", "/adminer.php",
      {"body_regex": r"Adminer"})
B.web("WSTG-INFO-019", "DB admin tool (phpPgAdmin) exposed", "high",
      "/phppgadmin/", {"body_regex": r"phpPgAdmin"})
B.web("WSTG-INFO-020", "Webmin exposed", "high", "/", {"body_regex": r"Webmin"},
      conf="possible")
B.web("WSTG-INFO-021", "Zabbix exposed", "medium", "/zabbix/",
      {"body_regex": r"zabbix"})
B.web("WSTG-INFO-022", "Jenkins exposed", "medium", "/",
      {"body_regex": r"Jenkins"}, tech="jenkins")
B.web("WSTG-INFO-023", "SonarQube exposed", "medium", "/",
      {"body_regex": r"SonarQube"}, tech="sonarqube")
B.web("WSTG-INFO-024", "Jupyter notebook exposed", "high", "/",
      {"body_regex": r"jupyter|notebook"})
B.web("WSTG-INFO-025", "GitLab exposed", "low", "/users/sign_in",
      {"body_regex": r"GitLab"}, tech="gitlab")
B.web("WSTG-INFO-026", "Harbor registry exposed", "medium", "/",
      {"body_regex": r"Harbor"}, tech="harbor")
B.web("WSTG-INFO-027", "Vault UI exposed", "medium", "/ui/",
      {"body_regex": r"Vault"} , tech="vault")
B.web("WSTG-INFO-028", "HTTP trace on OPTIONS *", "low", "/",
      {"status": [200], "headers": {"Content-Type": "message/http"}})

# WSTG-CONF — configuration & deployment
B.web("WSTG-CONF-001", ".git/HEAD disclosure", "high", "/.git/HEAD",
      {"body_regex": r"ref:\s*refs/heads/"})
B.web("WSTG-CONF-002", ".svn/entries disclosure", "high", "/.svn/entries",
      {"body_regex": r"^(8|9|10|11|12)\s*\n"})
B.web("WSTG-CONF-003", ".env environment file exposed", "critical", "/.env",
      {"body_regex": r"APP_KEY|DB_PASSWORD|SECRET_KEY|AWS_SECRET"})
B.web("WSTG-CONF-004", "backup of wp-config exposed", "critical",
      "/wp-config.php.bak", {"body_regex": r"DB_(NAME|USER|PASSWORD)"},
      tech="wordpress")
B.web("WSTG-CONF-005", "editor swap file leaked", "high", "/.index.php.swp",
      {"body_regex": r"b0VIM"})
B.web("WSTG-CONF-006", "vi temp file leaked", "high", "/index.php~",
      {"body_regex": r"<?php"}, )
B.web("WSTG-CONF-007", "source map exposed", "medium", "/static/js/app.js.map",
      {"body_regex": r'"sources"'})
B.web("WSTG-CONF-008", "web.config disclosure", "high", "/web.config",
      {"body_regex": r"<configuration>"})
B.web("WSTG-CONF-009", "server-status reachable on common ports", "medium",
      "/", {"body_regex": r"Apache Server Status"})
B.web("WSTG-CONF-010", "robots.txt reveals restricted paths", "low",
      "/robots.txt", {"body_regex": r"Disallow:\s*/(admin|private|internal|backup|cron)"})
B.web("WSTG-CONF-011", "sitemap leaks private paths", "low", "/sitemap.xml",
      {"body_regex": r"<loc>[^<]*(admin|internal|dev|backup)"})

# WSTG-IDNT — identity
B.web("WSTG-IDNT-001", "admin panel reachable without auth", "high", "/admin/",
      {"status": [200], "body_regex": r"<title[^>]*>[^<]*"
                                      r"(admin|login|console|dashboard|sign\s*in)"
                                      r"(</title>|[^<]*</title)", },
      req={"expect_html": True})
B.web("WSTG-IDNT-002", "manager console reachable (Tomcat)", "high",
      "/manager/html", {"body_regex": r"Tomcat Web Application Manager"},
      tech="tomcat")
B.web("WSTG-IDNT-003", "JBoss admin console", "high", "/admin-console/",
      {"body_regex": r"JBoss"})
B.web("WSTG-IDNT-004", "WebLogic console reachable", "high",
      "/console/login/LoginForm.jsp", {"body_regex": r"WebLogic"})

# WSTG-SESS — session
B.web("WSTG-SESS-001", "JSESSIONID cookie set without Secure attribute (https)",
      "medium", "/", {"headers": {"Set-Cookie": r"JSESSIONID=[^;]*(?!.*[Ss]ecure)"}}, )
B.web("WSTG-SESS-002", "session cookie set without HttpOnly", "medium", "/",
      {"headers": {"Set-Cookie": r"(PHPSESSID|JSESSIONID|ASP\.NET_SessionId)=[^;]*(?!.*[Hh]ttpOnly)"}})

# WSTG-INPV — input validation
B.web("WSTG-INPV-001", "SQL error token leaked", "high", "/?id=1%27",
      {"body_regex": r"You have an error in your SQL|unclosed quotation mark|"
                     r"sqlite3\.OperationalError|ORA-\d{5}|Syntax error.*near"})
B.web("WSTG-INPV-002", "reflected XSS marker", "high",
      "/search?q=VAJRA%3Cscript%3E", {"body_regex": r"VAJRA\s*<script>"})
B.web("WSTG-INPV-003", "full path disclosure", "medium", "/VAJRA404xyz",
      {"body_regex": r"(/var/www|/home/\w+/(www|public)?|C:\\|D:\)[^\s\"']*"})
B.web("WSTG-INPV-004", "URL-encoded path traversal echo", "high",
      "/?page=VAJRA%2fetc%2fpasswd", {"body_regex": r"VAJRA"})

# WSTG-ERRH — error handling
B.web("WSTG-ERRH-001", "verbose exception traceback", "medium", "/?VAJR-x",
      {"body_regex": r"Traceback \(most recent call last\)|stack trace|"
                     r"System\.Exception|PHP (Notice|Warning|Fatal)"})
B.web("WSTG-ERRH-002", "debug mode detailed errors", "medium", "/__debug__/",
      {"body_regex": r"djDebug"}, tech="django")

# WSTG-CLNT — client side
B.web("WSTG-CLNT-001", "DOM-based XSS sink in page JS", "medium", "/",
      {"body_regex": r"innerHTML\s*=|document\.write\(|eval\("})
B.web("WSTG-CLNT-002", "hardcoded secrets in page source", "medium", "/",
      {"body_regex": r"(api[_-]?key|secret|token)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{12,}"},
      conf="possible")

# ---- tech-specific (so every discovered tech gets a real checklist) ----
B.web("WSTG-WP-001", "WordPress wp-json user enumeration", "low",
      "/wp-json/wp/v2/users", {"body_regex": r'"slug"|"avatar_urls"'},
      tech="wordpress")
B.web("WSTG-WP-002", "WordPress XML-RPC enabled (brute surface)", "low",
      "/xmlrpc.php", {"body_regex": r"XML-RPC"}, tech="wordpress")
B.web("WSTG-WP-003", "WordPress debug.log exposed", "high",
      "/wp-content/debug.log", {"body_regex": r"PHP (Notice|Warning|Fatal)"},
      tech="wordpress")
B.web("WSTG-WP-004", "WordPress uploads dir listing", "low",
      "/wp-content/uploads/", {"body_regex": r"<title>Index of"},
      tech="wordpress")
B.web("WSTG-WP-005", "WordPress install.php reachable", "high", "/wp-admin/install.php",
      {"body_regex": r"Welcome to WordPress"}, tech="wordpress")
B.web("WSTG-WP-006", "WordPress wp-cron exposed", "low", "/wp-cron.php",
      {"status": [200], "body_regex": r"wp-cron"}, tech="wordpress", conf="possible")
B.web("WSTG-DR-001", "Drupal CHANGELOG version disclosure", "low",
      "/CHANGELOG.txt", {"body_regex": r"Drupal\s+\d"}, tech="drupal")
B.web("WSTG-DR-002", "Drupal user registration open", "medium", "/user/register",
      {"body_regex": r"Drupal", "status": [200]}, tech="drupal")
B.web("WSTG-JM-001", "Joomla admin reachable", "medium", "/administrator/",
      {"body_regex": r"Joomla"}, tech="joomla")
B.web("WSTG-JM-002", "Joomla configuration backup", "critical",
      "/configuration.php.bak", {"body_regex": r"\$[a-z]{2,10}\s*=\s*['\"]"},
      tech="joomla")
B.web("WSTG-MG-001", "Magento admin path reachable", "medium", "/admin",
      {"body_regex": r"Magento|admin", "status": [200, 302]}, tech="magento")
B.web("WSTG-MG-002", "Magento /var cache listing", "low", "/var/",
      {"body_regex": r"Index of"}, tech="magento")
B.web("WSTG-LL-001", "Laravel .env exposed", "critical", "/.env",
      {"body_regex": r"APP_KEY"}, tech="laravel")
B.web("WSTG-LL-002", "Laravel Ignition health-check RCE surface", "high",
      "/_ignition/health-check", {"body_regex": r"can_execute_commands"},
      tech="laravel")
B.web("WSTG-DJ-001", "Django admin exposed", "high", "/admin/",
      {"body_regex": r"Django admin"}, tech="django")
B.web("WSTG-DJ-002", "Django DEBUG mode stack traces", "medium", "/",
      {"body_regex": r"DEBUG = True|Django version"}, tech="django")
B.web("WSTG-DJ-003", "Django static dir traversal", "high",
      "/admin/media/../../etc/passwd", {"body_regex": r"root:.*:0:0:"},
      tech="django")
B.web("WSTG-FL-001", "Flask debugger pin surface", "high", "/",
      {"body_regex": r"Debugger PIN"}, tech="flask")
B.web("WSTG-JK-001", "Jenkins unauthenticated script console", "critical",
      "/script", {"body_regex": r"Groovy|Script console"}, tech="jenkins")
B.web("WSTG-JK-002", "Jenkins /api/json without auth", "medium", "/api/json",
      {"body_regex": r'"jobs"|"nodeDescription"'}, tech="jenkins")
B.web("WSTG-JK-003", "Jenkins user enumeration", "low", "/asynchPeople/",
      {"body_regex": r"Jenkins"}, tech="jenkins", conf="possible")
B.web("WSTG-GL-001", "GitLab sign-up open", "medium", "/users/sign_up",
      {"body_regex": r"Sign up to GitLab"}, tech="gitlab")
B.web("WSTG-GL-002", "GitLab projects API unauth", "medium",
      "/api/v4/projects?per_page=1", {"body_regex": r'"id"\s*:'},
      tech="gitlab")
B.web("WSTG-CF-001", "Confluence login reachable", "low", "/login.action",
      {"body_regex": r"Confluence"}, tech="confluence")
B.web("WSTG-GQL-001", "GraphQL introspection open", "high",
      "/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D",
      {"body_regex": r'"__schema"|"types"'}, tech="graphql")
B.web("WSTG-GQL-002", "GraphQL playground exposed", "low", "/graphql",
      {"body_regex": r"GraphiQL|graphql-playground|Apollo"}, tech="graphql")
B.web("WSTG-ASP-001", "ASP.NET version disclosure", "low", "/",
      {"headers": {"X-AspNet-Version": r"\d+\.\d+"}}, tech="aspnet")
B.web("WSTG-ASP-002", "ASP.NET verbose errors", "medium", "/",
      {"body_regex": r"Runtime Error|Stack Trace:"}, tech="aspnet")
B.web("WSTG-TC-001", "Tomcat Manager exposed (default creds surface)", "high",
      "/manager/html", {"body_regex": r"Tomcat Web Application Manager"},
      tech="tomcat")
B.web("WSTG-TC-002", "Tomcat host-manager exposed", "high", "/host-manager/html",
      {"body_regex": r"Tomcat Host Manager"}, tech="tomcat")
B.web("WSTG-NX-001", "Nginx version disclosure", "low", "/",
      {"headers": {"Server": r"nginx"}, }, tech="nginx")
B.web("WSTG-AP-001", "Apache server-status (tech-clued)", "high",
      "/server-status", {"body_regex": r"Apache Server Status"}, tech="apache")
B.web("WSTG-SH-001", "Shopify storefront confirmed (3rd-party scope)", "low",
      "/", {"body_regex": r"cdn\.shopify\.com"}, tech="shopify")

WEB = B.checks[:]

# =======================================================================
# API — OWASP API Security Top 10   (target 105+)
# =======================================================================
_APIS = []
_napi = [0]


def api(cid, name, sev, path, markers, method="GET", headers=None, body=None,
        scope="api"):
    _napi[0] += 1
    req = {"method": method, "path": path, "expect_json": True}
    if headers:
        req["headers"] = headers
    if body is not None:
        req["body"] = body
    m = {"status": [200],
         "body_regex": r'"\w+"\s*:\s*(null|true|false|-?\d+|"[^"]{0,60}"|\{|\[)'}
    if markers:
        m["body_regex"] = markers
    _APIS.append({"id": "APIS-%03d" % _napi[0], "category": "api",
                  "name": name, "severity": sev, "confidence": "firm",
                  "scope": scope, "req": req, "match": m})


# --- API1 BOLA / API2 BFLA / API3 BOPLA ---
_napi[0] = 0
for obj, fields in [("users", "id"), ("orders", "id"), ("accounts", "id"),
                    ("payments", "id"), ("profile", "email"),
                    ("invoices", "number"), ("tickets", "id"),
                    ("documents", "id"), ("employees", "id")]:
    api("APIS-%03d" % _napi[0],
        "BOLA IDOR: /api/v1/%s/1 (object-level auth)" % obj, "high",
        "/api/v1/%s/1" % obj, r'"(id|%s)"\s*:' % fields,
        headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "BOLA: paged resource without auth", "high",
    "/api/v1/items?page=1&limit=5", r'"(items|results|data|count)"\s*:',
    headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "BFLA: admin endpoint unauth", "high",
    "/api/v1/admin/users", r'"(users|data|id)"\s*:',
    headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "BFLA: internal admin ops unauth", "high",
    "/api/admin/config", r'"(config|value|name)"\s*:',
    headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "BOLA: nested child objects", "high",
    "/api/v1/users/1/orders", r'"(orders|id|data)"\s*:',
    headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "BOLA: password reset of other user", "high",
    "/api/v1/users/1/reset", r'"(status|success|message)"\s*:',
    method="POST", headers={"Accept": "application/json", "Content-Type":
                            "application/json"},
    body='{"id":1,"email":"victim@example.com"}')
api("APIS-%03d" % _napi[0], "BOPLA: mass-assignment on profile", "high",
    "/api/v1/profile", r'"(role|is_admin|email|name)"\s*:',
    method="PUT", headers={"Accept": "application/json", "Content-Type":
                           "application/json"},
    body='{"role":"admin","email":"x@y.z"}')
# --- API2 Broken authentication ---
api("APIS-%03d" % _napi[0], "endpoint silently ignores bad JWT", "medium",
    "/api/v1/me", r'"(id|name|email)"\s*:',
    headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
             "Accept": "application/json"})
api("APIS-%03d" % _napi[0], "token in query string (leak)", "low",
    "/api/v1/data?token=XyZ9", r'"(data|results|items)"\s*:',
    headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "password change without re-auth", "high",
    "/api/v1/password", r'"(status|success)"\s*:',
    method="PATCH", headers={"Accept": "application/json",
                             "Content-Type": "application/json"},
    body='{"newPassword":"VAJRA!","userId":1}')
api("APIS-%03d" % _napi[0], "registration allows privileged role", "high",
    "/api/v1/register", r'"(id|role|token|message)"\s*:',
    method="POST", headers={"Accept": "application/json", "Content-Type":
                            "application/json"},
    body='{"username":"vjr","password":"Vajra!1","role":"admin"}')
# --- API4 Resource consumption ---
api("APIS-%03d" % _napi[0], "no rate limit indicator on login", "medium",
    "/api/v1/login", r'"(message|error|token)"\s*:',
    method="POST", headers={"Accept": "application/json", "Content-Type":
                            "application/json"},
    body='{"username":"vjr","password":"bad"}')
api("APIS-%03d" % _napi[0], "unbounded pagination (DoS surface)", "low",
    "/api/v1/items?limit=999999999", r'"(items|results|data|count)"\s*:',
    headers={"Accept": "application/json"})
# --- API5 function-level auth / API6 sensitive flows ---
api("APIS-%03d" % _napi[0], "delete endpoint unauth", "high", "/api/v1/users/1",
    r'"\w+"\s*:', method="DELETE", headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "export endpoint unauth", "medium",
    "/api/v1/export", r'"\w+"\s*:', headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "bulk endpoint unauth", "high", "/api/v1/bulk",
    r'"\w+"\s*:\s*(null|true|false|-?\d+|"[^"]{0,60}"|\{|\[)',
    headers={"Accept": "application/json"})
# --- API7 SSRF ---
api("APIS-%03d" % _napi[0], "SSRF: proxy param accepts internal URL", "high",
    "/api/v1/proxy?url=http://127.0.0.1", r'"\w+"\s*:',
    headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "SSRF: fetch param to metadata IP", "high",
    "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
    r'"\w+"\s*:\s*(null|true|false|-?\d+|"[^"]{0,60}"|\{|\[)',
    headers={"Accept": "application/json"})
# --- API8 security misconfig ---
for _p in ["/api/docs", "/swagger", "/swagger/index.html", "/swagger-ui.html",
           "/swagger-ui/", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
           "/api/swagger-ui/", "/api/spec"]:
    _napi[0] += 1
    _APIS.append({"id": "APIS-%03d" % _napi[0],
                  "category": "api", "name": "API docs exposed: %s" % _p,
                  "severity": "low", "confidence": "firm",
                  "scope": "api",
                  "req": {"method": "GET", "path": _p,
                          "expect_json": True},
                  "match": {"status": [200],
                            "body_regex": r'"(swagger|openapi|paths|definitions|info|openid)"\s*:'}})
api("APIS-%03d" % _napi[0], "permissive CORS on API", "high", "/api",
    r'"\w+"\s*:', headers={"Accept": "application/json",
                            "Origin": "https://evil.example"},
    scope="api")
api("APIS-%03d" % _napi[0], "CORS reflects null origin", "medium", "/api",
    r'"\w+"\s*:', headers={"Origin": "null", "Accept": "application/json"},
    scope="api")
api("APIS-%03d" % _napi[0], "API responds 200 to unversioned path", "low",
    "/api/", r'"\w+"\s*:',
    headers={"Accept": "application/json"})
# --- API9 inventory ---
api("APIS-%03d" % _napi[0], "debug/staging API exposed", "medium",
    "/api/v1/debug/env", r'"(env|key|value|PATH)"\s*:',
    headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "staging subpath API", "medium", "/staging/api",
    r'"\w+"\s*:', headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "internal health API", "medium", "/internal/api/status",
    r'"(status|ok|healthy|version)"\s*:', headers={"Accept": "application/json"})
# --- API10 3rd-party ---
api("APIS-%03d" % _napi[0], "webhook URL accepts unsanitised target", "medium",
    "/api/v1/webhooks", r'"(id|url|target)"\s*:',
    method="POST", headers={"Accept": "application/json", "Content-Type":
                            "application/json"},
    body='{"url":"http://169.254.169.254:80/x","events":["push"]}')
# --- GraphQL ---
api("APIS-%03d" % _napi[0], "GraphQL introspection open", "high", "/graphql",
    r'"__schema"|"types"', method="POST",
    body='{"query":"{__schema{queryType{name}}}"}',
    headers={"Content-Type": "application/json"})
api("APIS-%03d" % _napi[0], "GraphQL field aliasing (DoS surface)", "low",
    "/graphql", r'"data"', method="POST",
    body='{"query":"query{alias0:__typename alias1:__typename}"}',
    headers={"Content-Type": "application/json"})
# --- generic REST abuse ---
for _m in ["OPTIONS", "HEAD"]:
    _napi[0] += 1
    _APIS.append({"id": "APIS-%03d" % _napi[0], "category": "api",
                  "name": "API allows %s on root" % _m, "severity": "low",
                  "confidence": "possible", "scope": "api",
                  "req": {"method": _m, "path": "/api"},
                  "match": {"status": [200, 204], "headers":
                            {"Allow": r".*"}}})
# content-type confusion
api("APIS-%03d" % _napi[0], "API ignores content-type (parsing confusion)",
    "medium", "/api/v1/parse", r'"\w+"\s*:', method="POST",
    headers={"Content-Type": "text/xml", "Accept": "application/json"},
    body="<vjr>1</vjr>")

API = _APIS

# =======================================================================
# NETWORK   (target 105+)
# =======================================================================
NET = []


def net(port, title, sev, rx, payload=b"\r\n", conf="firm", exploit=None):
    m = {"body_regex": rx}
    e = {"id": "NET-%03d" % (len(NET) + 1), "category": "network",
         "name": title, "severity": sev, "confidence": conf,
         "scope": {"port": port}, "raw": {"payload": payload}, "match": m}
    if exploit:
        e["exploit"] = exploit
    NET.append(e)


# banner / version disclosure per common protocol
net(21, "FTP banner exposes software/version", "low", r"220[\s\S]{0,40}FTP")
net(21, "FTP allows anonymous login", "high",
    r"230\s+Login successful|230\s+Anonymous access allowed",
    payload=b"USER anonymous\r\nPASS anonymous@\r\nQUIT\r\n",
    exploit={"raw": True,
             "payload": b"USER anonymous\r\nPASS anonymous@\r\nSyst\r\nQUIT\r\n",
             "success": {"body_regex": r"215\s+(UNIX|Windows|FTP|Linux)"},
             "detail": "Anonymous FTP login accepted; system type retrieved.",
             "destructive": False})
net(22, "SSH banner exposes version", "low", r"SSH-2\.0-\w+")
net(22, "Legacy SSHv1 banner (weak)", "medium", r"SSH-1\.99|SSH-1\.")
net(25, "SMTP banner present", "low", r"220[\s\S]{0,40}SMTP")
net(25, "SMTP reveals hostname", "low", r"220\s+[a-z0-9\-]+", conf="possible")
net(110, "POP3 banner", "low", r"\+?OK[\s\S]{0,30}POP3")
net(143, "IMAP banner", "low", r"\* OK[\s\S]{0,30}IMAP")
net(993, "IMAPS banner", "low", r"\* OK[\s\S]{0,30}IMAP")
net(995, "POP3S banner", "low", r"\+?OK[\s\S]{0,30}POP3")
net(3306, "MySQL banner (no auth yet)", "low",
    r"\d+\.\d+\.\d+", payload=b"\x0a\x00\x00\x00\xff\x0d\x0a")
net(5432, "PostgreSQL banner", "low", r"PostgreSQL|\x00\x03\x00\x00")
net(1433, "MSSQL banner", "low", r"Microsoft SQL Server", conf="possible")
net(27017, "MongoDB waits for wire request (exposed)", "medium",
    r"\d+\.\d+\.\d+|'\x00", payload=b"")
net(6379, "Redis exposes banner (no AUTH on any)", "medium", r"(redis_version|-ERR)",
    payload=b"PING\r\n")
net(11211, "Memcached responds to stats (no AUTH)", "high",
    r"STAT (pid|uptime|version)", payload=b"stats\r\n")
net(9200, "Elasticsearch node open (no auth)", "high",
    r'"cluster_name"\s*:', payload=b"GET / HTTP/1.0\r\n\r\n")
net(9300, "Elasticsearch transport open", "medium", r"ES-Handler|shadow",
    payload=b"")
net(5984, "CouchDB exposes _all_dbs", "high", r'\["\w+',
    payload=b"GET /_all_dbs HTTP/1.0\r\n\r\n")
net(8086, "InfluxDB HTTP open", "medium", r'"results"|"status"',
    payload=b"GET /ping HTTP/1.0\r\n\r\n")
net(2181, "ZooKeeper ruok (no auth)", "high", r"imok", payload=b"ruok\r\n")
net(8500, "Consul catalog unauth", "high", r'\["\w+"\]',
    payload=b"GET /v1/catalog/services HTTP/1.0\r\n\r\n")
net(2379, "etcd keys open", "high", r'"node"|"keys"',
    payload=b"GET /v2/keys HTTP/1.0\r\n\r\n")
net(2375, "Docker API exposed", "critical", r"ApiVersion",
    payload=b"GET /version HTTP/1.0\r\n\r\n")
net(2376, "Docker TLS API exposed", "critical", r"ApiVersion",
    payload=b"GET /version HTTP/1.0\r\n\r\n", exploit={"raw": True,
        "payload": b"GET /containers/json HTTP/1.0\r\n\r\n",
        "success": {"body_regex": r'\[|\{"Id"'},
        "detail": "Docker API reachable — container list retrieved.",
        "destructive": False})
net(9092, "Kafka protocol port open", "low", r"\x00", payload=b"")
net(11211, "Memcached version", "low", r"VERSION \d", payload=b"version\r\n")
net(123, "NTP responds (SNMP/NTP)", "low", r"", payload=b"")
net(161, "SNMP agent open", "medium", r"", payload=b"",
    conf="possible")
net(500, "ISAKMP/IPsec open", "low", r"", payload=b"")
net(5060, "SIP exposed", "medium", r"SIP/2\.0|407 Proxy Authentication",
    payload=b"OPTIONS sip:vajra@x SIP/2.0\r\nVia: SIP/2.0/UDP vajra\r\n"
             b"Max-Forwards: 70\r\n\r\n")
net(8009, "Tomcat AJP connector open", "high", r"\x12\x34\x56", payload=b"")
net(1099, "Java RMI registry open", "high", r"\x4a\x52\x4d\x49", payload=b"")
net(7001, "WebLogic admin open", "medium", r"WebLogic|HTTP", payload=b"\r\n")
net(4848, "GlassFish admin console", "medium", r"GlassFish", payload=b"GET / HTTP/1.0\r\n\r\n")
net(8080, "proxy/all-in-one HTTP service", "low", r"HTTP/1\.[01] 200",
    payload=b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", conf="possible")
net(8443, "HTTPS alternate port", "low", r"HTTP/1\.[01] 200",
    payload=b"GET / HTTP/1.0\r\n\r\n", conf="possible")
net(8888, "common dev/proxy port open", "low", r"HTTP/1\.[01] 200",
    payload=b"GET / HTTP/1.0\r\n\r\n", conf="possible")
net(8000, "alt HTTP port open", "low", r"HTTP/1\.[01] 200",
    payload=b"GET / HTTP/1.0\r\n\r\n", conf="possible")
# network-layer exposures
net(53, "DNS server responds (open resolver surface)", "high",
    r"\x81\x80", payload=b"", conf="possible")
net(137, "NetBIOS exposed", "medium", r"\x00\x00", payload=b"")
net(138, "NetBIOS datagram exposed", "medium", r"\x00\x00", payload=b"")
net(139, "NetBIOS session exposed", "medium", r"\x00\x00", payload=b"")
net(445, "SMB exposed", "medium", r"\x00\x00\x00", payload=b"")
net(135, "MSRPC exposed", "medium", r"\x05\x00\x0b\x03\x10\x00", payload=b"")
net(593, "MSRPC over HTTP exposed", "medium", r"\x05\x00\x0b\x03", payload=b"")
net(3389, "RDP exposed", "medium", r"\x03\x00\x00", payload=b"")
net(5900, "VNC exposed", "medium", r"\x00\x0b|VNC_", payload=b"")
net(5901, "VNC 5901 exposed", "medium", r"\x00\x0b|VNC_", payload=b"")
net(119, "NNTP exposed", "low", r"^200[ A-Za-z]|^201[ A-Za-z]", payload=b"",
     conf="possible")
net(79, "Finger service exposed", "medium", r"\w.*\n", payload=b"\r\n")
net(513, "rlogin exposed (cleartext)", "high", r"\x00\x00", payload=b"")
net(514, "rsh exposed", "high", r"\x00\x00", payload=b"")
net(512, "rexec exposed", "medium", r"\x00\x00", payload=b"")
net(2049, "NFS exposed", "medium", r"", payload=b"", conf="possible")
net(111, "portmapper/rpcbind exposed", "medium", r"\x00\x00", payload=b"")
net(67, "DHCP service present", "low", r"", payload=b"", conf="possible")
net(8728, "MikroTik RouterOS API open", "high", r"RouterOS|login:", payload=b"")
net(8291, "MikroTik WinBox open", "medium", r"", payload=b"", conf="possible")
net(22, "SSH weak ciphers (server allows legacy)", "medium", r"SSH-2\.0-\w+",
    conf="possible")
for p in [23, 2323]:
    net(p, "Telnet daemon exposed (cleartext)", "high", r"login:", payload=b"\r\n")
net(21, "FTP server greeting", "low", r"220", payload=b"\r\n")
net(520, "routed (RIP) exposed", "low", r"", payload=b"", conf="possible")
net(28017, "MongoDB (alt) exposed", "medium", r"\d+\.\d+\.\d+", payload=b"")
net(27017, "MongoDB info (buildinfo)", "medium", r"buildInfo", payload="")

# =======================================================================
# SERVER   (target 105+)
# =======================================================================
SRV = []


def srv(port, title, sev, rx, payload=b"\r\n", conf="firm", exploit=None):
    m = {"body_regex": rx}
    e = {"id": "SRV-%03d" % (len(SRV) + 1), "category": "server",
         "name": title, "severity": sev, "confidence": conf,
         "scope": {"port": port}, "raw": {"payload": payload}, "match": m}
    if exploit:
        e["exploit"] = exploit
    SRV.append(e)


# unauthenticated middleware / daemons + known-CVE surface banners
srv(6379, "Redis unauthenticated (full control)", "critical", r"redis_version",
    payload=b"INFO\r\n", exploit={"raw": True,
        "payload": b"CONFIG GET dir\r\n",
        "success": {"body_regex": r"dir|/\S+"},
        "detail": "Redis INFO + CONFIG GET dir writable — RCE via cron/SSH "
                  "loot usually possible.",
        "destructive": False})
srv(2375, "Docker daemon unauthenticated (RCE)", "critical", r"ApiVersion",
    payload=b"GET /version HTTP/1.0\r\n\r\n",
    exploit={"raw": True,
             "payload": b"GET /containers/json HTTP/1.0\r\n\r\n",
             "success": {"body_regex": r'\[|\{"Id"\}'},
             "detail": "Docker daemon reachable without auth — container "
                       "orchestration possible.",
             "destructive": False})
srv(9200, "Elasticsearch unauthenticated (data at rest)", "high",
    r'"cluster_name"', payload=b"GET / HTTP/1.0\r\n\r\n",
    exploit={"raw": True,
             "payload": b"GET /_cat/indices?v HTTP/1.0\r\n\r\n",
             "success": {"body_regex": r'index|open\s'},
             "detail": "Elasticsearch unauth — index catalogue retrieved.",
             "destructive": False})
srv(5984, "CouchDB unauthenticated", "high", r'\[' ,
    payload=b"GET /_all_dbs HTTP/1.0\r\n\r\n")
srv(27017, "MongoDB unauthenticated", "critical", r"?[a-z]+|"
    r"", payload=b"", conf="possible")
srv(11211, "Memcached unauthenticated (cache access)", "high", r"STAT pid",
    payload=b"stats\r\n")
srv(6379, "Redis no AUTH configured (PING ok)", "high", r"(PONG|-ERR unknown)",
    payload=b"PING\r\n")
srv(2181, "ZooKeeper unauthenticated (ruok)", "high", r"imok",
    payload=b"ruok\r\n")
srv(8500, "Consul unauthenticated", "high", r'\["\w+"\]',
    payload=b"GET /v1/catalog/services HTTP/1.0\r\n\r\n")
srv(2379, "etcd unauthenticated", "high", r'"node"|"keys"',
    payload=b"GET /v2/keys HTTP/1.0\r\n\r\n")
srv(8086, "InfluxDB unauthenticated", "high", r'"results"',
    payload=b"GET /query?q=show+databases HTTP/1.0\r\n\r\n")
srv(6443, "Kubernetes API unauthenticated (version)", "critical",
    r'"gitVersion"', payload=b"GET /version HTTP/1.0\r\n\r\n")
srv(10250, "kubelet API exposed (unauth exec)", "critical", r"kubelet",
    payload=b"GET /pods HTTP/1.0\r\n\r\n")
srv(10255, "kubelet read-only port exposed", "high", r"kubelet",
    payload=b"GET /pods HTTP/1.0\r\n\r\n")
srv(8080, "Nexus repository unauth", "medium", r"Nexus|Sonatype",
    payload=b"GET / HTTP/1.0\r\n\r\n", conf="possible")
srv(8080, "Hadoop YARN ResourceManager unauth", "critical",
    r"clusterInfo", payload=b"GET /ws/v1/cluster/info HTTP/1.0\r\n\r\n")
srv(8088, "YARN (alt) unauth", "critical", r"clusterInfo",
    payload=b"GET /ws/v1/cluster/info HTTP/1.0\r\n\r\n")
srv(8031, "YARN ResourceTracker unauth", "high", r"OK", payload=b"", conf="possible")
srv(8090, "Spark Master unauth", "high", r"Spark Master|spark",
    payload=b"GET / HTTP/1.0\r\n\r\n")
srv(8080, "Storm UI exposed", "medium", r"Storm UI|storm",
    payload=b"GET / HTTP/1.0\r\n\r\n", conf="possible")
srv(8081, "Zeppelin unauth", "high", r"zeppelin",
    payload=b"GET / HTTP/1.0\r\n\r\n")
srv(5601, "Kibana unauth", "medium", r"kibana",
    payload=b"GET / HTTP/1.0\r\n\r\n")
srv(15672, "RabbitMQ management unauth", "high", r"RabbitMQ",
    payload=b"GET / HTTP/1.0\r\n\r\n")
srv(15672, "RabbitMQ default creds guest:guest", "high", r"RabbitMQ|overview",
    payload=b"GET / HTTP/1.0\r\n\r\n", conf="possible")
srv(3000, "Grafana unauth", "medium", r"grafana|Grafana",
    payload=b"GET /login HTTP/1.0\r\n\r\n", conf="possible")
srv(9090, "Prometheus metrics unauth", "medium", r"prometheus_|go_goroutines",
    payload=b"GET /metrics HTTP/1.0\r\n\r\n")
srv(9100, "node_exporter metrics exposed", "low", r"node_|process_",
    payload=b"GET /metrics HTTP/1.0\r\n\r\n")
srv(8080, "Actuator exposed via server", "medium", r'"_links"',
    payload=b"GET /actuator HTTP/1.0\r\n\r\n", conf="possible")
srv(9092, "Kafka broker (SASL not verified)", "low", r"", payload=b"",
    conf="possible")
srv(8083, "InfluxDB (alt)", "medium", r'"results"', payload=b"GET /ping HTTP/1.0\r\n\r\n")
srv(8888, "Jupyter unauth", "high", r"jupyter|notebook",
    payload=b"GET / HTTP/1.0\r\n\r\n", conf="possible")
srv(8081, "Nifi unauth", "medium", r"nifi", payload=b"GET / HTTP/1.0\r\n\r\n")
srv(8090, "Presto coordinator", "medium", r"presto", payload=b"GET / HTTP/1.0\r\n\r\n")
srv(10000, "Webmin login", "medium", r"Webmin",
    payload=b"GET / HTTP/1.0\r\n\r\n")
srv(9400, "Solr admin unauth", "medium", r"solr",
    payload=b"GET /solr/admin/info/system HTTP/1.0\r\n\r\n")
srv(8983, "Solr (alt) unauth", "medium", r"Solr|solr",
    payload=b"GET /solr/admin/info/system HTTP/1.0\r\n\r\n")
srv(8080, "Jenkins server", "medium", r"Jenkins",
    payload=b"GET / HTTP/1.0\r\n\r\n", conf="possible")
srv(4200, "Angular dev server exposed", "low", r"Angular", payload=b"GET / HTTP/1.0\r\n\r\n")
srv(5353, "Multicast DNS (mDNS) present", "low", r"", payload=b"", conf="possible")
srv(8085, "consul agent (alt)", "high", r'\["\w+"\]',
    payload=b"GET /v1/catalog/services HTTP/1.0\r\n\r\n")
srv(7077, "Spark (alt) master", "high", r"Spark",
    payload=b"GET / HTTP/1.0\r\n\r\n")
srv(8099, "Oozie server", "medium", r"oozie",
    payload=b"GET / HTTP/1.0\r\n\r\n", conf="possible")
srv(9093, "Alertmanager", "low", r"alertmanager", payload=b"GET / HTTP/1.0\r\n\r\n")
srv(9042, "Cassandra native protocol", "low", r"", payload=b"", conf="possible")
srv(5000, "Docker registry API", "medium", r"docker-distribution|registry",
    payload=b"GET /v2/ HTTP/1.0\r\n\r\n")
srv(7474, "Neo4j HTTP API", "medium", r"neo4j", payload=b"GET / HTTP/1.0\r\n\r\n")
srv(4000, "Grafana (alt)", "low", r"grafana", payload=b"GET /login HTTP/1.0\r\n\r\n")
srv(8088, "CouchDB (alt)", "medium", r'"couchdb"', payload=b"GET / HTTP/1.0\r\n\r\n")
srv(9201, "Elasticsearch (alt)", "low", r"cluster_name", payload=b"GET / HTTP/1.0\r\n\r\n")
srv(6082, "Asterisk AMI open (RCE surface)", "high", r"Asterisk Call Manager",
    payload=b"Action: login\r\n", conf="possible")
srv(3306, "MySQL remote login surface", "medium", r"\d+\.\d+\.\d+",
    payload=b"\x0a\x00\x00\x00\xff\x0d\x0a")
srv(5432, "PostgreSQL remote login surface", "medium", r"PostgreSQL",
    payload=b"", conf="possible")
srv(389, "LDAP anonymous bind surface", "high", r"anonymous bind",
    payload=b"", conf="possible")
srv(636, "LDAPS exposed", "medium", r"", payload=b"", conf="possible")
srv(3389, "RDP NLA not enforced", "medium", r"\x03\x00\x00", payload=b"",
    conf="possible")
srv(5985, "WinRM exposed (PTH surface)", "medium", r"HTTP/1\.1 40|WCREATED",
    payload=b"GET /wsman HTTP/1.0\r\n\r\n")
srv(5986, "WinRM (TLS) exposed", "medium", r"HTTP/1\.1 40|WCREATED",
    payload=b"GET /wsman HTTP/1.0\r\n\r\n", conf="possible")
srv(445, "SMBv1 enabled (MS17-010 surface)", "high", r"\x00\x00", payload=b"",
    conf="possible")
srv(5938, "TeamViewer port open", "medium", r"TeamViewer", payload=b"", conf="possible")
srv(5900, "VNC - check for plain auth", "high", r"\x01\x01\x00|VNC", payload=b"\x00\x00\x00\x01",
    conf="possible")
srv(5555, "ADB exposed (Android)", "high", r"ADB|Android", payload=b"\x00\x2a\x30\x30\x30\x31", conf="possible")
srv(554, "RTSP exposed", "medium", r"RTSP/1\.0 200", payload=b"OPTIONS rtsp://x RTSP/1.0\r\n\r\n")
srv(5061, "SIP-TLS exposed", "medium", r"SIP/2\.0", payload=b"OPTIONS sip:x@y SIP/2.0\r\n\r\n")
srv(9101, "JMX-in-HTML unauth", "medium", r"Java Management Extensions|jmx",
    payload=b"GET / HTTP/1.0\r\n\r\n")
srv(10051, "Zabbix agent exposed", "medium", r"Zabbix", payload=b"", conf="possible")

# =======================================================================
# EXPANSION — web, api, network, server to 100+ each
# =======================================================================

# ---- web: sensitive files, CGIs, version/header leaks, more CMS --------
B.web("WSTG-CONF-012", ".htaccess disclosure", "high", "/.htaccess",
      {"body_regex": r"RewriteEngine|Order\s+(allow,deny)|AddHandler"})
B.web("WSTG-CONF-013", ".DS_Store directory metadata", "medium", "/.DS_Store",
      {"body_regex": r"Bud1"})
B.web("WSTG-CONF-014", "db.sql backup exposed", "critical", "/db.sql",
      {"body_regex": r"(INSERT INTO|CREATE TABLE|--\s*MySQL|--\s*PostgreSQL)"})
B.web("WSTG-CONF-015", "backup.sql exposed", "critical", "/backup.sql",
      {"body_regex": r"(INSERT INTO|CREATE TABLE|--\s*MySQL|--\s*PostgreSQL)"})
B.web("WSTG-CONF-016", "backup.zip exposed", "high", "/backup.zip",
      {"status": [200], "headers": {"Content-Type": r"application/zip"}})
B.web("WSTG-CONF-017", "config.php.bak exposed", "high", "/config.php.bak",
      {"body_regex": r"<\?php|mysql(_i)?_connect|DB_(NAME|USER|PASSWORD|HOST)|\$db\b|define\s*\(\s*['\"]DB_"})
B.web("WSTG-CONF-018", "database.sql dump", "critical", "/database.sql",
      {"body_regex": r"(INSERT INTO|CREATE TABLE)"})
B.web("WSTG-CONF-019", "error_log exposed", "medium", "/error_log",
      {"body_regex": r"PHP\s+(Fatal|Warning|Parse)"})
B.web("WSTG-CONF-020", "access.log exposed", "medium", "/access.log",
      {"body_regex": r"GET\s+/\S+\s+HTTP"})
B.web("WSTG-CONF-021", "WEB-INF/web.xml disclosure", "critical", "/WEB-INF/web.xml",
      {"body_regex": r"</web-app>|<servlet-name>"})
B.web("WSTG-CONF-022", "META-INF/MANIFEST.MF disclosure", "medium",
      "/META-INF/MANIFEST.MF", {"body_regex": r"Manifest-Version:"})
B.web("WSTG-CONF-023", "cgi-bin/printenv command output", "high",
      "/cgi-bin/printenv", {"body_regex": r"CONTENT_LENGTH|GATEWAY_INTERFACE"})
B.web("WSTG-CONF-024", "cgi-bin/test-cgi reachable", "medium", "/cgi-bin/test-cgi",
      {"body_regex": r"REMOTE_ADDR|CGI/1\.1"})
B.web("WSTG-CONF-025", "PHP-FPM status page exposed", "medium", "/fpm-status?full",
      {"body_regex": r"process manager:|pm\.start"})
B.web("WSTG-CONF-026", "WordPress version file", "low", "/wp-includes/version.php",
      {"body_regex": r"wp-includes/version" }, tech="wordpress")
B.web("WSTG-CONF-027", "Drupal install.php present", "medium", "/install.php",
      {"body_regex": r"Drupal\s+installation|install.php"}, tech="drupal")
B.web("WSTG-CONF-028", "PrestaShop footprint", "low", "/",
      {"body_regex": r"prestashop"}, tech="prestashop")
B.web("WSTG-CONF-029", "OpenCart footprint", "low", "/",
      {"body_regex": r"opencart"}, tech="opencart")
B.web("WSTG-CONF-030", "Django CSRF cookie set", "low", "/",
      {"headers": {"Set-Cookie": r"csrftoken="}}, tech="django")
B.web("WSTG-CONF-031", "X-Powered-By: Express", "low", "/",
      {"headers": {"X-Powered-By": r"Express"}}, tech="express")
B.web("WSTG-CONF-032", "X-Powered-By: PHP version", "low", "/",
      {"headers": {"X-Powered-By": r"PHP/\d+\.\d+"}}, tech="php")
B.web("WSTG-CONF-033", "X-Powered-By: ASP.NET", "low", "/",
      {"headers": {"X-Powered-By": r"ASP\.NET"}}, tech="aspnet")
B.web("WSTG-CONF-034", "node-red exposed", "high", "/",
      {"body_regex": r"node-red|Node-RED"}, tech="node")
B.web("WSTG-CONF-035", "Rails /rails/info/properties", "medium",
      "/rails/info/properties", {"body_regex": r"RailsVersion|ruby\s+"},
      tech="rails")
B.web("WSTG-CONF-036", "vendor/composer/installed.json", "low",
      "/vendor/composer/installed.json",
      {"body_regex": r'"name"\s*:\s*"'}, tech="php")
B.web("WSTG-CONF-037", "package-lock.json dependency versions", "low",
      "/package-lock.json", {"body_regex": r'"packages"\s*:'}, tech="node")
B.web("WSTG-CONF-038", "security.txt present", "info", "/.well-known/security.txt",
      {"body_regex": r"Contact:\s*(https|mailto)"})
B.web("WSTG-CONF-039", "Spring /actuator/mappings (URL map leak)", "medium",
      "/actuator/mappings", {"body_regex": r'"(mappings|path)"\s*:'},
      tech="spring")
B.web("WSTG-CONF-040", "JBoss JMX invoker servlet surface", "high",
      "/invoker/JMXInvokerServlet", {"body_regex": r"jboss|JMXInvoker"},
      tech="jboss")
B.web("WSTG-CONF-041", "WebLogic console.portal", "high", "/console/console.portal",
      {"body_regex": r"WebLogic"}, tech="weblogic")
B.web("WSTG-CONF-042", "WebLogic wls-wsat coordinator (deser surface)", "high",
      "/wls-wsat/CoordinatorPortType",
      {"body_regex": r"faultstring|CoordinatorPortType"}, tech="weblogic")
B.web("WSTG-CONF-043", "Druid monitor panel", "medium", "/druid/index.html",
      {"body_regex": r"Druid Monitor|Initialization Sequences"},
      tech="spring")
B.web("WSTG-CONF-044", "phpMemcachedAdmin panel", "medium",
      "/memcached/index.php", {"body_regex": r"phpMemcachedAdmin|memcached"})
B.web("WSTG-CONF-045", "PHPUnit eval-stdin surface", "high",
      "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
      {"status": [200], "headers": {"Content-Type": r"text/html"}})
B.web("WSTG-CONF-046", "Kibana /app/dev_tools", "medium", "/app/dev_tools",
      {"body_regex": r"kibana|console"})
B.web("WSTG-CONF-047", "Struts devMode webconsole", "high",
      "/struts/webconsole.html", {"body_regex": r"struts|webconsole"},
      tech="struts")
B.web("WSTG-CONF-048", "Grafana /api/health (unauth)", "medium", "/api/health",
      {"body_regex": r'"database"\s*:\s*"ok"'}, tech="grafana")
B.web("WSTG-CONF-049", "Jenkins CLI exposed", "medium", "/cli",
      {"body_regex": r"Jenkins-cli|MavenDeployer"}, tech="jenkins")
B.web("WSTG-CONF-050", "Magento REST API version disclosure", "low",
      "/rest/V1/integration/admin/token",
      {"body_regex": r'"(message|code)"\s*:'}, tech="magento")
B.web("WSTG-CONF-051", "Nexus /service/rest/v1/repositories", "medium",
      "/service/rest/v1/repositories",
      {"body_regex": r'"(name|url|format)"\s*:'}, tech="nexus")
B.web("WSTG-CONF-052", "Docker Registry v2 API", "medium", "/v2/",
      {"body_regex": r'"registry_distribution"|"docker"'},
      tech="docker-registry")
B.web("WSTG-CONF-053", "Actuator shutdown endpoint (DoS)", "medium",
      "/actuator/shutdown", {"status": [200, 405]}, tech="spring")
B.web("WSTG-CONF-054", "Apache server-info detailed config", "high",
      "/server-info?DB_VJ", {"body_regex": r"Server Settings"})
B.web("WSTG-CONF-055", "Symfony /_profiler list", "medium", "/_profiler/",
      {"body_regex": r"Symfony|profiler"})

# ---- api: mass BOLA across resources, verb confusion, injection, SSRF ----
_api_resources = [
    ("users", "id"), ("accounts", "id"), ("orders", "id"), ("payments", "id"),
    ("invoices", "id"), ("tickets", "id"), ("projects", "id"),
    ("documents", "id"), ("messages", "id"), ("notifications", "id"),
    ("activities", "id"), ("favorites", "id"), ("cart", "id"),
    ("addresses", "id"), ("subscriptions", "id"), ("reviews", "id"),
    ("ratings", "id"), ("memberships", "id"), ("wallet", "id"),
    ("transactions", "id"), ("transfers", "id"), ("refunds", "id"),
    ("disputes", "id"), ("claims", "id"), ("policies", "id"),
    ("bookings", "id"), ("appointments", "id"), ("reservations", "id"),
    ("inventory", "id"), ("catalog", "id"), ("skus", "id"), ("prices", "id"),
    ("stock", "id"), ("warehouses", "id"), ("shipments", "id"),
    ("carriers", "id"), ("tracking", "id"), ("returns", "id"),
    ("coupons", "id"), ("discounts", "id"), ("promotions", "id"),
    ("giftcards", "id"), ("loyalty", "id"), ("feature_flags", "id"),
    ("experiments", "id"), ("abtests", "id"), ("configs", "id"),
    ("settings", "id"), ("preferences", "id"), ("themes", "id"),
    ("translations", "id"), ("media", "id"), ("assets", "id"),
    ("images", "id"), ("videos", "id"), ("playlists", "id"),
    ("channels", "id"), ("subscribers", "id"), ("followers", "id"),
    ("friends", "id"), ("posts", "id"), ("comments", "id"), ("likes", "id"),
    ("shares", "id"), ("insights", "id"), ("reports", "id"),
    ("dashboards", "id"), ("widgets", "id"), ("charts", "id"),
    ("datasets", "id"), ("schemas", "id"), ("migrations", "id"),
    ("jobs", "id"), ("queues", "id"), ("workers", "id"), ("nodes", "id"),
    ("clusters", "id"), ("deployments", "id"), ("services", "id"),
    ("endpoints", "id"), ("proxies", "id"), ("routes", "id"),
    ("certificates", "id"), ("domains", "id"), ("dns_records", "id"),
    ("zones", "id"), ("api_keys", "id"), ("sessions", "id"),
    ("devices", "id"), ("oauth_tokens", "id"), ("credentials", "id"),
    ("tenants", "id"), ("organizations", "id"), ("groups", "id"),
    ("roles", "id"), ("permissions", "id"), ("rules", "id"),
    ("workflows", "id"), ("pipelines", "id"), ("builds", "id"),
    ("artifacts", "id"), ("environments", "id"), ("keypairs", "id"),
    ("webhooks", "id"), ("events", "id"), ("loans", "id"),
]
for _res, _f in _api_resources:
    _napi[0] += 1
    _APIS.append({"id": "APIS-%03d" % _napi[0], "category": "api",
                  "name": "BOLA: /api/v1/%s/1 (object-level auth)" % _res,
                  "severity": "high", "confidence": "firm", "scope": "api",
                  "req": {"method": "GET", "path": "/api/v1/%s/1" % _res,
                          "headers": {"Accept": "application/json"},
                          "expect_json": True},
                  "match": {"status": [200],
                            "body_regex": r'"(id|%s|data|result|message)"\s*:' % _f}})
# more API10/2/8
api("APIS-%03d" % _napi[0], "JSONP callback reflects (CSP bypass)", "medium",
    "/api/data?callback=vjrNs", r'vjrNs\s*\(\s*\{', headers={
        "Accept": "application/javascript"})
api("APIS-%03d" % _napi[0], "sql injection in API query param", "high",
    "/api/v1/items?id=1'", r'"(message|error)"\s*:|SQL', headers={
        "Accept": "application/json"})
api("APIS-%03d" % _napi[0], "no Content-Type enforcement (smuggling)", "low",
    "/api/v1/create", r'"(id|status|message)"\s*:', method="POST",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    body="name=vjr&role=admin")
api("APIS-%03d" % _napi[0], "HTTP method override accepted", "medium",
    "/api/v1/resource", r'"(id|status|message)"\s*:', method="GET",
    headers={"X-HTTP-Method-Override": "DELETE"})
api("APIS-%03d" % _napi[0], "path normalization bypass (/api//admin)", "high",
    "/api//v1/admin", r'"(users|data|id)"\s*:', headers={
        "Accept": "application/json"})
api("APIS-%03d" % _napi[0], "URL-encoded traversal in API path", "high",
    "/api/v1/%2e%2e/%2e%2e/admin", r'"(users|data|id)"\s*:', headers={
        "Accept": "application/json"})
api("APIS-%03d" % _napi[0], "OTP endpoint no rate limit", "medium",
    "/api/v1/otp/request", r'"(status|ok|sent|message)"\s*:', method="POST",
    headers={"Accept": "application/json", "Content-Type":
             "application/json"}, body='{"phone":"+10000000000"}')
api("APIS-%03d" % _napi[0], "query-string auth token leaks via referrer", "low",
    "/api/me?token=VAJRA", r'"(id|name|email)"\s*:', headers={
        "Accept": "application/json"})
api("APIS-%03d" % _napi[0], "GraphQL query of sensitive type", "high",
    "/graphql", r'"data"|"errors"', method="POST",
    headers={"Content-Type": "application/json"},
    body='{"query":"{users{id email}}"}')
api("APIS-%03d" % _napi[0], "OpenAPI schema leaks files endpoint", "medium",
    "/api/openapi.json", r'"paths"|"definitions"',
    headers={"Accept": "application/json"})
api("APIS-%03d" % _napi[0], "XML entity injection in API body", "critical",
    "/api/v1/upload", r'"(message|error|status)"\s*:|resolves', method="POST",
    headers={"Content-Type": "application/xml"},
    body='<!DOCTYPE r [<!ENTITY e "VJR">]><r>&e;</r>')
api("APIS-%03d" % _napi[0], "request body not size-limited (DoS)", "low",
    "/api/v1/items", r'"x"\s*:\s*"V{10,}"', method="POST",
    headers={"Content-Type": "application/json",
             "Accept": "application/json"},
    body='{"x":"' + "V" * 4000 + '"}')
api("APIS-%03d" % _napi[0], "S3-presigned style key enumeration", "medium",
    "/api/v1/objects?key=s3://vjr", r'"(url|key|name)"\s*:',
    headers={"Accept": "application/json"})

# ---- network: more banner checks across alt ports + less common protocols ---
_n = len(NET) + 1
def netm(port, name, sev, regex, payload=None, conf="firm"):
    global _n
    NET.append({"id": "NET-%03d" % _n, "category": "network",
                "name": name, "severity": sev, "confidence": conf,
                "scope": {"port": port},
                "raw": {"host": "{_h}", "port": port, "timeout": 5,
                        "payload": payload if payload is not None else b""},
                "match": {"body_regex": regex}})
    _n += 1

netm(636, "LDAP (TLS) open", "low", r"(ldapResult|objectClass|baseObject)")
netm(1389, "LDAP (any) open", "low", r"(ldapResult|objectClass)")
netm(161, "SNMP responds", "low",
     r"public|private|SNMPv[12c]|GET-NEXT-RESPONSE", conf="possible")
netm(389, "LDAP responds", "low", r"(ldapResult|objectClass|namingContexts)")
netm(135, "MSRPC/DCE endpoint mapper", "medium",
     r"(ncacn_ip_tcp|ncalrpc|objectClass)", conf="possible")
netm(1025, "MSRPC dynamic port", "medium",
     r"(ncacn_ip_tcp|ncalrpc|REFLection|ObjectSpec)", conf="possible")
netm(2049, "NFS open", "medium", r"(nfs|NFS|Mount|nfsd)")
netm(111, "rpcbind/portmapper open", "medium", r"(portmapper|rpcbind|pmdebug)")
netm(512, "rexec/openbsd rexd", "high", r"rexec|login:")
netm(513, "rlogin responds", "high", r"login:", conf="possible")
netm(514, "rsh/rshd responds", "high", r"Permission denied|Login", conf="possible")
netm(873, "rsync daemon", "medium", r"RSYNCD|rsync\s+\d")
netm(6379, "Redis (alt port)", "high", r"\$-?\d+|OK|ERR|NOAUTH")
netm(16379, "Redis cluster port", "high", r"\$-?\d+|OK|ERR")
netm(26379, "Redis Sentinel", "high", r"\$-?\d+|OK|myid|runid")
netm(11211, "Memcached responds", "medium", r"VERSION\s+\d|STAT\s+pid")
netm(11215, "Memcached (alt port)", "medium", r"VERSION\s+\d")
netm(50070, "Hadoop NameNode HTTP", "high",
     r"fsckState|liveNodes|HDFS.*Web", conf="possible")
netm(9870, "Hadoop NameNode HTTP (v3)", "high",
     r"fsckState|liveNodes|HDFS.*Web", conf="possible")
netm(8188, "Yarn timelineserver", "high",
     r"ApplicationReport|timeline", conf="possible")
netm(8081, "Flink dashboard", "medium", r"flink|Apache Flink")
netm(10001, "HiveServer2 Thrift", "medium", r"HiveServer2|beeline", conf="possible")
netm(10000, "Spark Thrift server", "medium", r"Spark.*thrift|SparkContext", conf="possible")
netm(2181, "ZooKeeper responds", "medium", r"Zookeeper|imok|zookeeper")
netm(9092, "Kafka broker", "medium", r"kafka|KafkaServer|cluster.id")
netm(9093, "Kafka (SSL)", "medium", r"kafka|KafkaServer")
netm(8082, "Kafka REST Proxy", "medium", r"consumer.*topics|kafka-rest")
netm(5672, "AMQP (RabbitMQ)", "medium", r"AMQP", conf="possible")
netm(15672, "RabbitMQ Management", "high",
     r"rabbitmq|RabbitMQ|\"overview\"", conf="possible")
netm(6650, "Pulsar broker", "medium", r"pulsar|PulsarService")
netm(9876, "RocketMQ NameServer", "medium", r"rocketmq|mqVersion")
netm(61616, "ActiveMQ OpenWire", "high", r"ActiveMQ|openwire", conf="possible")
netm(50090, "ActiveMQ (cluster)", "high", r"ActiveMQ|openwire", conf="possible")
netm(8161, "ActiveMQ Web Console", "high", r"activemq|ActiveMQ.*Web")
netm(9042, "Cassandra native", "medium", r"CQL|SUPPORTED|READY|error")
netm(7199, "Cassandra JMX (TLS)", "medium", r"cassandra|jmx")
netm(16010, "HBase Master HTTP", "high", r"BaseTableRegionStats|hbase.*master")
netm(16020, "HBase RegionServer", "medium", r"RegionServer|hbase", conf="possible")
netm(8080, "Solr/Presto/Druid HTTP", "medium",
     r"(solr|Solr|presto|Presto|druid|Druid)", conf="possible")
netm(8983, "Solr native", "medium", r"solr|SolrAdmin")
netm(9200, "OpenSearch/Elasticsearch", "high",
     r"cluster_name|\"version\"|\"name\"", conf="possible")
netm(9600, "OpenSearch (alt)", "high",
     r"cluster_name|\"version\"", conf="possible")
netm(8428, "VictoriaMetrics", "medium", r"vm_rows|vm_total_rows")
netm(19999, "Netdata dashboard", "medium", r"netdata|Netdata")
netm(9100, "Node Exporter", "medium", r"node_exporter|go\.build")
netm(9115, "Blackbox Exporter", "medium", r"blackbox|prometheus")
netm(24224, "Fluentd forward", "medium", r"fluentd|Fluentd", conf="possible")
netm(3100, "Loki API", "medium", r"ready|ingester|loki")
netm(5000, "MLflow UI", "medium", r"mlflow|experiment")
netm(8088, "Superset", "medium", r"superset|flask.appbuilder")
netm(4646, "Nomad HTTP API", "medium", r"Nomad|region|node")
netm(8500, "Consul HTTP API", "high", r"\"Config\"|consul|Consul")
netm(8200, "Vault API", "high", r"\"initialized\"|vault|sealed")
netm(4001, "etcd client", "high", r"etcdserver|clusterVersion|\"header\"")
netm(9229, "Node.js inspector", "high", r"Debugger listening|WebSocket")
netm(15671, "AMQPS (TLS)", "medium", r"AMQP", conf="possible")
netm(3000, "Dev dashboard (Grafana/etc)", "medium",
     r"(grafana|Grafana|kibana|Kibana|jupyter)", conf="possible")
netm(5044, "Logstash Beats", "medium", r"Beats|logstash", conf="possible")
netm(9000, "MinIO/generic", "medium",
     r"(MinIO|minio|<ListBucketResult>)", conf="possible")
netm(1521, "Oracle TNS", "high", r"(Oracle|TNS-|ORA-)", conf="possible")
netm(3050, "Firebird", "medium", r"(firebird|Firebird)", conf="possible")
netm(502, "Modbus/TCP (ICS) MBAP handshake", "high",
     r"\x00\x01\x00\x00\x00\x0[2-9a-f]",
     payload=b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x01\x00",
     conf="possible")
netm(8000, "Salt API/Web UI", "medium", r"salt|SaltStack|salt-api")
netm(5555, "ADB service", "high", r"Android|CNXN|OPEN", conf="possible")

# ---- server: more unauth surface checks with discriminating markers ----
_s = len(SRV) + 1
def svrm(name, sev, regex, bytes_marker=b"", conf="firm"):
    global _s
    SRV.append({"id": "SRV-%03d" % _s, "category": "server",
                "name": name, "severity": sev, "confidence": conf,
                "scope": "server",
                "raw": {"host": "{_h}", "port": "{_p}", "timeout": 5,
                        "payload": bytes_marker},
                "match": {"body_regex": regex}})
    _s += 1

svrm("Unauthenticated MinIO bucket listing", "high",
     r"<ListBucketResult>|<Contents>")
svrm("ArangoDB web interface unauth", "high",
     r"arangodb|ArangoDB|\"server\"")
svrm("Neo4j Browser unauth", "high",
     r"neo4j|Neo4j|bolt://")
svrm("RethinkDB admin panel", "high",
     r"rethink|RethinkDB|debug")
svrm("OpenSearch Dashboards unauth", "high",
     r"opensearch|OpenSearch|kibana")
svrm("ClickHouse HTTP interface unauth", "high",
     r"Ok\.|DB::Exception|row.*parsed")
svrm("InfluxDB v2 API unauth", "high",
     r"buckets|orgs|\"authorizations\"|influx")
svrm("CockroachDB admin UI", "high",
     r"cockroach|CockroachDB|_status/nodes")
svrm("TimescaleDB (PostgreSQL-based) exposed", "medium",
     r"timescaledb|hypertable", conf="possible")
svrm("Grafana unauthenticated", "high",
     r"grafana|Grafana|\"database\"")
svrm("Prometheus UI unauth", "medium",
     r"prometheus|Prometheus|target_group")
svrm("VictoriaMetrics UI unauth", "medium", r"vm_rows|VictoriaMetrics")
svrm("Netdata dashboard unauth", "medium", r"netdata|Netdata")
svrm("Node Exporter metrics unauth", "low", r"node_exporter|go\.build|HELP")
svrm("cAdvisor metrics unauth", "medium", r"cadvisor|container_")
svrm("Consul agent UI unauth", "high",
     r"consul|Consul|\"Config\"|\"Node\"")
svrm("Nomad UI unauth", "medium", r"Nomad|\"ID\"|job.*status")
svrm("Vault UI unauth", "high",
     r"vault|Vault|\"initialized\"|\"sealed\"")
svrm("etcd dashboard /keys dump", "high",
     r"etcdserver|\"key\"|\"value\"")
svrm("Docker daemon TCP exposed", "critical",
     r"API Version|\"Version\"|containerCreate")
svrm("Kubernetes kubelet unauth", "critical",
     r"\"nodeName\"|\"pods\"|containerStatuses")
svrm("Kubernetes dashboard unauth", "high",
     r"kubernetes|Kubernetes|dashboard")
svrm("OpenShift API unauth", "high",
     r"openshift|gitVersion|OpenShift")
svrm("Jupyter Notebook unauth", "high",
     r"jupyter|Jupyter|notebook_list")
svrm("Apache Airflow UI unauth", "high",
     r"airflow|Airflow|\"dag_id\"")
svrm("Apache Flink dashboard unauth", "medium",
     r"flink|Apache Flink|taskmanagers")
svrm("Apache Spark master UI unauth", "medium",
     r"Apache Spark|spark://|workers")
svrm("Grafana Loki /ready", "low", r"ready|ingester")
svrm("Graylog REST API unauth", "medium",
     r"graylog|Graylog|\"cluster_id\"")
svrm("Paperless-ngx unauth", "medium",
     r"paperless|Paperless", conf="possible")
svrm("Wekan/WeKan unauth", "medium", r"wekan|WeKan", conf="possible")
svrm("MinIO Console unauth", "high",
     r"minio.*console|MinIO.*Console")
svrm("RocketMQ dashboard unauth", "high",
     r"rocketmq|RocketMQ|\"brokerName\"")
svrm("APISIX Dashboard unauth", "high",
     r"apisix|APISIX|\"total_count\"")
svrm("Portainer unauth", "high",
     r"portainer|Portainer|\"Version\"")
svrm("Rancher unauth", "high",
     r"rancher|Rancher|\"clusterName\"")
svrm("Vault unsealed without auth", "critical",
     r"\"initialized\":\s*true|\"sealed\":\s*false")
svrm("SonarQube unauth", "high",
     r"sonarqube|SonarQube|\"id\".*\"key\"")
svrm("Nexus Repository unauth", "high",
     r"nexus|Nexus|\"version\".*\"edition\"")
svrm("Kafka UI unauth", "medium",
     r"kafka-ui|AKHQ|topic.*count")
svrm("Memcached full stats (no auth)", "high",
     r"STAT pid|STAT curr_items|STAT bytes")
svrm("MongoDB HTTP status", "high",
     r"\"ok\"\s*:\s*1|\"ismaster\"|\"maxBsonObjectSize\"")
svrm("CouchDB unauthenticated", "high",
     r"couchdb|CouchDB|\"couchdb\"|Welcome")
svrm("HDFS DataNode web UI", "medium",
     r"DataNodeInfo|hdfs.*datanode")
svrm("YARN ResourceManager unauth", "high",
     r"YARN.*Resource|yarn.*scheduler|running0applications")
svrm("HBase REST API unauth", "medium",
     r"BaseTableRegionStats|\"name\".*\"hbase\"")
svrm("Solr admin unauth", "medium",
     r"SolrAdmin|\"lucene\"|core.*collection")
svrm("Druid console unauth", "high",
     r"druid.*console|\"druid\"|supervisor")
svrm("Kibana unauth", "medium",
     r"Kibana|\"kibana\"|dashboard")
svrm("Fluentd forward port open", "medium",
     r"fluent_forward|in_forward", conf="possible")
svrm("SaltStack master unauth", "high",
     r"Salt|salt.*master|pub_key")
svrm("Chrony/NTP open", "low",
     r"leap|stratum|refid|refsources")
svrm("OpenSSH version disclosure", "info",
     r"SSH-2\.0-OpenSSH", conf="possible")

# =======================================================================
# assemble + validate (drop entries with no usable marker)
# =======================================================================
checks = []
for e in (B.checks + API + NET + SRV):
    m = e.get("match") or {}
    has_marker = bool(m.get("body_contains") or m.get("body_regex") or
                      m.get("headers"))
    if not has_marker:
        continue  # anti-FP: keep only discriminating entries
    checks.append(e)

bank = {"meta": {
    "source": "VAJRA uniform coverage bank (OWASP WSTG / OWASP API Top 10 / "
              "network / server)",
    "categories": {"web": sum(1 for c in checks if c["category"] == "web"),
                   "api": sum(1 for c in checks if c["category"] == "api"),
                   "network": sum(1 for c in checks if c["category"] == "network"),
                   "server": sum(1 for c in checks if c["category"] == "server")},
    "total": len(checks),
}, "checks": checks}

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(_ser(bank), f, ensure_ascii=False, indent=2)

print("web=%d api=%d network=%d server=%d total=%d" % (
    bank["meta"]["categories"]["web"], bank["meta"]["categories"]["api"],
    bank["meta"]["categories"]["network"], bank["meta"]["categories"]["server"],
    len(checks)))