"""Vajra - shared helpers, parsers and extraction utilities."""
import os
import re
import json
import html
import random
import string
import ipaddress
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode, quote

PROJECT_ROOT = Path(__file__).resolve().parent.parent

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "VajraScanner/2.0 (+security-assessment)",
]

TOP1000_PORTS_STR = """
7 9 13 21 22 23 25 26 37 53 79 80 81 88 106 110 111 113 119 135 139 143 144 179 199
389 427 443 444 445 465 513 514 515 543 544 548 554 587 631 646 750 751 760 764 773
774 775 780 783 787 799 800 801 808 843 873 888 898 900 901 902 903 990 992 993 995
999 1000 1001 1002 1007 1009 1010 1011 1021 1022 1023 1024 1025 1026 1027 1028 1029
1030 1031 1032 1033 1034 1035 1036 1037 1038 1039 1040 1041 1042 1043 1044 1045 1046
1047 1048 1049 1050 1051 1052 1053 1054 1055 1056 1057 1058 1059 1060 1061 1062 1063
1064 1065 1066 1067 1068 1069 1070 1071 1072 1073 1074 1075 1076 1077 1078 1079 1080
1081 1082 1083 1084 1085 1086 1087 1088 1089 1090 1091 1092 1093 1094 1095 1096 1097
1098 1099 1100 1102 1104 1105 1106 1107 1108 1110 1111 1112 1113 1114 1117 1119 1121
1122 1123 1124 1126 1130 1131 1132 1137 1138 1141 1145 1147 1148 1149 1151 1152 1154
1163 1164 1165 1166 1169 1174 1175 1183 1185 1186 1187 1192 1198 1199 1201 1213 1216
1217 1218 1233 1234 1236 1244 1247 1248 1259 1277 1287 1296 1300 1301 1309 1310 1311
1322 1328 1334 1352 1417 1433 1434 1443 1455 1461 1494 1500 1501 1503 1521 1524 1533
1556 1580 1583 1594 1600 1641 1658 1666 1687 1688 1700 1717 1718 1719 1720 1721 1723
1755 1761 1782 1783 1801 1805 1812 1839 1840 1862 1863 1864 1875 1900 1914 1935 1947
1971 1972 1974 1984 1998 1999 2000 2001 2002 2003 2004 2005 2006 2007 2008 2009 2010
2013 2020 2021 2022 2023 2024 2025 2030 2033 2034 2035 2038 2040 2041 2042 2043 2045
2046 2047 2048 2049 2065 2068 2099 2100 2103 2105 2106 2107 2111 2119 2121 2126 2135
2144 2160 2161 2170 2179 2190 2191 2196 2200 2222 2251 2260 2288 2301 2323 2366 2381
2382 2383 2393 2394 2399 2401 2492 2500 2522 2525 2557 2601 2602 2604 2605 2607 2608
2638 2701 2702 2710 2717 2718 2725 2800 2809 2811 2869 2875 2909 2910 2920 2967 2968
2998 3000 3001 3003 3005 3006 3007 3011 3013 3017 3030 3031 3052 3071 3077 3128 3168
3211 3221 3260 3261 3268 3269 3283 3300 3301 3306 3322 3323 3324 3325 3333 3351 3367
3372 3389 3390 3404 3476 3493 3517 3527 3546 3551 3580 3659 3689 3690 3703 3737 3766
3784 3785 3786 3787 3800 3801 3809 3814 3826 3827 3828 3851 3869 3871 3878 3889 3905
3914 3918 3920 3945 3971 3986 3995 3998 4000 4001 4002 4003 4004 4005 4006 4045 4111
4125 4126 4129 4224 4242 4279 4321 4343 4443 4444 4445 4446 4449 4550 4567 4662 4848
4899 4900 4998 5000 5001 5002 5003 5004 5009 5030 5033 5050 5051 5054 5060 5061 5080
5087 5100 5101 5102 5120 5145 5150 5151 5168 5190 5200 5201 5221 5222 5225 5226 5269
5280 5298 5353 5357 5405 5414 5431 5432 5440 5500 5510 5544 5550 5555 5560 5566 5631
5632 5633 5666 5678 5679 5718 5730 5800 5801 5802 5810 5811 5825 5850 5859 5862 5877
5900 5901 5902 5903 5904 5906 5907 5910 5911 5915 5922 5925 5950 5952 5959 5960 5961
5962 5963 5985 5986 5987 5988 5989 5998 5999 6000 6001 6002 6003 6004 6005 6006 6007
6009 6025 6059 6060 6100 6101 6106 6112 6123 6129 6156 6346 6347 6379 6382 6389 6502
6510 6543 6547 6565 6566 6567 6580 6646 6666 6667 6668 6669 6689 6692 6699 6779 6788
6789 6792 6839 6881 6901 6969 7000 7001 7002 7007 7019 7025 7070 7100 7103 7106 7200
7201 7402 7435 7443 7496 7512 7625 7626 7627 7676 7741 7777 7778 7800 7911 7920 7921
7937 7938 7999 8000 8001 8002 8007 8008 8009 8010 8011 8021 8022 8031 8042 8045 8080
8081 8082 8083 8084 8085 8086 8087 8088 8089 8090 8093 8099 8100 8180 8181 8192 8193
8194 8200 8222 8254 8280 8281 8282 8300 8333 8383 8400 8401 8402 8418 8443 8500 8600
8649 8651 8652 8654 8701 8800 8873 8899 8983 9000 9001 9002 9003 9009 9010 9011 9040
9050 9071 9080 9081 9090 9091 9099 9100 9101 9102 9103 9110 9111 9200 9207 9220 9290
9415 9418 9485 9500 9502 9503 9535 9575 9593 9594 9595 9618 9666 9876 9877 9878 9898
9900 9917 9929 9943 9944 9968 9998 9999 10000 10001 10002 10003 10004 10009 10010
10012 10024 10025 10082 10180 10215 10243 10566 10616 10617 10621 10626 10628 10629
10778 11110 11111 11967 12000 12174 12265 12345 13456 13722 13782 13783 14000 14238
14441 14442 15000 15002 15003 15004 15660 15742 16000 16001 16012 16016 16018 16080
16113 16992 16993 17877 17988 18040 18101 18988 19101 19283 19315 19350 19780 19801
19842 20000 20005 20031 20221 20222 20828 21571 22939 23502 24444 24800 25734 25735
26214 27000 27017 27352 27353 27355 27356 27715 28200 29000 29867 30000 30704 30951
31038 31337 32768 32769 32770 32771 32772 32773 32774 32775 32776 32777 32778 32779
32780 32781 32782 32783 32784 32785 33354 33899 34571 34572 34573 35500 38292 40193
40911 41511 42510 44176 44442 44443 44444 44501 45100 48080 49152 49153 49154 49155
49156 49157 49158 49159 49160 49161 49162 49163 49165 49166 49167 49175 49176 49181
49182 49191 49192 49193 49200 49201 49500 50000 50001 50002 50003 50006 50300 50389
50500 50636 50800 51103 51493 52673 52822 52848 52869 54045 54328 55055 55056 55555
55600 56737 56738 57294 57797 58080 60020 60443 61532 61900 62078 63331 64623 64624
65023 65024
"""

TOP1000 = sorted({int(p) for p in TOP1000_PORTS_STR.split()})
TOP100 = TOP1000[:100]
EXTENDED_EXTRA = [1883, 2181, 3306, 33060, 3389, 4444, 5000, 5037, 5555, 5601,
                  5672, 6379, 7001, 7002, 8009, 8088, 8500, 8888, 9001, 9042,
                  9092, 9160, 9200, 9300, 11211, 15672, 16379, 19888, 26257,
                  27017, 27018, 27019, 28017, 32768, 50050, 50051, 50070,
                  55553, 61616, 1337, 20000, 32000]
EXTENDED = sorted(set(TOP1000) | set(EXTENDED_EXTRA))


def parse_ports(spec, default=None):
    if not spec:
        return list(default or TOP100)
    spec = str(spec).strip().lower()
    if spec == "top100":
        return list(TOP100)
    if spec == "top1000":
        return list(TOP1000)
    if spec in ("extended", "fast"):
        return list(EXTENDED)
    if spec in ("all", "-"):
        return list(range(1, 65536))
    ports = set()
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a, _, b = tok.partition("-")
            lo, hi = int(a), int(b)
            if 1 <= lo <= hi <= 65535:
                ports.update(range(lo, hi + 1))
        elif tok.isdigit() and 1 <= int(tok) <= 65535:
            ports.add(int(tok))
    return sorted(ports)


def is_ip(value):
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def expand_cidr(raw, cap=256):
    net = ipaddress.ip_network(raw, strict=False)
    hosts = [str(h) for h in net.hosts()]
    if not hosts and net.num_addresses == 1:
        hosts = [str(net.network_address)]
    if len(hosts) > cap:
        hosts = hosts[:cap]
    return hosts


def normalize_url(raw):
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw
    p = urlparse(raw)
    scheme = p.scheme.lower()
    port = p.port
    if not port:
        port = 443 if scheme == "https" else 80
    path = p.path or "/"
    host = p.hostname or ""
    netloc = "%s:%d" % (host, port) if port not in (80, 443) else host
    return urlunparse((scheme, netloc, path, "", p.query, ""))


def base_of(url):
    p = urlparse(url)
    port = p.port
    if not port:
        port = 443 if p.scheme == "https" else 80
    scheme = p.scheme.lower()
    netloc = p.hostname
    if port not in (80, 443):
        netloc = "%s:%d" % (p.hostname, port)
    return "%s://%s" % (scheme, netloc)


def nonce(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def which_tool(*names):
    """Resolve an external tool that may be shipped under several binary
    names (e.g. impacket scripts moved from 'X.py' to 'impacket-X' on
    recent Kali/dpkg). Returns the first PATH hit or None."""
    import shutil
    for n in names:
        if not n:
            continue
        p = shutil.which(n)
        if p:
            return p
    return None


def rand_path(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))


def chunked(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def load_json(relpath, default=None):
    path = PROJECT_ROOT / relpath
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


LINK_RE = re.compile(r"""(?:href|src|action|data-url)\s*=\s*["']([^"'>]+)""", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.S | re.I)
INPUT_RE = re.compile(r"<(?:input|textarea|select)\b[^>]*>", re.I)
ATTR_RE = re.compile(r'(\w+)\s*=\s*["\']?([^"\'>\s]+)')
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
GEN_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


def attr_dict(tag_html):
    return {k.lower(): v for k, v in ATTR_RE.findall(tag_html)}


def extract_forms(html_text, page_url):
    forms = []
    for block in FORM_RE.findall(html_text or ""):
        m = re.search(r"<form\b([^>]*)>", block, re.I)
        attrs = attr_dict(m.group(1)) if m else {}
        action = attrs.get("action", "")
        method = (attrs.get("method") or "get").lower()
        fields = []
        for itag in INPUT_RE.findall(block):
            ia = attr_dict(itag)
            name = ia.get("name")
            if not name:
                continue
            fields.append({"name": name, "type": (ia.get("type") or "text").lower(),
                           "value": ia.get("value", "")})
        abs_action = urljoin(page_url, action) if action else page_url
        forms.append({"page": page_url, "action": abs_action, "method": method,
                      "fields": fields})
    return forms


def extract_links(html_text, page_url):
    out = set()
    for link in LINK_RE.findall(html_text or ""):
        link = link.strip()
        low = link.lower()
        if low.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
            continue
        absu = urljoin(page_url, link)
        p = urlparse(absu)
        if p.scheme in ("http", "https"):
            out.add(urlunparse((p.scheme, p.netloc, p.path, "", p.query, "")))
    return out


def extract_emails(html_text):
    found = set(EMAIL_RE.findall(html_text or ""))
    cleaned = set()
    for e in found:
        if e.lower().endswith((".png", ".jpg", ".gif", ".webp", ".js")):
            continue
        cleaned.add(e.lower())
    return cleaned


def extract_comments(html_text):
    return [c.strip()[:500] for c in COMMENT_RE.findall(html_text or "")]


def extract_title(html_text):
    m = TITLE_RE.search(html_text or "")
    if m:
        return html.unescape(m.group(1)).strip()[:300]
    return ""


def strip_html(html_text):
    t = re.sub(r"(?is)<(script|style).*?</\1>", " ", html_text or "")
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    return html.unescape(re.sub(r"\s+", " ", t)).strip()


def human_time(seconds):
    seconds = int(seconds)
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    if h:
        return "%dh%02dm%02ds" % (h, m, s)
    if m:
        return "%dm%02ds" % (m, s)
    return "%ds" % s
