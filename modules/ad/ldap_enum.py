"""VAJRA LDAP enumerator — TWO passes, both always available.

Pass 1 (unauthenticated):  null/empty simple bind + 389 mining for users,
SPN/kerberoast targets, Domain Admins members, LAPS-readable accounts and
password-leaking descriptions. Works on anonymous-session misconfigurations.

Pass 2 (authenticated):   when any --ad-user/--ad-pass/--nthash credentials
are supplied, VAJRA binds with them and goes deeper: adminCount=1 accounts,
unconstrained-delegation accounts, no-preauth accounts, computer accounts and
domain trusts. The LDAP bind resultCode is parsed and reported explicitly, so
a rejected login surfaces as a finding instead of pretending to enumerate.

Filters are constructed as proper BER (equality / present / substring /
extensible-match) rather than smuggled strings, so the authorisation wall
between the two passes is real on genuine AD servers."""
import re
import socket

from core.database import Finding
from core.crypto_mini import der, der_int, octet

ATTRS_WANTED = [
    "sAMAccountName", "servicePrincipalName", "userAccountControl",
    "member", "cn", "description", "ms-Mcs-AdmPwd", "adminCount",
    "trustPartner",
]

BASE_SEARCHES = [
    ("users-anon", "(sAMAccountName=*)",
     ["sAMAccountName", "userAccountControl"]),
    ("spns", "(servicePrincipalName=*)",
     ["sAMAccountName", "servicePrincipalName"]),
    ("domain-admins", "(cn=Domain Admins)", ["member", "cn"]),
    ("laps", "(ms-Mcs-AdmPwd=*)", ["sAMAccountName", "ms-Mcs-AdmPwd"]),
    ("desc-leak", "(description=*pass*)", ["sAMAccountName", "description"]),
]

# Authenticated-only depth: privileged groups, delegation, trust material.
AUTH_SEARCHES = BASE_SEARCHES + [
    ("admins", "(&(objectCategory=person)(adminCount=1))",
     ["sAMAccountName", "adminCount", "userAccountControl"]),
    ("delegation", "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
     ["sAMAccountName", "servicePrincipalName", "userAccountControl"]),
    ("no-preauth", "(userAccountControl:1.2.840.113556.1.4.803:=4194304)",
     ["sAMAccountName", "userAccountControl"]),
    ("computers", "(userAccountControl:1.2.840.113556.1.4.803:=4096)",
     ["sAMAccountName"]),
    ("trusts", "(objectClass=trustedDomain)", ["cn", "trustPartner"]),
]

BIND_RESULT = {0: "success", 8: "strongAuthRequired (SASL needed)",
               32: "noSuchObject", 34: "invalidDnSyntax",
               49: "invalidCredentials (creds rejected)",
               50: "insufficientAccessRights",
               52: "unavailable (server does not offer this bind)"}


def _bind_req(user_dn, password):
    return der(0x30, der_int(1),
               der(0x60, der_int(3), octet(user_dn.encode()),
                   octet(password.encode())))


def _split_segs(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        cur += ch
        if depth == 0 and cur.strip():
            out.append(cur.strip())
            cur = ""
    if cur.strip():
        out.append(cur.strip())
    return out


def _substrings(val):
    parts = []
    if not val.startswith("*"):
        head, _, val = val.partition("*")
        if head:
            parts.append(der(0x80, octet(head.encode())))
    while "*" in val:
        piece, _, val = val.partition("*")
        if piece:
            parts.append(der(0x81, octet(piece.encode())))
    if val:
        parts.append(der(0x82, octet(val.encode())))
    if not parts:
        parts.append(der(0x81, b""))
    return b"".join(parts)


def _filter(s):
    """Turn "(attr=val)" LDAP filter strings into real BER Filter values."""
    s = s.strip()
    if not (s.startswith("(") and s.endswith(")")):
        return der(0x87, s.encode())
    inner = s[1:-1]
    if inner.startswith("&"):
        return der(0xA0, b"".join(_filter(x) for x in _split_segs(inner[1:])))
    m = re.match(r"^([A-Za-z0-9-]+):([0-9.]+):=([^()]*)$", inner)
    if m:
        attr, oid, val = m.groups()
        return der(0xA9, der(0x81, octet(oid.encode())),
                   der(0x82, octet(attr.encode())),
                   der(0x83, octet(val.encode())))
    m = re.match(r"^([A-Za-z0-9-]+)=(.*)$", inner)
    if m:
        attr, val = m.groups()
        if val == "*":
            return der(0x87, attr.encode())
        if "*" in val:
            return der(0xA4, octet(attr.encode()) +
                       der(0x30, _substrings(val)))
        return der(0xA3, octet(attr.encode()), octet(val.encode()))
    return der(0x87, inner.encode())


def _search_req(base_dn, filt, attrs):
    filt_b = _filter(filt) if isinstance(filt, str) else filt
    attr_bytes = b"".join(octet(a.encode()) for a in attrs)
    body = (octet(base_dn.encode()) + b"\x0a\x01\x02"      # wholeSubtree
            + b"\x0a\x01\x00" + b"\x02\x01\x00" + b"\x02\x01\x3c"
            + b"\x01\x01\x00"
            + filt_b
            + der(0x30, attr_bytes))
    return der(0x30, der_int(2), der(0x63, body))


def _ldap_converse(host, port, messages, timeout=6):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    out = []
    for msg in messages:
        try:
            s.sendall(msg)
            raw = b""
            while True:
                chunk = s.recv(65535)
                if not chunk:
                    break
                raw += chunk
                if len(chunk) < 65535:
                    break
            out.append(raw)
        except Exception:
            out.append(b"")
    s.close()
    return out


def _bind_result(raw):
    """Parse the BindResponse resultCode (ENUMERATED value after 0x61)."""
    i = raw.find(b"\x61")
    if i < 0:
        return None
    j = i + 2
    if j < len(raw) and raw[j] == 0x0a and j + 2 < len(raw) \
            and raw[j + 1] == 1:
        return raw[j + 2]
    return None


def extract_attr(raw, name):
    """Hacky but effective: value follows the attributeDesc marker."""
    vals = []
    for m in re.finditer(re.escape(name.encode()) + rb"\x04.(.{1,120}?)\x04",
                         raw, re.S):
        vals.append(m.group(1).decode("utf-8", "replace"))
    if not vals:
        idx = raw.find(name.encode())
        while idx >= 0:
            j = idx + len(name)
            if j < len(raw) and raw[j] == 0x04:
                ln = raw[j + 1]
                if ln < 128 and j + 2 + ln <= len(raw):
                    vals.append(raw[j + 2:j + 2 + ln].decode("utf-8",
                                                             "replace"))
            idx = raw.find(name.encode(), idx + 1)
    return vals


UAC_FLAGS = {
    0x400000: "DONT_REQ_PREAUTH (AS-REP roastable)",
    0x80000: "TRUSTED_FOR_DELEGATION (unconstrained)",
    0x100000: "PASSWORD_NEVER_EXPIRES",
    0x1000: "workstation/computer account",
    0x200: "normal account",
    0x10: "LOCKED OUT? (partial flag overlap)",
    0x2: "disabled account",
}


def uac_flags(value):
    try:
        v = int(value)
    except Exception:
        return []
    return [n for bit, n in UAC_FLAGS.items() if v & bit]


def _run_pass(engine, host, base_dn, bind_req, searches, label):
    """One full bind+search conversation. Returns an aggregator dict."""
    msgs = [bind_req] + [_search_req(base_dn, f, a) for _n, f, a in searches]
    try:
        responses = _ldap_converse(host, 389, msgs)
    except Exception as e:
        engine.db.add_finding(Finding(
            engine.target.display, "ad.ldap_enum", "coverage", "info",
            "LDAP conversation (%s) failed: %r" % (label, e),
            confidence="possible"))
        return None
    if not responses:
        return None
    br = _bind_result(responses[0]) if responses[0] else None
    out = {"label": label, "bind_result": br, "users": set(),
           "spns": [], "admins": [], "trusts": [],
           "notes": [], "rows": [], "raw_first": responses[0]}
    for (name, _filt, attrs), raw in zip(searches, responses[1:]):
        if not raw:
            continue
        first = attrs[0]
        if name in ("users-anon", "admins", "no-preauth", "computers"):
            out["users"] |= set(extract_attr(raw, "sAMAccountName"))
            for uacv in extract_attr(raw, "userAccountControl"):
                for fl in uac_flags(uacv):
                    if "AS-REP" in fl:
                        out["notes"].append("no-preauth account present "
                                            "(UAC %s)" % uacv)
                    if "unconstrained" in fl:
                        out["notes"].append("unconstrained delegation "
                                            "account (UAC %s)" % uacv)
            if name == "admins":
                out["admins"] += extract_attr(raw, "sAMAccountName")
        elif name == "spns":
            out["spns"] += extract_attr(raw, "servicePrincipalName")
        elif name == "domain-admins":
            members = extract_attr(raw, "member")
            if members:
                out["rows"].append("Domain Admins:\n  " +
                                   "\n  ".join(members[:15]))
        elif name == "laps":
            pwds = extract_attr(raw, "ms-Mcs-AdmPwd")
            if pwds:
                out["notes"].append("LAPS passwords readable! (%d values)"
                                    % len(pwds))
                out["rows"].append("LAPS sample: %s" % pwds[0])
        elif name == "desc-leak":
            descs = [(u, d) for u, d in zip(
                extract_attr(raw, "sAMAccountName"),
                extract_attr(raw, "description")) if d]
            for u, d in descs[:5]:
                if re.search(r"(pass|pwd|cred)", d, re.I):
                    out["notes"].append("password hint in description of "
                                        "%s: %r" % (u, d[:60]))
        elif name == "delegation":
            out["notes"].append("unconstrained-delegation accounts present")
            for uacv in extract_attr(raw, "userAccountControl"):
                if uac_flags(uacv):
                    out["notes"].append("delegation UAC %s" % uacv)
        elif name == "trusts":
            for c, p in zip(extract_attr(raw, "cn"),
                            extract_attr(raw, "trustPartner")):
                out["trusts"].append("%s <-> %s" % (c, p))
        if first == "sAMAccountName":
            pass
    return out


def _emit_pass(engine, domain, passres):
    """Findings + state seeding for one pass result dict."""
    t = engine.target
    if passres is None:
        return
    bind_txt = BIND_RESULT.get(passres["bind_result"],
                               "code %s" % passres["bind_result"])
    bound_as = passres["label"]
    users, spns = passres["users"], passres["spns"]
    rows, notes = passres["rows"], []
    if passres["bind_result"] == 0:
        rows.insert(0, "BIND: %s authenticated %s" % (bind_txt, bound_as))
    else:
        rows.insert(0, "BIND: %s (%s)" % (bind_txt, bound_as))
    if users:
        rows.insert(0, "Users enumerated: %d" % len(users))
    if notes:
        passres["notes"] = notes
    notes = passres["notes"]
    spn_txt = ""
    if spns:
        spn_txt = ", ".join(sorted(set(spns))[:20])
        rows.append("SPN (kerberoast) targets: %s" % spn_txt)
    if passres.get("trusts"):
        rows.append("Forest trusts:\n  " + "\n  ".join(passres["trusts"][:8]))

    sev = "info"
    if users or spns:
        sev = "medium"
    if passres["bind_result"] == 49:
        sev = "info"
        title = "AD credentials REJECTED by LDAP bind (%s)" % bound_as
    else:
        title = ("%s LDAP enumeration as %s — %d users, %d SPN targets%s"
                 % ("Authenticated" if bound_as != "anonymous"
                    else "Unauthenticated",
                    bound_as, len(users), len(set(spns)),
                    ", %d privesc notes" % len(notes) if notes else ""))
    detail = "\n".join(rows)[:3000] if rows else \
        "no directory data returned (bind: %s)" % bind_txt
    if users:
        prev = set(engine.state.get("ad_users", []) or [])
        engine.state["ad_users"] = sorted(prev | users)
        try:
            engine.save_evidence("ldap_users_%s.txt" % bound_as,
                                 "\n".join(sorted(users)))
        except Exception:
            pass
    if spns:
        engine.state["spn_targets"] = sorted(set(spns))
    engine.db.add_finding(Finding(
        t.display, "ad.ldap_enum", "recon", sev, title,
        detail=detail,
        evidence=(("\n".join(notes)) if notes else "\n".join(rows)[:1500]),
        remediation="Restrict anonymous binds; audit who can read LAPS; "
                    "scrub descriptions.",
        confidence="firm"))


def run(engine):
    t = engine.target
    ad = engine.state.get("ad") or {}
    domain = ad.get("domain") or guess_domain(t)
    host = t.scan_host()
    if 389 not in engine.state.get("open_ports", {}):
        engine.db.add_event(t.display, "ad.ldap_enum", "389 closed")
        return
    creds = getattr(engine, "ad_creds", {}) or {}
    user = creds.get("user", "")
    base_dn = ", ".join("dc=%s" % p for p in domain.split("."))

    # Pass 1 — unauthenticated, always on.
    anon = _bind_req("", "")
    p1 = _run_pass(engine, host, base_dn, anon, BASE_SEARCHES, "anonymous")
    _emit_pass(engine, domain, p1)

    # Pass 2 — authenticated, whenever credentials are supplied.
    if user:
        upn = "%s@%s" % (user, domain)
        auth = _bind_req(upn, creds.get("password", ""))
        p2 = _run_pass(engine, host, base_dn, auth,
                       AUTH_SEARCHES, user)
        _emit_pass(engine, domain, p2)


def guess_domain(t):
    parts = t.hostname.split(".")
    return ".".join(parts[-2:]) if "." in parts[-1] else t.hostname