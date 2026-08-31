"""Vajra - web technology / CMS fingerprinting + web-version -> CVE
correlation against the built-in vulnerability database."""
import re

from core.database import Finding
from core.utils import load_json, GEN_RE

VERS_HUNTERS = [
    (re.compile(r"Apache/([\d.]+)", re.I), "apache"),
    (re.compile(r"nginx/([\d.]+)", re.I), "nginx"),
    (re.compile(r"(?:php(?:/| ))([\d.]+)", re.I), "php"),
    (re.compile(r"PHP/([\d.]+)", re.I), "php"),
    (re.compile(r"phpMyAdmin\s+([\d.]+)", re.I), "phpmyadmin"),
    (re.compile(r"Grafana\s*v?([\d.]+)", re.I), "grafana"),
    (re.compile(r"Apache-Coyote(?:/)([\d.]+)", re.I), "tomcat"),
    (re.compile(r"WordPress\s+([\d.]+)", re.I), "wordpress"),
    (re.compile(r"Joomla!\s*([\d.]+)", re.I), "joomla"),
    (re.compile(r"Drupal\s*([\d.]+)", re.I), "drupal"),
    (re.compile(r"Jenkins\s*([\d.]+)", re.I), "jenkins"),
    (re.compile(r"GitLab\s*([\d.]+)", re.I), "gitlab"),
    (re.compile(r"ThinkPHP(?:/)?\s*([\d.]+)", re.I), "thinkphp"),
    (re.compile(r"Tomcat/[\w.]*([\d.]+)", re.I), "tomcat"),
]

_RANGE_OPS = re.compile(r"^(<=|>=|<|>|==|=)\s*(.*)$")

# CMS findings must carry their own, accurate play-notes — never copy the
# WordPress text onto Magento/Drupal/Joomla (that was an obvious false
# positive in the report).
CMS_ACTIONS = {
    "wordpress": (
        "WordPress CMS deployed - plugin/theme attack surface applies",
        "WordPress marker seen in a first-party page. Playbook: enumerate "
        "users (wp-json/wp/v2/users), list outdated plugins/themes, probe "
        "xmlrpc.php (pingback/ping), and correlate the core + plugin versions "
        "against known CVEs. Lock down the admin surface and XML-RPC if "
        "unused.",
        "Harden: disable XML-RPC, auto-update core+plugins, enforce app "
        "passwords and 2FA on admins."),
    "drupal": (
        "Drupal CMS deployed - module/theme attack surface applies",
        "Drupal marker seen in a first-party page. Playbook: enumerate users "
        "(/user/register, /user/login), outdated modules/themes, and core "
        "CVEs (e.g. Drupalgeddon)."),
    "joomla": (
        "Joomla CMS deployed - extension/theme attack surface applies",
        "Joomla marker seen in a first-party page. Playbook: enumerate "
        "super-users (/administrator), outdated extensions, and known Joomla "
        "core CVEs."),
    "magento": (
        "Magento CMS deployed - extension/theme attack surface applies",
        "Magento marker seen in a first-party page. Playbook: enumerate store "
        "routes (/admin, /catalogsearch), outdated Magento versions and "
        "known CVEs (RCE/XXE chains), exposed /static and setup endpoints."),
    "shopify": (
        "Shopify store detected - template/app attack surface",
        "Shopify platform marker seen in a first-party page. Playbook: review "
        "public app/theme surfaces; backend is SaaS-managed."),
}


def _bounded_in(pat, text):
    """True when pat occurs in text and is NOT the suffix of a longer token —
    'mage/' must NOT match inside 'image/' (a plain substring match would
    report Magento on every page containing an <img> tag). Only the character
    immediately BEFORE the pattern matters: markers may legitimately be
    followed by more path ('mage/static/...')."""
    plen = len(pat)
    if plen == 0:
        return False
    start = 0
    while True:
        i = text.find(pat, start)
        if i < 0:
            return False
        before = text[i - 1] if i > 0 else ""
        if i == 0 or not (before.isalnum() or before == "_"):
            return True
        start = i + 1


def _ver_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v)))


def _range_match(oprn, version):
    m = _RANGE_OPS.match(oprn.strip())
    if not m:
        return False
    op, bound = m.group(1), _ver_tuple(m.group(2))
    v = _ver_tuple(version)
    for i in range(min(len(v), len(bound))):
        if v[i] != bound[i]:
            break
    else:
        n = min(len(v), len(bound))
        v, bound = v[:n], bound[:n]
        if len(v) < len(bound):
            v = v + (0,) * (len(bound) - len(v))
        elif len(bound) < len(v):
            bound = bound + (0,) * (len(v) - len(bound))
    if op == "<=":
        return v <= bound
    if op == "<":
        return v < bound
    if op == ">=":
        return v >= bound
    if op == ">":
        return v > bound
    return v == bound


def _cve_for(product_cfg, tech, version):
    found = []
    for rng, cves in (product_cfg.get("ranges") or {}).items():
        try:
            if _range_match(rng, version):
                found.extend(cves)
        except Exception:
            continue
    return found


def cve_correlation(engine, t, version_sightings):
    """version_sightings: list of (tech_key, version, source). Match against
    intel/cve_db.json product ranges and emit findings."""
    try:
        db = load_json("intel/cve_db.json").get("products", {})
    except Exception:
        return
    seen = set()
    for tech, version, source in version_sightings:
        key = (tech, version)
        if key in seen:
            continue
        seen.add(key)
        cfg = db.get(tech)
        if not cfg:
            cfg = next((v for k, v in db.items()
                        if tech in v.get("aliases", [])), None)
        hits = []
        if cfg:
            hits = _cve_for(cfg, tech, version)
        if not hits and getattr(engine, "cve_update", False) and \
                getattr(engine, "online", True):
            try:
                from core.cve_refresh import lookup_online
                live = lookup_online(tech, version)
            except Exception:
                live = None
            if live:
                lines = "\n".join("%s (%.1f) %s" % (e["id"], e["cvss"],
                                                    e["summary"])
                                  for e in live[:8])
                engine.db.add_finding(Finding(
                    t.display, "web.tech", "vuln-exposure", "medium",
                    "Live CVE pulse: %s %s (%s)" % (tech, version, len(live)),
                    detail="Offline KB had no match for %s %s; live CIRCL "
                           "query returned:\n%s" % (tech, version, lines),
                    evidence="%s %s" % (tech, version),
                    remediation="Validate the versions against vendor "
                                "advisories; upgrade out of range.",
                    confidence="possible"))
                engine.log.finding("[CVE-online] %s %s -> %d CVE(s)" %
                                   (tech, version, len(live)))
                continue
        if not hits:
            continue
        cvss = [float(c.split("|")[2]) for c in hits
                if len(c.split("|")) > 2]
        maxcv = max(cvss) if cvss else 0.0
        sev = "high" if maxcv >= 9.0 else ("medium" if maxcv >= 6.0 else "info")
        lines = "\n".join("%s (%.1f) %s" % (h.split("|")[0],
                                            float(h.split("|")[2])
                                            if len(h.split("|")) > 2 else 0,
                                            h.split("|")[1])
                          for h in hits[:12])
        engine.db.add_finding(Finding(
            t.display, "web.tech", "vuln-exposure", sev,
            "Web tech %s %s matches %d known CVE range(s)" %
            (tech, version, len(hits)),
            detail="Version captured from: %s\nAffected ranges:\n%s"
                   % (source, lines),
            evidence="%s %s" % (tech, version),
            remediation="Upgrade the component past the affected version; "
                        "track CVE feeds for it.",
            confidence="firm"))
        engine.log.finding("[CVE] %s %s -> %d CVE range(s) (peak %.1f)"
                           % (tech, version, len(hits), maxcv))


# Free-text words (python, apache, jenkins, ...) false-positive in prose
# ("Check our python guides").  Generic tech is only asserted when it appeared
# in a strong context (server/protocol header, generator meta, X-Powered-By)
# or via >=2 distinct markers; a lone body word stays an unverified 'possible'.
GENERIC_TECH = {"php", "python", "apache", "nginx", "tomcat", "jenkins",
                "grafana", "express", "laravel", "django", "drupal",
                "joomla", "magento"}

# Distinct, CMS-specific markers.  A single marker may still be copied page
# furniture (a theme link someone pasted); two independent markers — or one
# marker plus an active signature probe below — promote the claim to firm.
CMS_MARKERS = {
    "wordpress": ("wp-content", "wp-json", "wp-login", "wp-includes",
                  "wp-submit", "wordpress"),
    "drupal": ("drupal", "x-drupal-cache", "form_build_id", "misc/drupal"),
    "joomla": ("joomla", "com_login", "mod_login", "media/jui",
               "/administrator"),
    "magento": ("mage/", "mage/static", "data-mage-init", "magento"),
    "shopify": ("cdn.shopify.com", "shopify", "myshopify"),
}

CMS_PROBES = {
    "wordpress": ("/wp-login.php",
                  ("wp-submit", "user_login", "wp-login")),
    "drupal": ("/user/login",
               ("form_build_id", "user-login-form", "edit-name")),
    "joomla": ("/administrator/",
               ("com_login", "mod_login", "login-form")),
}


FIRM_TOKENS = {"cdn.shopify.com", "wp-login", "data-mage-init", "mage/static",
               "x-drupal-cache", "form_build_id"}


def _cms_markers(hay):
    """Distinct CMS-specific markers observed in the page (as their lowercase
    tokens).  Counter is offset so that the shared generic word token (e.g.
    'drupal') counts half as much as a real structural marker — two real
    markers are required for a firm claim, a lone generic word never."""
    counts = {}
    for c, toks in CMS_MARKERS.items():
        seen = set()
        blob = "%s %s" % (hay.get("body", ""), hay.get("header", ""))
        for tok in toks:
            if _bounded_in(tok, blob):
                weight = 0.5 if tok in GENERIC_TECH else 1.0
                seen.add((tok, weight))
        counts[c] = seen
    return counts


def _firm_cms(c, markers):
    """Two weighted-distinct markers (>=1.5 for structural tokens, or >=2.0
    counting one generic word) make the CMS claim firm."""
    weight = sum(w for _t, w in markers)
    structural = sum(1 for _t, w in markers if w == 1.0)
    return structural >= 2 or weight >= 1.5 and structural >= 1


def _confirm_cms_probe(engine, base, c):
    path, sigs = CMS_PROBES.get(c, ("", ()))
    if not path:
        return None
    try:
        r = engine.http.get(base + path)
        if r.status != 200:
            return None
        low = r.body[:40000].lower()
        for s in sigs:
            if _bounded_in(s, low):
                return "%s returned %s signature ('%s')" % (path, r.status, s)
    except Exception:
        return None
    return None


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    try:
        sigs = load_json("intel/signatures.json").get("tech_signatures", [])
    except Exception:
        sigs = []
    techs = set()
    tech_proof = {}          # tech -> first observed  (url : where : sample)
    strong = set()           # techs seen in a self-asserting context
    sightings = []
    cms_counts = {}
    strong_cms = set()
    for wt in targets:
        base = wt["url"].rstrip("/")
        r = engine.http.get(base + "/")
        if r.status == 0:
            continue
        hay = {
            "header": " ".join("%s:%s" % (k, v) for k, v in list(r.headers.items())[:20]).lower(),
            "body": r.body[:20000].lower(),
            "cookie": r.cookies_str.lower(),
            "path": "",
        }
        gen = GEN_RE.search(r.body)
        gen_low = (gen.group(1).strip()[:60].lower()
                   if gen else "")
        if gen:
            techs.add(gen.group(1).strip()[:60])
        for s in sigs:
            where = s.get("where", "body")
            pat = s.get("pattern", "")
            if where in hay and _bounded_in(pat, hay[where]):
                name = s["name"]
                techs.add(name)
                tech_proof.setdefault(name, (base, where, pat))
                if where in ("header", "cookie"):
                    strong.add(name)
        for c in CMS_ACTIONS:
            if gen_low and _bounded_in(c, gen_low):
                strong.add(c.capitalize())
                strong_cms.add(c)
        mc = _cms_markers(hay)
        for c, seen in mc.items():
            cms_counts.setdefault(c, set()).update(seen)
        needle = "%s %s %s" % (r.headers.get("server", ""),
                               r.headers.get("x-powered-by", ""),
                               r.body[:3000])
        seen_v = set()
        for rx, tech in VERS_HUNTERS:
            m = rx.search(needle)
            if m and (tech, m.group(1)) not in seen_v:
                seen_v.add((tech, m.group(1)))
                sightings.append((tech, m.group(1), base))
    engine.state.setdefault("tech", sorted(techs))
    for tech in sorted(techs):
        proof = tech_proof.get(tech) or ("", "body", "")
        _, _where, _pat = proof
        key = tech.lower()
        if key in CMS_ACTIONS:
            continue                       # CMS findings emitted below
        if tech.lower() in GENERIC_TECH and tech not in strong:
            engine.db.add_finding(Finding(
                t.display, "web.tech", "recon", "info",
                "Possible %s — unverified body marker" % tech,
                detail="The word '%s' appears in page body only; a copied "
                       "template or prose could match it. Runs as a lead, "
                       "not as a confirmed technology." % _pat,
                evidence="marker '%s' in %s of GET %s/" % (_pat, _where,
                                                           proof[0] or "-"),
                confidence="possible"))
            engine.log.info("[tech] %s (body-only marker, UNVERIFIED)" % tech)
            continue
        engine.log.info("[tech] " + tech)
        engine.db.add_finding(Finding(
            t.display, "web.tech", "recon", "info",
            "Technology fingerprint: %s" % tech,
            evidence="%s" % (_pat or tech),
            confidence="firm"))
    for c in sorted(CMS_ACTIONS):
        markers = cms_counts.get(c, set())
        if not markers and c.capitalize() not in techs and \
                c not in {x.lower() for x in techs}:
            continue
        base = tech_proof.get(c.capitalize(),
                              tech_proof.get(c, ("", "body", "")))[0] \
            or (targets[0]["url"].rstrip("/") if targets else "")
        probe_note = None
        firm = _firm_cms(c, markers) or any(
            tok in FIRM_TOKENS for tok, _w in markers) or \
            c in strong_cms
        if not firm and markers and base:
            probe_note = _confirm_cms_probe(engine, base, c)
            firm = bool(probe_note)
        toks = ", ".join(sorted(t for t, _w in markers)) or "-"
        title, detail, remed = CMS_ACTIONS[c]
        if firm:
            extra = probe_note or "two independent CMS markers observed"
            engine.db.add_finding(Finding(
                t.display, "web.tech", "attack-surface", "medium", title,
                detail="%s\nObserved on %s\nConfirmed by: %s" %
                       (detail, base, extra),
                evidence="%s\nMarkers: %s\n%s" % (c, toks, extra),
                remediation=remed, confidence="firm"))
            engine.log.finding("[cms] %s CONFIRMED (%s)" % (c, extra))
        else:
            engine.db.add_finding(Finding(
                t.display, "web.tech", "recon", "info",
                "Possible %s — single unverified marker" % c,
                detail="One marker ('%s') found on %s; that can be copied "
                       "theme furniture or prose. Needs a second marker or "
                       "a signature probe to be promoted." % (toks, base),
                evidence="markers on %s: %s" % (base, toks),
                confidence="possible"))
            engine.log.info("[cms] %s present? single marker — UNVERIFIED" % c)
    cve_correlation(engine, t, sightings)
