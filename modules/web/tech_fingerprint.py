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
    sightings = []
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
        if gen:
            techs.add(gen.group(1).strip()[:60])
        for s in sigs:
            where = s.get("where", "body")
            pat = s.get("pattern", "")
            if where in hay and pat.lower() in hay[where]:
                techs.add(s["name"])
        if "/wp-json" in r.body or "wp-content" in r.body:
            techs.add("WordPress")
        low_headers = hay["header"]
        if "x-drupal-cache" in low_headers:
            techs.add("Drupal")
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
        engine.log.info("[tech] " + tech)
        engine.db.add_finding(Finding(
            t.display, "web.tech", "recon", "info",
            "Technology fingerprint: %s" % tech,
            confidence="firm"))
    cms = {c for c in techs if c.lower() in ("wordpress", "drupal", "joomla",
                                             "magento")}
    for c in cms:
        engine.db.add_finding(Finding(
            t.display, "web.tech", "attack-surface", "medium",
            "%s CMS deployed - plugin/theme attack surface applies" % c,
            detail="Enumerate users (/wp-json/wp/v2/users), outdated plugins, "
                   "xmlrpc.php abuse and known CVEs for the CMS version.",
            confidence="firm"))
    cve_correlation(engine, t, sightings)
