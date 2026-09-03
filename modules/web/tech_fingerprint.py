"""Vajra - web technology / CMS fingerprinting + web-version -> CVE
correlation against the built-in vulnerability database."""
import re
from urllib.parse import urlsplit

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
                    detail="Offline KB had no match for %s %s; live OSV "
                           "(exact version-range) query returned:\n%s" % (tech, version, lines),
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


def _meta_tags(body):
    """<meta name=... content=...> -> {lower_name: content}."""
    out = {}
    for m in re.finditer(r"<meta\b[^>]*>", body or "", re.I):
        tag = m.group(0)
        nm = ct = None
        for a in re.finditer(r"([\w.-]+)=([\"'])(.*?)\2", tag, re.I):
            k, v = a.group(1).lower(), a.group(3)
            if k == "name":
                nm = v.lower()
            elif k == "content":
                ct = v
        if nm:
            out[nm] = ct
    return out


def _score_page(cfg, page):
    """Per-page contribution for one technology signature, as a list of
    (weight, proof, version) entries.  Weighting is context-aware exactly
    like Wappalyzer: a self-asserting location (header, cookie, meta
    generator) is worth 2x a URL marker, which is worth 2x a bounded html
    marker; plain text words are not signatures at all."""
    out = []
    headers = {k.lower(): str(v) for k, v in (page.get("headers") or {}).items()}
    for hname, hrx in (cfg.get("headers") or {}).items():
        val = headers.get(hname)
        if val is None:
            continue
        if hrx and not re.search(hrx, val, re.I):
            continue
        out.append((6, "header %s: %s" % (hname, val[:60]), ""))
    seth = (headers.get("set-cookie") or "").lower()
    for ck in cfg.get("cookies") or []:
        if _bounded_in(ck.lower(), seth):
            out.append((6, "cookie: " + ck, ""))
            break
    for mname, mrx in (cfg.get("meta") or {}).items():
        mval = (page.get("meta") or {}).get(mname)
        if mval and (not mrx or re.search(mrx, mval, re.I)):
            out.append((7, "meta[%s]: %s" % (mname, mval[:60]), ""))
    u = urlsplit(page.get("url") or "").path.lower()
    for up in cfg.get("url") or []:
        if up in u:
            out.append((5, "path: " + up, ""))
            break
    low = (page.get("body") or "").lower()
    for hp in cfg.get("html") or []:
        if _bounded_in(hp, low):
            out.append((3, "html: " + hp, ""))
    return out


def _detect_techs(sigs, pages):
    """Aggregate per-signature weights across pages.  A signature only scores
    once per DISTINCT marker — repeating the same template footer on 20 pages
    does not turn a weak marker into a firm claim."""
    res = {}
    for cfg in sigs:
        name = cfg.get("name")
        weight = 0
        proofs = []
        seen = set()
        for p in pages:
            for w, proof, _v in _score_page(cfg, p):
                if proof in seen:
                    continue
                seen.add(proof)
                weight += w
                proofs.append(proof)
        if weight >= 3:
            strong = any(x.startswith(("header ", "cookie:", "meta["))
                         for x in proofs)
            version = ""
            if cfg.get("version") and proofs:
                cols = {
                    "html": "body",
                }
                for p in pages[:6]:
                    blob = "%s\n%s %s" % (
                        p.get("body") or "",
                        (p.get("headers") or {}).get("server", ""),
                        (p.get("headers") or {}).get("x-powered-by", ""))
                    m = re.search(cfg["version"], blob, re.I)
                    if m:
                        version = m.group(1)
                        break
            res[name] = {"score": weight, "proofs": proofs[:8],
                         "version": version, "strong": strong}
    return res


def _cms_markers_from(pages):
    """Aggregate weighted CMS markers across every crawled page."""
    counts = {}
    for p in pages:
        hay = {"body": (p.get("body") or ""),
               "header": " ".join(str(v) for v in
                                  (p.get("headers") or {}).values())}
        for c, seen in _cms_markers(hay).items():
            counts.setdefault(c, set()).update(seen)
    return counts


def _strong_cms_from(gen_low, c):
    return bool(gen_low and _bounded_in(c, gen_low))


# Cloud / CDN / object-storage markers. The cloud exposure scan must only run
# when evidence of a cloud-backed target is found (never on every target).
CLOUD_TECH = {"Cloudflare", "Akamai", "Fastly", "AWS CloudFront", "Azure",
              "Google Cloud", "Amazon S3", "AWS", "GCP"}
CLOUD_HOST_HINTS = (".s3.", ".s3.amazonaws.com", ".blob.core.windows.net",
                    ".storage.googleapis.com", ".cloudfront.net", ".azurefd.net",
                    ".akamaiedge.net", ".fastly.net", ".aliyuncs.com",
                    ".amazonaws.com")


def _flag_cloud(engine, techs, pages):
    """Set engine.state['cloud_indicators'] True only when concrete cloud
    evidence exists — a known cloud/CDN technology fingerprint, or a web/url
    hostname that points at a cloud storage/CDN domain."""
    hits = set()
    for name in techs:
        if name in CLOUD_TECH:
            hits.add(name)
    hay = []
    for wt in engine.state.get("web_targets", []) or []:
        try:
            hay.append(urlsplit(wt["url"]).netloc.lower())
        except Exception:
            pass
    for p in pages:
        hdr = " ".join(str(v).lower() for v in (p.get("headers") or {}).values())
        if any(h in hdr for h in (".cloudfront.net", ".azurefd.net",
                                  ".akamaiedge.net", "x-amz-", ".s3.")):
            hits.add("cloud-headers")
    host = (engine.target.hostname or "").lower()
    if any(h in host for h in CLOUD_HOST_HINTS):
        hits.add("cloud-hostname")
    if hits:
        engine.state["cloud_indicators"] = True
        engine.state.setdefault("cloud_tech", []).extend(sorted(hits))
        engine.log.info("[cloud] cloud-backed target detected (%s) — "
                        "enabling cloud exposure scan"
                        % ", ".join(sorted(hits)))


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    try:
        sigs = load_json("intel/signatures.json").get("tech_signatures", [])
    except Exception:
        sigs = []
    pages = []
    for wt in targets:
        base = wt["url"].rstrip("/")
        r = engine.http.get(base + "/")
        if r.status == 0:
            continue
        pages.append({"url": base + "/", "headers": r.headers,
                      "body": r.body, "meta": _meta_tags(r.body)})
    for p in (engine.state.get("pages") or [])[:80]:
        pages.append({"url": p["url"], "headers": p["headers"],
                      "body": p.get("body") or "", "meta": _meta_tags(
                          p.get("body") or "")})
    det = _detect_techs(sigs, pages)
    gen = None
    gen_low = ""
    for p in pages[:6]:
        gv = (p.get("meta") or {}).get("generator")
        if gv:
            gen = gv
            gen_low = gv.lower()
            break
    if gen and not any(gen_low.startswith(n.lower()) for n in det):
        det.setdefault(gen.strip()[:60],
                       {"score": 9, "proofs": ["meta generator: " + gen],
                        "version": "", "strong": True})
    techs = {name for name, d in det.items() if d["score"] >= 3}
    tech_proof = {name: d["proofs"][0] if d["proofs"] else name
                  for name, d in det.items()}
    strong = {name for name, d in det.items() if d["strong"]}
    _flag_cloud(engine, techs, pages)
    sightings = []
    for p in pages:
        needle = "%s %s %s" % (
            (p.get("headers") or {}).get("server", ""),
            (p.get("headers") or {}).get("x-powered-by", ""),
            (p.get("body") or "")[:3000])
        seen_v = set()
        for rx, tech in VERS_HUNTERS:
            m = rx.search(needle)
            if m and (tech, m.group(1)) not in seen_v:
                seen_v.add((tech, m.group(1)))
                sightings.append((tech, m.group(1), p.get("url", "")))
    engine.state.setdefault("tech", sorted(techs))
    for tech in sorted(techs):
        info = det[tech]
        if tech.lower() in CMS_ACTIONS:
            continue                        # CMS findings emitted below
        if info["strong"] or info["score"] >= 6:
            vtxt = " %s" % info["version"] if info["version"] else ""
            engine.log.info("[tech] " + tech + vtxt)
            engine.db.add_finding(Finding(
                t.display, "web.tech", "recon", "info",
                "Technology fingerprint: %s%s" % (tech, vtxt),
                evidence="; ".join(info["proofs"]),
                confidence="firm"))
        else:
            engine.db.add_finding(Finding(
                t.display, "web.tech", "recon", "info",
                "Possible %s — unverified signal" % tech,
                detail="Only weak/bounded page markers matched (%d pts); "
                       "the word alone can be prose or copied templates. Runs "
                       "as a lead, not as a confirmed technology." % info["score"],
                evidence="; ".join(info["proofs"]),
                confidence="possible"))
            engine.log.info("[tech] %s possible (score %d, UNVERIFIED) %s"
                            % (tech, info["score"], info["proofs"][:1]))
    for c in sorted(CMS_ACTIONS):
        info = det.get(c)
        markers = _cms_markers_from(pages)
        if not info and not markers[c]:
            continue
        # A CMS claim backed only by the discounted generic word token (e.g.
        # 'wordpress' appearing in prose/footer) is not worth a finding — it is
        # noise. Require at least one real structural marker before reporting
        # even a weak/possible CMS signal.
        structural = [t for t, w in markers[c] if w == 1.0]
        if not structural:
            continue
        base = targets[0]["url"].rstrip("/") if targets else ""
        probe_note = None
        firm = bool(info and (info["score"] >= 6 or info["strong"])) or \
            _strong_cms_from(gen_low, c) or _firm_cms(c, markers[c])
        if not firm and info and base:
            probe_note = _confirm_cms_probe(engine, base, c)
            firm = bool(probe_note)
        toks = ", ".join(sorted(set(t for t, _w in markers[c]) or
                                [info["proofs"][0] if info else c])) or "-"
        title, detail, remed = CMS_ACTIONS[c]
        if firm:
            extra = (probe_note or
                     (info and "; ".join(info["proofs"])[:160]) or
                     "two independent CMS markers observed")
            engine.db.add_finding(Finding(
                t.display, "web.tech", "attack-surface", "medium", title,
                detail="%s\nConfirmed by: %s" % (detail, extra),
                evidence="%s\n%s" % (c, extra),
                remediation=remed, confidence="firm"))
            engine.log.finding("[cms] %s CONFIRMED (%s)" % (c, extra))
        else:
            engine.db.add_finding(Finding(
                t.display, "web.tech", "recon", "info",
                "Possible %s — unverified signal" % c,
                detail="Signals found on %s (%s). A copied theme or the "
                       "CMS word alone is not proof; promote with a second "
                       "marker or a signature probe." % (base, toks),
                evidence="on %s: %s" % (base, toks),
                confidence="possible"))
            engine.log.info("[cms] %s present? weak signal — UNVERIFIED" % c)
    cve_correlation(engine, t, sightings)
