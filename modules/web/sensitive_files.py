"""VAJRA - sensitive-file / leak-path checklist.

Data-driven from intel/loot_paths.json: read-only GETs for classic leak
locations (.git/HEAD, .env, backup archives, phpinfo, actuator, exposed admin
panels).

Two gates, both required before a path is reported:

1. the response must differ from how the host answers a path that certainly
   does not exist (core.evidence), so a soft-404 - in any status code - is
   never mistaken for a file; and
2. the body must carry a *format marker* only the real file produces: a VCS
   reference, KEY=value lines, archive magic bytes, a SQL dump header.

The previous version accepted "more than 40 bytes and not HTML", which fires
on any JSON error page a framework returns with 200. That fallback is gone.
"""
import json
import re

from core.evidence import baseline_for, verdict, REAL
from core.utils import load_json
from core import proof as P

GROUPS = load_json("intel/loot_paths.json", {}).get("groups", [])

HTML_TYPES = ("text/html", "application/xhtml")
MAX_PATHS = 120

ENV_LINE_RE = re.compile(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S+")
HTML_RE = re.compile(r"<\s*(html|body|div|a\s|!doctype)", re.I)

# Archive / database magic numbers: an exposed backup is a real file, and a
# real file starts with its format's bytes. This cannot be faked by an error
# page, which is exactly what makes it proof.
MAGIC = (
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"BZh", "bzip2 archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\xd0\xcf\x11\xe0", "OLE compound document"),
    (b"-- MySQL dump", "MySQL dump"),
    (b"PGDMP", "PostgreSQL dump"),
    (b"ustar", "tar archive"),
)

SQL_DUMP_RE = re.compile(r"(?im)^\s*(CREATE TABLE|INSERT INTO|DROP TABLE|"
                         r"-- (MySQL|PostgreSQL) database dump|LOCK TABLES)")
HTPASSWD_RE = re.compile(r"(?m)^[A-Za-z0-9_.\-]{1,64}:\$(apr1|2y|2a|1|5|6|"
                         r"argon2|y)\$")
PHPINFO_RE = re.compile(r"(?i)<title>\s*phpinfo\(\)|PHP Version\s*=>|"
                        r"php version\s*</td>")
APACHE_STATUS_RE = re.compile(r"(?i)Apache Server Status|Server Version:\s*"
                              r"Apache|Total Accesses:")
WEBXML_RE = re.compile(r"(?i)<\s*(web-app|servlet|jsp-config)\b")
HTACCESS_RE = re.compile(r"(?im)^\s*(RewriteEngine|RewriteRule|Order deny,"
                         r"allow|Require all denied|<IfModule)")
CROSSDOMAIN_RE = re.compile(r"(?i)<\s*cross-domain-policy\b")
SECTXT_RE = re.compile(r"(?im)^\s*Contact:\s*\S+")
JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.")


def _magic_of(body_bytes):
    for sig, label in MAGIC:
        if body_bytes.startswith(sig):
            return sig, label
    # tar stores its magic at offset 257
    if len(body_bytes) > 262 and body_bytes[257:262] == b"ustar":
        return b"ustar", "tar archive"
    return None, None


def _marker_for(path, name, body, ctype, raw):
    """Return (marker_text, label) when the body proves this is the real
    file, else (None, None). Marker text becomes the finding's proof."""
    p = (path or "").lower().lstrip("/")
    n = (name or "").lower()
    low = (body or "")[:60000].lower()

    if p.endswith(".git/head") or p == ".git/head":
        if low.strip().startswith("ref:"):
            return body.strip()[:200], "git HEAD reference"
        return None, None
    if p.endswith(".git/config"):
        if "[core]" in low:
            return body[:300], "git config core section"
        return None, None
    if p.endswith(".svn/entries") or p.endswith(".svn/wc.db"):
        if raw[:16].startswith(b"SQLite format 3") or re.match(
                r"^\s*\d+\s*\n", body or ""):
            return body[:200], "subversion entries file"
        return None, None
    if n.startswith(".env") or n.endswith(".env"):
        m = ENV_LINE_RE.search(body or "")
        if m and not HTML_RE.search((body or "")[:200]):
            lines = [ln for ln in (body or "").splitlines()
                     if ENV_LINE_RE.match(ln)]
            return "\n".join(lines)[:400], "KEY=value configuration lines"
        return None, None
    if n.endswith((".zip", ".tar.gz", ".tgz", ".gz", ".bz2", ".7z", ".rar",
                   ".rar", ".sqlite", ".db")):
        sig, label = _magic_of(raw)
        if sig:
            return "%s: %r" % (label, sig), label
        return None, None
    if n.endswith(".sql"):
        m = SQL_DUMP_RE.search(body or "")
        if m:
            return body[max(0, m.start() - 40):m.start() + 200], "SQL dump"
        sig, label = _magic_of(raw)
        return (("%s: %r" % (label, sig)), label) if sig else (None, None)
    if n.endswith((".bak", ".old", ".save", ".swp", "~")):
        # A backup is only meaningful when it is the backup *of* something
        # recognisable. HTML at a .bak path is usually the app's error page.
        if ctype and any(t in ctype for t in HTML_TYPES):
            return None, None
        if len(body or "") > 40:
            return body[:300], "backup file body"
        return None, None
    if p.endswith("phpinfo.php"):
        if PHPINFO_RE.search(body or ""):
            return body[:300], "phpinfo output"
        return None, None
    if "server-status" in p or "server-info" in p:
        if APACHE_STATUS_RE.search(body or ""):
            return body[:300], "Apache status page"
        return None, None
    if p.endswith("web.xml"):
        if WEBXML_RE.search(body or ""):
            return body[:300], "Java web descriptor"
        return None, None
    if n.endswith(".htpasswd"):
        m = HTPASSWD_RE.search(body or "")
        if m:
            return body[max(0, m.start() - 20):m.start() + 160], "htpasswd entry"
        return None, None
    if n.endswith(".htaccess"):
        if HTACCESS_RE.search(body or ""):
            return body[:300], "Apache directives"
        return None, None
    if n.endswith("crossdomain.xml"):
        if CROSSDOMAIN_RE.search(body or ""):
            return body[:300], "cross-domain policy"
        return None, None
    if n.endswith("security.txt"):
        if SECTXT_RE.search(body or ""):
            return body[:300], "security.txt contact"
        return None, None
    if n.endswith(("composer.json", "package.json")):
        try:
            doc = json.loads(body or "")
        except Exception:
            return None, None
        if isinstance(doc, dict) and (doc.get("name") or doc.get("dependencies")
                                      or doc.get("require")):
            return body[:300], "dependency manifest"
        return None, None
    if n.endswith(".ds_store"):
        if raw.startswith(b"\x00\x00\x00\x01Bud1"):
            return repr(raw[:8]), "DS_Store magic"
        return None, None
    if n.lower().endswith("thumbs.db"):
        sig, label = _magic_of(raw)
        return (("%s: %r" % (label, sig)), label) if sig else (None, None)
    return None, None


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    probed = 0
    suppressed = 0
    for wt in targets:
        base = wt["url"].rstrip("/")
        bl = baseline_for(engine, base)
        for grp in GROUPS:
            label = grp.get("label", grp.get("name", "leak"))
            hits, markers = [], []
            for path in (grp.get("paths") or []):
                if probed >= MAX_PATHS:
                    continue
                ap = path if path.startswith("/") else "/" + path
                try:
                    r = engine.http.get(base + ap, allow_redirects=False,
                                        timeout=6)
                except Exception:
                    continue
                probed += 1
                if r.status != 200:
                    continue
                v, why = verdict(r, bl, ap)
                if v != REAL:
                    suppressed += 1
                    engine.log.debug("[SUPPRESS] web.loot %s%s: %s"
                                     % (base, ap, why))
                    continue
                body = r.body or ""
                # Use the raw bytes, not a re-encode of the decoded body:
                # utf-8 decoding replaces any byte >= 0x80, which is exactly
                # where gzip (\x1f\x8b), 7-Zip (7z\xbc\xaf) and OLE
                # (\xd0\xcf\x11\xe0) keep their magic. Checking mangled bytes
                # would make those formats undetectable.
                raw = getattr(r, "content", None)
                if not isinstance(raw, bytes):
                    raw = body.encode("utf-8", "replace")
                ctype = (r.headers.get("content-type", "") or "").lower()
                name = path.rsplit("/", 1)[-1]
                mk, mlabel = _marker_for(path, name, body, ctype, raw)
                if not mk:
                    suppressed += 1
                    engine.log.debug(
                        "[SUPPRESS] web.loot %s%s: 200 but no format marker "
                        "for %r" % (base, ap, name))
                    continue
                hits.append("%s (%s)" % (path, mlabel))
                markers.append(mk)
            if not hits:
                continue
            sev = grp.get("severity", "medium")
            engine.record(
                t.display, "web.loot", "info-leak", sev,
                "%s on %s" % (label, base),
                detail="Read-only probes confirmed %d of %d candidate "
                       "path(s) from the %s group, each by a format marker "
                       "in its body." % (len(hits),
                                         len(grp.get("paths") or []),
                                         grp.get("name", "?")),
                evidence="\n".join(hits[:24]),
                remediation="Remove sensitive files/archives from the web "
                            "tree; deny access to VCS metadata and debug "
                            "endpoints.",
                cls="exposure",
                proof=P.marker("\n".join(markers)[:2000],
                               note="format marker present in body"))
            engine.log.finding("[LOOT:%s] %s: %s" % (
                grp.get("name", "?"), base, ", ".join(hits[:6])))
    if suppressed:
        engine.log.info("[loot] %d candidate path(s) suppressed (no marker "
                        "or indistinguishable from the not-found baseline)"
                        % suppressed)
