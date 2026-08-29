"""VAJRA upload handling (web.upload): find multipart/file-input forms, verify
what happens to hostile filenames (traversal, double-extension, null-byte,
server-side extension) and whether uploaded content is stored AND retrievable
with our marker — the storage+server step that turns an upload form into
arbitrary-file upload / webshell surface.

Benign uploads only; payload content is inert in every case."""
import re
import time

from core.database import Finding
from core.http_client import build_multipart

MARKER = "vaju7391"
LOC_RE = re.compile(r"[`'\"]?/?uploads?[^\s'\"]{0,80}", re.I)


def _upload_points(engine):
    seen = set()
    for page in engine.state.get("pages", []):
        for f in page.get("forms", []):
            fields = f.get("fields", [])
            is_multipart = (f.get("enctype") or "").lower().find("multipart") >= 0
            has_file = any(fd.get("type") == "file" for fd in fields)
            if not (is_multipart or has_file):
                continue
            url = f.get("action")
            key = (f.get("method", "POST").upper(), url)
            if key in seen:
                continue
            seen.add(key)
            yield url, f.get("method", "POST").upper(), fields


def _grab_stored_urls(body, headers):
    urls = []
    loc = headers.get("location", "")
    if loc:
        urls.append(loc)
    for m in LOC_RE.findall(body):
        s = m.strip().strip("\"'")
        if s.startswith(("/", "http")):
            urls.append(s)
    return list(dict.fromkeys(urls))[:4]


def run(engine):
    t = engine.target
    points = list(_upload_points(engine))
    if not points:
        engine.state.setdefault("no_upload_surfaces", True)
        engine.log.warn("[upload] no multipart/file forms discovered")
        return
    for idx, (url, method, fields) in enumerate(points):
        if idx >= 3:
            break
        base = url.split("?")[0]
        host_hint = engine.state.get("web_targets", [{}])[0].get("url", "")
        results = {}
        benign = b"vajra benign upload test " + MARKER.encode()
        cases = [
            ("benign", "vajra_test.txt", "text/plain", benign),
            ("traversal", "../../vajra_up.php", "application/x-php",
             b"<?php // vajra inert marker " + MARKER.encode()),
            ("double-ext", "vajra_avatar.jpg.php", "image/jpeg",
             b"vajra jpeg\n" + MARKER.encode()),
            ("nullbyte", "vajra_shell.php\x00.jpg", "image/jpeg", benign),
            ("rx-html", "vajra_payload.html", "text/html", benign),
        ]
        for label, fname, ctype, blob in cases:
            ctype_m, body = build_multipart(
                fields={fd["name"]: fd.get("value", "")
                        for fd in fields
                        if fd.get("type") not in ("submit", "button",
                                                  "file")},
                files=[("file", fname, ctype, blob)])
            try:
                r = engine.http.request(method, base,
                                        data=body,
                                        headers={"Content-Type": ctype_m},
                                        allow_redirects=False, timeout=8)
                results[label] = r
            except Exception:
                results[label] = None
            time.sleep(0.25)
        stored = {}
        for label in ("traversal", "double-ext", "nullbyte", "rx-html"):
            r = results.get(label)
            if not r or not (200 <= getattr(r, "status", 0) < 400):
                continue
            urls = _grab_stored_urls(getattr(r, "body", ""), r.headers)
            shown = []
            for u in urls:
                if u.startswith("/"):
                    u = host_hint.rstrip("/") + u
                try:
                    g = engine.http.get(u, timeout=6)
                except Exception:
                    continue
                if g.status == 200 and MARKER.encode() in g.content:
                    shown.append(u)
            if shown:
                stored[label] = (r.status, shown[0])

        hostile = {k: v for k, v in stored.items()}
        accepted_any = any(r and 200 <= r.status < 400
                           for r in results.values())
        if hostile:
            names = ", ".join(hostile)
            chk = engine.db.add_finding(Finding(
                t.display, "web.upload", "critical-upload-surface", "critical",
                "Upload accepted AND served hostile filename(s): %s at %s"
                % (names, url),
                detail="Joined cases suffix list: %s. Stored+retrievable with "
                       "our marker proves the server executed/served the file "
                       "at a reachable URL — arbitrary-file-upload / "
                       "stored-webshell surface." % names,
                evidence="\n".join("=".join((k, str(v))) for k, v in hostile.items())
                + "\nmarker=%s" % MARKER,
                remediation="Validate filename + content (magic bytes), serve "
                            "uploads from an isolated origin with "
                            "Content-Disposition: attachment.",
                confidence="firm"))
            if chk:
                engine.log.finding("[upload] CRITICAL stored+served for %s"
                                   % "|".join(hostile))
            return
        if accepted_any and results.get("traversal") and \
                results["traversal"].status in (403, 415, 400):
            engine.db.add_finding(Finding(
                t.display, "web.upload", "controlled", "info",
                "Upload form enforces filename-filtering at %s" % url,
                detail="Benign/text files accepted; traversal/PHP variants "
                       "rejected by the server.",
                evidence="cases: " + ", ".join(
                    "%s=%s" % (l, getattr(r, "status", "err"))
                    for l, r in results.items()),
                remediation="—", confidence="firm"))
            engine.log.info("[upload] %s: filter enforced, no persistence "
                            "of hostile content" % url)
        elif accepted_any:
            engine.db.add_finding(Finding(
                t.display, "web.upload", "medium", "medium",
                "Upload accepts files but hostile content was not re-fetched "
                "(%s)" % url,
                detail="Upload returned success (%s) but no stored URL was "
                       "retrievable with our marker — persistence or "
                       "reachability unverified. Manual follow-up advised." %
                       ", ".join(str(getattr(results[l], "status", "?"))
                                 for l in ("benign", "traversal",
                                           "double-ext")),
                evidence="marker=%s" % MARKER,
                confidence="possible"))