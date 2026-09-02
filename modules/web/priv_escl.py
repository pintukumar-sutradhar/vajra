# modules/web/priv_escl.py
# web.escalate - the authenticated privilege-escalation / cross-user phase.
#
# Runs only once an authenticated session exists (minted by web.auth_login,
# either from --web-user/--web-pass or from an auto-registered account). Two
# checks:
#
#  * horizontal (IDOR / object-level authorisation): mint a SECOND throwaway
#    identity when auto-registration is available, discover the object id the
#    app assigns that identity, then request the second user's resource with
#    the first user's session. Only a response that (a) carries the second
#    user's private marker (email/username) AND (b) is NOT readable by an
#    anonymous session is reported as a confirmed IDOR. Anything an anonymous
#    session can read is public data and is skipped, so the check cannot
#    fire a false 'cross-user leak'.
#
#  * vertical (broken access control surface): as the low-privilege session,
#    probe common administrative/management endpoints and diff them against
#    the anonymous baseline. Deliberately reported as info-grade recon only;
#    we never claim a confirmed vertical escalation without a role oracle,
#    keeping the report free of false positives.

import re
import urllib.parse

from core.database import Finding

module = "web.escalate"
style = "uppercase"

ME_ENDPOINTS = ("/api/me", "/api/v1/me", "/api/current-user",
                "/api/current_user", "/api/user/me", "/api/v1/user/me",
                "/api/account/me", "/api/v1/account/me", "/api/self",
                "/api/profile", "/me", "/whoami", "/account", "/profile")
IDISH_PARAM = re.compile(
    r"(^|[_.-])(id|uid|user_?id|userid|account_?id|accountid|profile_?id|"
    r"member_?id|owner_?id|creator_?id|file_?id|order_?id|item_?id|"
    r"post_?id|record_?id|doc_?id|docid|document_?id|patient_?id|"
    r"staff_?id|employee_?id|client_?id|message_?id|invoice_?id|"
    r"ticket_?id|folder_?id|team_?id|project_?id|grant_?id)([_.-]?$)", re.I)
ID_KEY_RE = re.compile(r'["\'](?:id|user_?id|userId|uid|account_?id|accountId|'
                       r'profile_?id|profileId|ownerId)[\"\']\s*:\s*["\']?'
                       r'([0-9a-fA-F-]{1,40})["\']?')
ADMIN_PATHS = ("/admin", "/admin/", "/admin.html", "/administrator",
               "/manage", "/management", "/dashboard", "/staff",
               "/internal", "/backoffice", "/api/admin", "/api/users",
               "/api/v1/admin", "/api/v1/users", "/users", "/user/list",
               "/console", "/debug", "/actuator", "/ops", "/ops/console",
               "/graphql")
ADMIN_MARKER_RE = re.compile(
    r"(user management|manage users|all users|total users|role.?[:=]?\"?"
    r"admin|rbac|permissions|account management|user admin||"
    r"create user|delete user|grant|demote|update role)", re.I)


def _cookie(engine):
    return engine.http._cookie if hasattr(engine.http, "_cookie") else ""


def _swap(engine, cookie):
    old = _cookie(engine)
    engine.http._cookie = cookie or ""
    return old


def _restore(engine, old):
    engine.http._cookie = old


def _discover_identity(engine, label):
    """Best effort: as the given account, fetch own-profile endpoints until we
    learn the account's object id + a private marker (email/username)."""
    regs = engine.state.setdefault("_autoreg", {})
    entry = regs.get(label) or {}
    cookie = entry.get("cookie", "")
    base = engine.target.url.rstrip("/") if hasattr(engine.target, "url") else ""
    if not base and engine.state.get("web_targets"):
        w0 = engine.state["web_targets"][0]
        base = (w0.get("url") if isinstance(w0, dict) else str(w0)).rstrip("/")
    if not base:
        return None
    old = _swap(engine, cookie)
    try:
        for p in ME_ENDPOINTS:
            try:
                r = engine.http.get(base + p, timeout=min(8,
                                                          engine.http.timeout))
            except Exception:
                continue
            body = (r.body or "")[:200000]
            if r.status not in (200, 201) or not body:
                continue
            marker = entry.get("email")
            if marker and marker in body:
                m = ID_KEY_RE.search(body)
                if m:
                    return {"label": label, "id": m.group(1),
                            "marker": marker, "cookie": cookie,
                            "endpoint": base + p}
            um = entry.get("user")
            if um and um in body:
                m = ID_KEY_RE.search(body)
                if m:
                    return {"label": label, "id": m.group(1),
                            "marker": um, "cookie": cookie,
                            "endpoint": base + p}
    finally:
        _restore(engine, old)
    return None


def _idor_candidates(engine, ident_b):
    """Endpoint templates that might expose the second user's objects: id-ish
    query parameters observed on crawled pages, plus conventional numeric
    object routes."""
    cands = []
    b_id = ident_b["id"]
    for pg in engine.state.get("pages", []):
        url = pg.get("url")
        if not url:
            continue
        try:
            qs = urllib.parse.urlsplit(url).query
        except Exception:
            continue
        qd = urllib.parse.parse_qsl(qs, keep_blank_values=True)
        for k, v in qd:
            if IDISH_PARAM.search(k) and v and v != b_id:
                cands.append(("param", url.replace(k + "=" + v,
                                                   k + "=" + b_id), k))
        if re.search(r"/\w+/\d+($|[?#])", url):
            cands.append(("path", re.sub(r"/(\w+)/(\d+)($|[?#])",
                                         r"/\1/%s\3" % b_id, url), ""))
    if re.fullmatch(r"[0-9]+", b_id):
        for tpl in ("/api/users/%s", "/api/user/%s", "/api/accounts/%s",
                    "/api/v1/users/%s", "/api/v1/user/%s", "/user/%s",
                    "/users/%s", "/account/%s", "/profile/%s",
                    "/account/%s", "/member/%s", "/api/me/%s"):
            try:
                base = (engine.target.url.rstrip("/") if hasattr(
                    engine.target, "url") else "")
            except Exception:
                base = ""
            if not base and engine.state.get("web_targets"):
                w0 = engine.state["web_targets"][0]
                base = (w0.get("url") if isinstance(w0, dict)
                        else str(w0)).rstrip("/")
            cands.append(("path", base + (tpl % b_id), tpl))
    seen, out = set(), []
    for kind, url, name in cands:
        if url not in seen:
            seen.add(url)
            out.append((kind, url, name))
    return out[:24]


def _session_get(engine, url, cookie):
    old = _swap(engine, cookie)
    try:
        return engine.http.get(url, timeout=min(9, engine.http.timeout))
    finally:
        _restore(engine, old)


def run(engine):
    t = engine.target
    auth = engine.state.get("web_auth") or {}
    regs = engine.state.setdefault("_autoreg", {})
    if not (auth.get("established") or regs):
        return
    noauto = getattr(engine.args, "no_autoreg", False)
    if auth.get("established") and "B" not in regs and not noauto:
        saved_cookie = _cookie(engine)
        saved_auth = dict(engine.state.get("web_auth") or {})
        try:
            from modules.web.auth_logic import auto_register
            auto_register(engine, "B")
        finally:
            engine.http._cookie = saved_cookie
            engine.state["web_auth"] = saved_auth

    ident_b = None
    if regs.get("B"):
        ident_b = _discover_identity(engine, "B")

    if not ident_b:
        if auth.get("established") and not noauto:
            engine.log.info(
                "[escalate] only one identity available - cross-user "
                "baseline unavailable; skipping IDOR sweep")
        elif not noauto:
            engine.db.add_finding(Finding(
                t.display, module, "coverage", "info",
                "Cross-user escalation baseline unavailable",
                detail="Could not register a second identity or discover "
                       "an owned object id; horizontal IDOR sweep skipped.",
                confidence="possible"))
    else:
        _run_horizontal(engine, ident_b)

    _run_vertical(engine, auth)


def _run_horizontal(engine, ident_b):
    t = engine.target
    a_cookie = _cookie(engine)
    found = 0
    for kind, url, name in _idor_candidates(engine, ident_b):
        marker = ident_b["marker"]
        try:
            anon = _session_get(engine, url, "")
        except Exception:
            continue
        anon_leak = anon.status in (200, 201, 203) and marker in (anon.body
                                                                 or "")
        if anon_leak:
            continue  # public data, not a broken authorisation
        try:
            resp = _session_get(engine, url, a_cookie)
        except Exception:
            continue
        body = resp.body or ""
        if resp.status in (200, 201, 203) and marker in body:
            found += 1
            snippet = marker + " leaked via %s at %s" % (resp.url or url, url)
            engine.save_evidence(
                "escl_idor_%03d.txt" % found,
                "IDOR confirmed: %s\nkind=%s param=%s\n\n%s %s\nstatus=%s "
                "len=%s\nmarker=%s\n\n%s" %
                (url, kind, name or "(path)", "GET", url, resp.status,
                 len(body), marker, body[:60000]))
            if engine._screenshots_enabled():
                try:
                    engine.save_screenshot(url,
                                          "escl_idor_%03d.png" % found)
                except Exception:
                    pass
            engine.db.add_finding(Finding(
                t.display, module, "idor", "high",
                "Object-level authorisation bypass (authenticated "
                "cross-user read)",
                detail=("Requesting another user's resource with the logged-"
                        "in session returned that user's private data.\n%s "
                        "as session=%s\nmarker identified via %s\n"
                        "anon baseline=%s (no leak)" %
                        (url, engine.state.get("web_auth", {}).get(
                            "user", "session"),
                         ident_b.get("endpoint", "?"), anon.status)),
                evidence="marker '%s' present in response; anonymous "
                         "baseline does NOT leak it" % marker,
                confidence="firm"))
            engine.log.warn("[escalate] IDOR %s -> %s" % (name, url))
    engine.log.info("[escalate] horizontal sweep complete: %d confirmed "
                    "cross-user read(s)" % found)


def _run_vertical(engine, auth):
    t = engine.target
    a_cookie = _cookie(engine)
    base = engine.target.url.rstrip("/") if hasattr(engine.target, "url") \
        else ""
    if not base:
        return
    hits = []
    for p in ADMIN_PATHS:
        url = base + p
        try:
            anon = _session_get(engine, url, "")
            authd = _session_get(engine, url, a_cookie)
        except Exception:
            continue
        if anon.status in (200, 201, 203):
            continue
        if authd.status in (200, 201, 203) and (authd.body or ""):
            body = authd.body[:200000]
            m = ADMIN_MARKER_RE.search(body)
            if m and "type=\"password\"" not in body and \
                    "type='password'" not in body:
                hits.append((url, authd.status, m.group(0), len(body)))
    if hits:
        engine.db.add_finding(Finding(
            t.display, module, "recon", "info",
            "Administrative/management surface reachable after "
            "authentication",
            detail="The authenticated session returns content for "
                   "administrative routes that anonymous sessions cannot "
                   "reach. Listed for manual review; not claimed as a "
                   "confirmed escalation without a role oracle.\n\n" +
                   "\n".join("GET %s -> %s (marker '%s', %d bytes)" %
                             (u, s, mf, ln) for u, s, mf, ln in hits),
            confidence="possible"))
        engine.log.info("[escalate] %d admin route(s) reachable "
                        "authenticated" % len(hits))