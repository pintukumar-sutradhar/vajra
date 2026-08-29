"""VAJRA API / OpenAPI / OAuth surface (web.api) — discover machine
interfaces, their swagger/OpenAPI docs, JWT JWKS misconfigurations and
OAuth/OIDC metadata problems. Read-only."""
import json
import re
from urllib.parse import urljoin

from core.database import Finding

OPENAPI_PATHS = [
    "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
    "/v1/api-docs", "/swagger/v1/swagger.json", "/swagger.json",
    "/api/swagger.json", "/swagger/resource", "/openapi.yaml",
    "/swagger-ui.html", "/swagger/index.html", "/api/openapi.json",
    "/swagger/v2/swagger.json", "/actuator", "/swagger",
]
WELL_KNOWN = [
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
]

DOC_MARK = {
    "swagger": "Swagger 2.0",
    "openapi": "OpenAPI 3.x",
    "paths": "resource listing",
}


def _mark_doc(data):
    if not isinstance(data, dict):
        return ""
    for key, label in DOC_MARK.items():
        if key in data:
            return label
    if isinstance(data.get("info"), dict):
        return "OpenAPI-style"
    return ""


def _pick_ct(data):
    """Best-effort request content-type from the spec (JSON default)."""
    if isinstance(data, dict):
        if isinstance(data.get("consumes"), list) and data["consumes"]:
            return data["consumes"][0]
        for path, methods in (data.get("paths") or {}).items():
            for m in (methods or {}).values():
                if not isinstance(m, dict):
                    continue
                rb = m.get("requestBody") or {}
                content = rb.get("content") or {}
                if content:
                    return next(iter(content))
        if isinstance(data.get("produces"), list) and data["produces"]:
            return data["produces"][0]
    return "application/json"


def run(engine):
    t = engine.target
    found_docs = 0
    state_api = {"docs": [], "endpoints": [], "jwks": {}, "oidc": {}}
    for wt in engine.state.get("web_targets", []) or []:
        base = wt["url"].rstrip("/")
        base = base.split("?")[0]
        for path in OPENAPI_PATHS:
            url = urljoin(base + "/", path.lstrip("/"))
            try:
                r = engine.http.get(url, allow_redirects=False,
                                    timeout=min(5, engine.http.timeout))
            except Exception:
                continue
            if r.status not in (200, 203):
                continue
            ctype = r.headers.get("content-type", "").lower()
            if "json" in ctype or "yaml" in ctype or "text/plain" in ctype \
                    or r.body and (r.body.lstrip().startswith("{") or
                                   r.body.lstrip().startswith("swagger:")):
                data = None
                try:
                    data = json.loads(r.body)
                except Exception:
                    pass
                if data is None:
                    data = {"_yaml": True, "swagger": "yaml"}
                mark = _mark_doc(data)
                if not mark:
                    continue
                _consume_doc(engine, state_api, url, data, mark, base)
                found_docs += 1
        _well_known(engine, state_api, base)
    engine.state["api"] = state_api
    if state_api["endpoints"]:
        engine.state.setdefault("api_endpoints", state_api["endpoints"])
    else:
        engine.db.add_event(t.display, "web.api",
                            "no swagger/OpenAPI/OIDC surface discovered")
    if state_api["jwks"]:
        _audit_jwks(engine, state_api)
    if state_api["oidc"]:
        _audit_oidc(engine, state_api, t)
    if state_api["endpoints"]:
        _authz_checks(engine, state_api, t)


def _consume_doc(engine, state_api, url, data, mark, base):
    state_api["docs"].append(url)
    endpoints = data.get("paths", {}) if isinstance(data, dict) else {}
    entries = 0
    for path, methods in endpoints.items():
        if not isinstance(methods, dict):
            continue
        for meth in methods:
            if not isinstance(meth, str) or meth.lower() not in (
                    "get", "post", "put", "patch", "delete", "head",
                    "options"):
                continue
            state_api["endpoints"].append(
                {"base": base, "method": meth.upper(), "path": path,
                 "url": urljoin(base + "/", path.lstrip("/")),
                 "ct": _pick_ct(data),
                 "auth": bool((methods[meth] or {}).get("security") or
                              (methods[meth] or {}).get("securitySchemes"))})
            entries += 1
            if entries >= 400:
                break
        if entries >= 400:
            break
    engine.db.add_finding(Finding(
        engine.target.display, "web.api", "exposure", "medium",
        "API specification discovered (%s) — %s" % (mark, url),
        detail="Documentation exposes the machine interface. %d endpoint(s) "
               "parsed.%s" % (
                   entries,
                   " Endpoints with explicit security requirements are "
                   "marked; others may be unauthenticated."
                   if entries else "Parsing was shallow (YAML not decoded)."),
        evidence="%s\n%s endpoint paths" % (url, entries),
        remediation="Restrict API docs to internal networks; treat the "
                    "endpoint map as attack-surface intelligence.",
        confidence="firm"))
    engine.log.finding("[api] %s doc at %s (%d endpoints)"
                       % (mark, url, entries))
    unauthed = [e for e in state_api["endpoints"] if not e.get("auth")]
    if len(unauthed) >= 3:
        engine.db.add_finding(Finding(
            engine.target.display, "web.api", "authz", "high",
            "%d documented API endpoint(s) without declared auth" %
            len(unauthed),
            detail="Paths:\n%s" % "\n".join(
                "%s %s" % (e["method"], e["path"]) for e in unauthed[:20]),
            evidence="from %s" % url,
            remediation="Advertise security requirements in the spec and "
                        "enforce them server-side.", confidence="firm"))


def _well_known(engine, state_api, base):
    for path in WELL_KNOWN:
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            r = engine.http.get(url, allow_redirects=False,
                                timeout=min(5, engine.http.timeout))
        except Exception:
            continue
        if r.status not in (200, 203):
            continue
        data = r.json
        if not isinstance(data, dict):
            continue
        if "jwks" in path:
            state_api["jwks"] = data.get("keys", [])
            engine.db.add_finding(Finding(
                engine.target.display, "web.api", "recon", "low",
                "JWKS endpoint exposed at %s (%d JWK key(s))" %
                (url, len(data.get("keys", []))),
                evidence=json.dumps(data)[:1200],
                confidence="firm"))
        elif "openid-configuration" in path or "oauth-authorization-server" \
                in path:
            state_api["oidc"][path] = data
            engine.db.add_finding(Finding(
                engine.target.display, "web.api", "recon", "low",
                "OAuth/OIDC metadata exposed at %s" % url,
                detail="issuer=%s token=%s auth=%s" % (
                    data.get("issuer", "?"), data.get("token_endpoint", "?"),
                    data.get("authorization_endpoint", "?")),
                evidence=json.dumps(data)[:1500], confidence="firm"))


def _audit_jwks(engine, state_api):
    keys = state_api.get("jwks", [])
    for k in keys:
        if not isinstance(k, dict):
            continue
        alg = k.get("alg") or (k.get("kty", "RSA").upper())
        if k.get("alg") == "none":
            engine.db.add_finding(Finding(
                engine.target.display, "web.api", "verified-exposure",
                "critical", "JWKS advertises alg:none — algorithm confusion",
                detail="Tokens may be accepted unsigned by clients trusting "
                       "this metadata.",
                evidence=json.dumps(k)[:600], confidence="firm"))
        if k.get("kty") == "RSA" and k.get("use") == "sig" and k.get("n"):
            engine.db.add_finding(Finding(
                engine.target.display, "web.api", "recon", "medium",
                "RSA signing key published in JWKS (alg-confusion surface)",
                detail="If any consumer verifies RS256 with this JWKS but "
                       "accepts HS256, the public 'n' becomes the HMAC "
                       "secret. Audit validation libraries.",
                evidence="n=<%s…>" % str(k.get("n", ""))[:40],
                confidence="possible"))
            break


def _parse_netloc(url):
    from urllib.parse import urlparse
    pr = urlparse(url)
    host = pr.hostname
    port = pr.port or (443 if pr.scheme == "https" else 80)
    return pr, host, port, pr.scheme == "https"


def _raw_get_no_cookie(url, socks5=None):
    """GET an endpoint with a pristine connection — zero cookies/headers —
    to test whether declared-auth endpoints actually enforce it."""
    from core.http_client import raw_http
    pr, host, port, tls = _parse_netloc(url)
    path = pr.path or "/"
    if pr.query:
        path += "?" + pr.query
    req = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (
        path, host or "x")
    raw = raw_http(host, port, req, tls=tls, timeout=4, socks5=socks5)
    if not raw:
        return None, None
    head, _, body = raw.partition(b"\r\n\r\n")
    try:
        status = int(head.split(b" ", 2)[1])
    except Exception:
        status = 0
    return status, body


def _authz_checks(engine, state_api, t):
    """Broken object-level authorization checks done without a second user:
    1) endpoints that declare auth but answer plain data to a cookie-less
       request (auth not enforced);
    2) parameterized GET object endpoints — id sweep visibility;
    3) state-changing endpoints that accept a cross-origin, token-less
       request (CSRF surface)."""
    declared = [e for e in state_api["endpoints"] if e.get("auth")]
    for ep in declared[:10]:
        url = ep.get("url")
        if not url or ep["method"] != "GET":
            continue
        path = ep.get("path")
        if not path or "{" not in path:
            continue
        url = url.split("{")[0].rstrip("/") + "/1"
        status, body = _raw_get_no_cookie(url,
                                          getattr(engine, "socks", None))
        if status in (200, 203) and body and len(body) > 40:
            engine.db.add_finding(Finding(
                t.display, "web.api", "authz", "high",
                "Declared-auth object endpoint reachable unauthenticated"
                " — BROKEN ACCESS CONTROL (%s)" % path,
                detail="%s returned HTTP %d to a cookie-less request with a "
                       "%d-byte body: accounts for endpoint object data, an "
                       "unauthenticated IDOR/BOLA condition." %
                       (path, status, len(body)),
                evidence=body[:400].decode("utf-8", "replace"),
                remediation="Enforce authentication AND object-level "
                            "authorization server-side on every resource.",
                confidence="firm"))
            engine.log.finding("[AUTHZ] %s ignores auth (%d bytes to "
                               "cookie-less GET)" % (path, len(body)))
            return
    # id visibility sweep (with our session if auth was established)
    sweeped = 0
    seen_len = set()
    for ep in state_api["endpoints"][:40]:
        path = ep.get("path", "")
        if ep["method"] != "GET" or "{" not in path or "id" not in path:
            continue
        prefix = ep.get("url", "").split("{")[0].rstrip("/")
        for ident in ("1", "2", "3"):
            try:
                r = engine.http.get("%s/%s" % (prefix, ident),
                                    allow_redirects=False, timeout=5)
            except Exception:
                continue
            if 200 <= r.status < 400:
                seen_len.add((r.status, len(r.body) // 50))
        sweeped += 1
    if sweeped and len(seen_len) >= 2 and engine.state.get("authenticated"):
        engine.db.add_finding(Finding(
            t.display, "web.api", "authz", "medium",
            "IDOR sweep: %d parameterized object endpoint(s) respond across "
            "sequential ids" % sweeped,
            detail="Different ids return different resources with the session "
                   "provided — verify object-level authorization per user "
                   "(requires a second account).",
            evidence="ids 1-3 probed across %d endpoint(s)" % sweeped,
            remediation="Enforce object-level authorization checks.",
            confidence="possible"))
    # CSRF surface: token-less state-changing call from a foreign Origin
    changer = [e for e in state_api["endpoints"]
               if e["method"] in ("POST", "PUT", "PATCH", "DELETE")][:6]
    for ep in changer:
        url = ep.get("url")
        if not url:
            continue
        path = ep.get("path")
        pr, host, port, tls = _parse_netloc(url)
        target = (pr.path or "/")
        if "{" in target:
            target = target.split("{")[0]
        try:
            r = engine.http.request(ep["method"], pr.scheme + "://" + host +
                                    ":" + str(port) + target,
                                    json_body={}, allow_redirects=False,
                                    timeout=5)
            if 200 <= r.status < 400 and r.status not in (204, 205):
                engine.db.add_finding(Finding(
                    t.display, "web.api", "csrf", "medium",
                    "State-changing API endpoint without evident CSRF "
                    "protection (%s %s)" % (ep["method"], path),
                    detail="Empty JSON body accepted without token → cross-"
                           "origin state change may succeed (verify Origin/"
                           "SameSite).",
                    evidence="%s %s -> HTTP %d" % (ep["method"], target,
                                                   r.status),
                    remediation="Require a CSRF token (or enforce "
                                "SameSite=Lax and Origin checking) on "
                                "state-changing routes.",
                    confidence="possible"))
            break
        except Exception:
            continue


def _audit_oidc(engine, state_api, t):
    for path, data in state_api.get("oidc", {}).items():
        iss = (data.get("issuer") or "").lower()
        auth = (data.get("authorization_endpoint") or "").lower()
        token = (data.get("token_endpoint") or "").lower()
        if any(e.startswith("http:") for e in (iss, auth, token)):
            engine.db.add_finding(Finding(
                t.display, "web.api", "misconfiguration", "high",
                "OAuth/OIDC metadata on cleartext HTTP (%s)" % path,
                evidence="issuer=%s" % iss,
                remediation="Serve OAuth metadata only over TLS.",
                confidence="firm"))