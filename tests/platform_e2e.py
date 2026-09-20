#!/usr/bin/env python3
"""VAJRA platform API end-to-end tests.

Exercises the real HTTP surface in an isolated temp database: login lockout,
user management + role enforcement, first-login password change, API keys,
CSV export and the audit trail. Run from the repo root:

    server/.venv/bin/python tests/platform_e2e.py
"""

import os
import sys
import tempfile
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Isolated runtime — everything below imports server.app.* lazily so Settings
# picks up this fresh database instead of the live one.
_TMP = tempfile.mkdtemp(prefix="vajra_platform_e2e_")
os.environ["VAJRA_PLATFORM_VAR"] = _TMP
os.environ["VAJRA_DB_URL"] = "sqlite:///%s/platform.db" % _TMP
os.environ["VAJRA_ADMIN_PASSWORD"] = "admin"
os.environ["VAJRA_LOGIN_MAX_ATTEMPTS"] = "3"
os.environ["VAJRA_LOGIN_LOCKOUT_SECONDS"] = "60"

from starlette.testclient import TestClient  # noqa: E402

from server.app.main import app  # noqa: E402

_client = TestClient(app)
_auth = {}  # username -> bearer token


def auth(username):
    return {"Authorization": "Bearer " + _auth[username]}


def login(username, password):
    r = _client.post("/api/v1/auth/login",
                     json={"username": username, "password": password})
    if r.status_code == 200:
        _auth[username] = r.json()["token"]
    return r


def run(name, fn):
    try:
        fn()
        print("[PASS] %s" % name)
        return True
    except Exception as e:  # noqa: BLE001
        print("[FAIL] %s    %s" % (name, repr(e)))
        traceback.print_exc()
        return False


OK = True

# ---------------------------------------------------------------- login flow


def t_bad_login():
    r = login("admin", "wrong-password")
    assert r.status_code == 401, r.status_code
    assert not _client.cookies.get("vajra_session")


def t_lockout():
    # Two misses get a plain 401…
    r = login("jane", "wrong-password")
    assert r.status_code == 401, r.status_code
    r = login("jane", "wrong-password")
    assert r.status_code == 401, r.status_code
    # …the hitting of the attempt ceiling is what locks the account.
    r = login("jane", "wrong-password")
    assert r.status_code == 429, r.status_code
    assert r.headers.get("Retry-After") == "60"
    # Locked: even the correct password is refused until the window passes.
    r = login("jane", "Letmein2026!x")
    assert r.status_code == 429, r.status_code


def t_login():
    r = login("admin", "admin")
    assert r.status_code == 200, r.status_code
    body = r.json()
    assert body["token"]
    assert body["user"]["role"] == "admin"
    # Seeded default password => forced change on first login.
    assert body["user"]["must_change_password"] is True
    assert _client.cookies.get("vajra_session")


def t_me():
    r = _client.get("/api/v1/auth/me", headers=auth("admin"))
    assert r.status_code == 200, r.status_code
    assert r.json()["user"]["username"] == "admin"


def t_password_change_wrong_current():
    r = _client.post("/api/v1/auth/password",
                     headers=auth("admin"),
                     json={"current_password": "nope",
                           "new_password": "Whatever2026!x"})
    assert r.status_code == 401, r.status_code


def t_password_change():
    r = _client.post("/api/v1/auth/password",
                     headers=auth("admin"),
                     json={"current_password": "admin",
                           "new_password": "CorrectHorseBatteryStaple1"})
    assert r.status_code == 200, r.status_code
    assert r.json()["must_change_password"] is False
    # Old password is dead.
    assert login("admin", "admin").status_code == 401
    # New password signs in cleanly.
    r2 = login("admin", "CorrectHorseBatteryStaple1")
    assert r2.status_code == 200, r2.status_code
    assert r2.json()["user"]["must_change_password"] is False


def t_short_password_rejected():
    r = _client.post("/api/v1/auth/users",
                     headers=auth("admin"),
                     json={"username": "short", "password": "Abc123!",
                           "role": "analyst"})
    assert r.status_code == 422, r.status_code


# ------------------------------------------------------------- user management


def t_admin_creates_analyst():
    r = _client.post("/api/v1/auth/users",
                     headers=auth("admin"),
                     json={"username": "jane", "password": "Letmein2026!x",
                           "display_name": "Jane", "role": "analyst",
                           "force_change": True})
    assert r.status_code == 200, r.status_code
    assert r.json()["role"] == "analyst"
    assert r.json()["must_change_password"] is True
    # Duplicate username refused.
    r2 = _client.post("/api/v1/auth/users",
                      headers=auth("admin"),
                      json={"username": "jane", "password": "Letmein2026!x",
                            "role": "analyst"})
    assert r2.status_code == 409, r2.status_code


def t_analyst_forbidden_from_admin():
    assert login("jane", "Letmein2026!x").status_code == 200
    r = _client.get("/api/v1/auth/users?all=1", headers=auth("jane"))
    assert r.status_code == 403, r.status_code
    r2 = _client.post("/api/v1/auth/users",
                      headers=auth("jane"),
                      json={"username": "bob", "password": "Letmein2026!x",
                            "role": "analyst"})
    assert r2.status_code == 403, r2.status_code
    # But an analyst may list active members (assignee picker).
    assert _client.get("/api/v1/auth/users",
                       headers=auth("jane")).status_code == 200


def t_auditor_read_only():
    _client.post("/api/v1/auth/users",
                 headers=auth("admin"),
                 json={"username": "kim", "password": "Auditme2026!x",
                       "role": "auditor", "force_change": True})
    assert login("kim", "Auditme2026!x").status_code == 200
    assert _client.get("/api/v1/findings",
                       headers=auth("kim")).status_code == 200
    assert _client.get("/api/v1/audit",
                       headers=auth("kim")).status_code == 200


def t_disable_and_lockout_lift():
    # Admin disables jane; her sessions are revoked and login is refused.
    jid = [u["id"] for u in _client.get(
        "/api/v1/auth/users?all=1", headers=auth("admin")).json()
        if u["username"] == "jane"][0]
    r = _client.patch("/api/v1/auth/users/%d" % jid,
                      headers=auth("admin"), json={"is_active": False})
    assert r.status_code == 200, r.status_code
    assert login("jane", "Letmein2026!x").status_code == 403
    # Disabled account listed in the admin roster.
    roster = _client.get("/api/v1/auth/users?all=1",
                         headers=auth("admin")).json()
    jane = [u for u in roster if u["username"] == "jane"][0]
    assert jane["is_active"] is False
    # Re-enable, then force a password reset (signs her out + sets force flag).
    _client.patch("/api/v1/auth/users/%d" % jid,
                  headers=auth("admin"), json={"is_active": True})
    r = _client.post("/api/v1/auth/users/%d/reset-password" % jid,
                     headers=auth("admin"),
                     json={"label": "Br@ndNew2026!x"})
    assert r.status_code == 200, r.status_code
    r = login("jane", "Br@ndNew2026!x")
    assert r.status_code == 200, r.status_code
    assert r.json()["user"]["must_change_password"] is True


def t_last_admin_guard():
    me = _client.get("/api/v1/auth/me", headers=auth("admin")).json()["user"]
    r = _client.patch("/api/v1/auth/users/%d" % me["id"],
                      headers=auth("admin"), json={"role": "analyst"})
    assert r.status_code == 422, r.status_code
    r2 = _client.patch("/api/v1/auth/users/%d" % me["id"],
                       headers=auth("admin"), json={"is_active": False})
    assert r2.status_code == 422, r2.status_code


# ---------------------------------------------------------------- API keys


def t_api_key():
    # Drop any ambient session cookie (TestClient keeps one from prior logins)
    # so the key is the only credential presented, as real scripts would.
    _client.cookies.clear()
    k = _client.post("/api/v1/auth/keys",
                     headers=auth("admin"), json={"label": "ci"}).json()
    key = k["key"]
    assert key.startswith("vaj_")
    r = _client.get("/api/v1/auth/me", headers={"X-API-Key": key})
    assert r.status_code == 200, r.status_code
    assert r.json()["user"]["username"] == "admin"
    r2 = _client.get("/api/v1/auth/keys",
                     headers=auth("admin")).json()
    assert any("ci" == x["label"] and not x["revoked"] for x in r2)


# --------------------------------------------------------------------- CSV


def t_csv_export():
    r = _client.get("/api/v1/findings/export.csv", headers=auth("admin"))
    assert r.status_code == 200, r.status_code
    assert r.headers["content-type"].startswith("text/csv")
    assert "Content-Disposition" in r.headers
    assert r.text.splitlines()[0].startswith("id,scan_id,engine_id")


# ------------------------------------------------------------- audit trail


def t_audit_ledger():
    rows = _client.get("/api/v1/audit?limit=500",
                       headers=auth("admin")).json()
    actions = {x["action"] for x in rows}
    for want in ("auth.login", "auth.user.create", "auth.user.update",
                 "auth.password_change", "key.create", "auth.lockout"):
        assert want in actions, (want, actions)


OK = (run("bad credentials rejected", t_bad_login)
      and run("seeded admin login forces password change", t_login)
      and run("session round-trip through /me", t_me)
      and run("password change rejects wrong current", t_password_change_wrong_current)
      and run("password change rotates the credential", t_password_change)
      and run("short passwords rejected", t_short_password_rejected)
      and run("admin provisions an analyst", t_admin_creates_analyst)
      and run("analyst forbidden from admin actions", t_analyst_forbidden_from_admin)
      and run("auditor is read-only", t_auditor_read_only)
      and run("brute-force lockout + Retry-After", t_lockout)
      and run("disable/reset revoke access correctly", t_disable_and_lockout_lift)
      and run("last-admin demotion/disable refused", t_last_admin_guard)
      and run("API key auth round-trip", t_api_key)
      and run("findings CSV export", t_csv_export)
      and run("audit ledger records the lifecycle", t_audit_ledger))

print()
print("platform API: %s" % ("all checks passed" if OK else "FAILURES"))
import shutil  # noqa: E402
shutil.rmtree(_TMP, ignore_errors=True)
sys.exit(0 if OK else 1)