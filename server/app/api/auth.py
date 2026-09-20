"""Auth: login, logout, me, password management, user management, API keys."""

import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, security
from ..audit import log as audit_log
from ..config import BRAND, settings
from ..db import get_db
from .deps import ROLES, current_user, require_role

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str
    password: str


class KeyIn(BaseModel):
    label: str = ""


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _validate_password(username, password):
    if len(password) < settings.password_min_length:
        raise HTTPException(
            422, "password must be at least %d characters"
            % settings.password_min_length)
    if password == username:
        raise HTTPException(422, "password must not equal the username")


def _user_schema(u):
    return {"id": u.id, "username": u.username,
            "display_name": u.display_name, "role": u.role,
            "is_active": u.is_active,
            "must_change_password": u.must_change_password,
            "last_login_at": str(u.last_login_at)
            if u.last_login_at else None,
            "locked": bool(u.locked_until and
                           u.locked_until > _utcnow())}


def _revoke_sessions(db, user_id):
    rows = db.query(models.Session).filter(
        models.Session.user_id == user_id,
        models.Session.revoked_at.is_(None)).all()
    for s in rows:
        s.revoked_at = _utcnow()


def _active_admins(db, org_id):
    return db.query(models.User).filter(
        models.User.org_id == org_id,
        models.User.role == "admin",
        models.User.is_active.is_(True)).count()


def _guard_last_admin(db, user, target):
    """Never allow the platform to end up with zero active admins."""
    if not (target.role == "admin" and target.is_active):
        return
    if _active_admins(db, user.org_id) > 1:
        return
    raise HTTPException(422, "cannot demote or disable the last active admin")


@router.post("/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    now = _utcnow()
    user = db.query(models.User).filter(
        models.User.username == body.username).first()
    if user and not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "account disabled")
    if user:
        if user.locked_until and user.locked_until > now:
            remaining = int((user.locked_until - now).total_seconds())
            audit_log(db, body.username, "auth.login.locked",
                      detail={"retry_after": remaining})
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "account temporarily locked; try again later",
                headers={"Retry-After": str(max(remaining, 1))})
        if user.locked_until:      # lock expired: open the account again
            user.locked_until = None
            user.failed_login_attempts = 0
        if not security.verify_password(body.password, user.password_hash):
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= settings.login_max_attempts:
                user.locked_until = now + datetime.timedelta(
                    seconds=settings.login_lockout_seconds)
                remaining = settings.login_lockout_seconds
                user.failed_login_attempts = 0
                audit_log(db, body.username, "auth.lockout",
                          detail={"seconds": remaining})
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "account temporarily locked; try again later",
                    headers={"Retry-After": str(remaining)})
            audit_log(db, body.username, "auth.login.failed",
                      detail={"attempts": user.failed_login_attempts})
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "bad credentials")
    else:
        # Same password work whether or not the account exists, so login
        # timing does not leak which usernames are valid.
        security.verify_password(
            body.password, "pbkdf2_sha256:260000$not$a")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad credentials")
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    token = security.issue_session_token()
    db.add(models.Session(
        user_id=user.id, token_hash=security.session_hash(token),
        expires_at=security.expires_after()))
    db.commit()
    audit_log(db, user.username, "auth.login")
    resp = JSONResponse({"token": token, "user": _user_schema(user)})
    resp.set_cookie("vajra_session", token,
                    max_age=settings.token_ttl_hours * 3600,
                    httponly=True, samesite="lax", path="/",
                    secure=settings.session_cookie_secure)
    return resp


@router.get("/users")
def list_users(all_users: bool = Query(False, alias="all"),
               db: Session = Depends(get_db),
               user=Depends(current_user)):
    """Org members.

    Default (any role): active members for assignee selection in the triage
    workflow. `all=1` (admin only): the full members roster including
    disabled accounts and lockout state.
    """
    q = db.query(models.User).filter(models.User.org_id == user.org_id)
    if all_users:
        if user.role != "admin":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "admin only")
    else:
        q = q.filter(models.User.is_active.is_(True))
    rows = q.order_by(models.User.username).all()
    out = [_user_schema(u) for u in rows]
    if not all_users:
        out = [{k: v for k, v in o.items()
                if k not in ("is_active", "must_change_password", "locked")}
               for o in out]
    return out


class UserCreate(BaseModel):
    username: str
    password: str
    display_name: str = ""
    role: str = "analyst"
    force_change: bool = True


class UserPatch(BaseModel):
    display_name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = None


@router.post("/users")
def create_user(body: UserCreate, db: Session = Depends(get_db),
                user=Depends(require_role("admin"))):
    username = body.username.strip()
    if not (3 <= len(username) <= 60) or not all(
            c.isalnum() or c in "._-" for c in username):
        raise HTTPException(422, "username: 3-60 chars of letters/digits/._-")
    if body.role not in ROLES:
        raise HTTPException(422, "role must be one of %s"
                            % ", ".join(sorted(ROLES)))
    _validate_password(username, body.password)
    if db.query(models.User).filter(
            models.User.username == username).first():
        raise HTTPException(409, "username already exists")
    u = models.User(org_id=user.org_id, username=username,
                    display_name=body.display_name,
                    password_hash=security.hash_password(body.password),
                    role=body.role, is_active=True,
                    must_change_password=body.force_change,
                    last_password_change_at=_utcnow())
    db.add(u)
    db.commit()
    audit_log(db, user.username, "auth.user.create", "user", u.id,
              {"username": username, "role": body.role})
    return _user_schema(u)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserPatch, db: Session = Depends(get_db),
                user=Depends(require_role("admin"))):
    target = db.get(models.User, user_id)
    if not target or target.org_id != user.org_id:
        raise HTTPException(404, "not found")
    if body.display_name is not None:
        target.display_name = body.display_name
    if body.role is not None:
        if body.role not in ROLES:
            raise HTTPException(422, "role must be one of %s"
                                % ", ".join(sorted(ROLES)))
        _guard_last_admin(db, user, target)
        target.role = body.role
    if body.is_active is not None and body.is_active != target.is_active:
        _guard_last_admin(db, user, target)
        target.is_active = body.is_active
        if not body.is_active:
            _revoke_sessions(db, target.id)
    if body.password:
        _validate_password(target.username, body.password)
        target.password_hash = security.hash_password(body.password)
        target.must_change_password = True
        target.last_password_change_at = _utcnow()
        _revoke_sessions(db, target.id)
    db.commit()
    audit_log(db, user.username, "auth.user.update", "user", target.id,
              {"username": target.username})
    return _user_schema(target)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: int, body: KeyIn, db: Session = Depends(get_db),
                   user=Depends(require_role("admin"))):
    """Force a reset: admin sets a new initial password; the target user must
    change it at their next login."""
    target = db.get(models.User, user_id)
    if not target or target.org_id != user.org_id:
        raise HTTPException(404, "not found")
    password = body.label
    if not password:
        raise HTTPException(422, "provide the new initial password")
    _validate_password(target.username, password)
    target.password_hash = security.hash_password(password)
    target.must_change_password = True
    target.last_password_change_at = _utcnow()
    target.failed_login_attempts = 0
    target.locked_until = None
    _revoke_sessions(db, target.id)
    db.commit()
    audit_log(db, user.username, "auth.user.reset_password", "user",
              target.id, {"username": target.username})
    return {"ok": True}


class PasswordIn(BaseModel):
    current_password: str
    new_password: str


@router.post("/password")
def change_password(body: PasswordIn, db: Session = Depends(get_db),
                    user=Depends(current_user)):
    """Self-service password change. Also clears the forced-change flag, so a
    first-login (seeded default admin) flows through this route."""
    if not security.verify_password(body.current_password,
                                    user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "current password is incorrect")
    _validate_password(user.username, body.new_password)
    user.password_hash = security.hash_password(body.new_password)
    user.must_change_password = False
    user.last_password_change_at = _utcnow()
    user.failed_login_attempts = 0
    user.locked_until = None
    _revoke_sessions(db, user.id)   # keep the current session, drop the rest
    db.commit()
    audit_log(db, user.username, "auth.password_change")
    return _user_schema(user)


@router.post("/logout")
def logout(response: Response, db: Session = Depends(get_db),
           user=Depends(current_user)):
    audit_log(db, user.username, "auth.logout")
    response.delete_cookie("vajra_session", path="/")
    return {"ok": True}


@router.get("/me")
def me(user=Depends(current_user)):
    return {"user": _user_schema(user)}


@router.post("/keys")
def create_key(body: KeyIn, db: Session = Depends(get_db),
               user=Depends(require_role("admin"))):
    raw = security.issue_api_key()
    db.add(models.ApiKey(org_id=user.org_id, user_id=user.id,
                         label=body.label,
                         key_hash=security.session_hash(raw),
                         key_prefix=security.api_public(raw)))
    db.commit()
    audit_log(db, user.username, "key.create")
    return {"key": raw}


@router.get("/keys")
def list_keys(db: Session = Depends(get_db),
              user=Depends(require_role("admin"))):
    rows = db.query(models.ApiKey).filter(
        models.ApiKey.org_id == user.org_id).order_by(
            models.ApiKey.created_at.desc()).all()
    return [{"id": k.id, "label": k.label, "prefix": k.key_prefix,
             "created_at": str(k.created_at),
             "last_used_at": str(k.last_used_at) if k.last_used_at else None,
             "revoked": bool(k.revoked_at)} for k in rows]


class BrandOut(BaseModel):
    product: str
    tagline: str
    edition: str
    logo_svg: str
    colors: dict


@router.get("/brand", response_model=BrandOut)
def brand():
    return BRAND