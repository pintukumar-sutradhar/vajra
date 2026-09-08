"""Auth: login, logout, me, API keys."""

import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, security
from ..audit import log as audit_log
from ..config import BRAND
from ..db import get_db
from .deps import current_user, require_role

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str
    password: str


class KeyIn(BaseModel):
    label: str = ""


def _user_schema(u):
    return {"id": u.id, "username": u.username,
            "display_name": u.display_name, "role": u.role}


@router.post("/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(
        models.User.username == body.username).first()
    if not user or not security.verify_password(body.password,
                                                user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad credentials")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "account disabled")
    token = security.issue_session_token()
    user.last_login_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    db.add(models.Session(
        user_id=user.id, token_hash=security.session_hash(token),
        expires_at=security.expires_after()))
    db.commit()
    audit_log(db, user.username, "auth.login")
    return {"token": token, "user": _user_schema(user)}


@router.post("/logout")
def logout(db: Session = Depends(get_db),
           user=Depends(current_user)):
    audit_log(db, user.username, "auth.logout")
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