"""FastAPI auth dependencies."""

import datetime

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import models, security
from ..db import get_db

ROLES = {"admin", "analyst", "auditor"}


def _token_from_request(request: Request):
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    cookie = request.cookies.get("vajra_session", "")
    if cookie:
        return cookie
    api = request.headers.get("X-API-Key", "")
    return None if not api else ("key:" + api)


def current_user(request: Request, db: Session = Depends(get_db)):
    token = _token_from_request(request)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "missing bearer token or API key")
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    if token.startswith("key:"):
        raw = token[4:]
        row = db.query(models.ApiKey).filter(
            models.ApiKey.key_hash == security.session_hash(raw)).first()
        if not row or row.revoked_at:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid key")
        row.last_used_at = now
        db.commit()
        user = db.get(models.User, row.user_id)
    else:
        row = db.query(models.Session).filter(
            models.Session.token_hash == security.session_hash(token)).first()
        if not row or row.revoked_at or row.expires_at < now:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "invalid or expired session")
        user = db.get(models.User, row.user_id)
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "inactive user")
    return user


def require_role(*roles):
    def dep(user=Depends(current_user)):
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "insufficient role")
        return user
    return dep


def org_base(db: Session, user):
    return db.query(models.Org).get(user.org_id)