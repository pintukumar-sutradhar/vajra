"""VAJRA platform API."""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models
from .api import auth, dashboard, engines, findings, reports, scans, targets
from .config import BRAND, settings
from .db import SessionLocal, init_db
from .security import hash_password

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("vajra.platform")


def seed(db):
    from .worker_engines import upsert_engines
    upsert_engines(db)
    org = db.query(models.Org).filter(models.Org.slug == "default").first()
    if not org:
        org = models.Org(name="Default", slug="default")
        db.add(org)
        db.flush()
    if not db.query(models.User).filter(
            models.User.username == "admin").first():
        db.add(models.User(org_id=org.id, username="admin",
                           display_name="Administrator",
                           password_hash=hash_password(
                               settings.admin_password),
                           role="admin"))
    db.commit()


def make_app():
    init_db()
    app = FastAPI(title="VAJRA Platform API", version="0.1.0",
                  description="Offensive security platform control plane")
    session = SessionLocal()
    try:
        seed(session)
    finally:
        session.close()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_origin_regex=r".*" if "*" in settings.cors_origins else None,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"])
    for r in (auth.router, targets.router, engines.router, scans.router,
              findings.router, reports.router, dashboard.router):
        app.include_router(r)

    @app.get("/health")
    def health():
        return {"ok": True, "product": BRAND["product"],
                "edition": BRAND["edition"], "version": "0.1.0"}
    return app


app = make_app()