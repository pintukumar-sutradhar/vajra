"""VAJRA platform data model.

Single-tenant-first layout: every entity carries an org_id so the later
SaaS step (per-tenant isolation on the existing tables) is additive rather
than a rewrite.
"""

import datetime

from sqlalchemy import (Boolean, DateTime, Float, ForeignKey, Integer, String,
                        Text)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from .db import Base


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class Org(Base):
    __tablename__ = "orgs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(60), unique=True, index=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                          default=_utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                          default=_utcnow)
    last_login_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    label: Mapped[str] = mapped_column(String(120), default="")
    key_hash: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(12), default="")
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                          default=_utcnow)
    revoked_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)
    last_used_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(100), unique=True,
                                            index=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                          default=_utcnow)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                          nullable=False)
    revoked_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    address: Mapped[str] = mapped_column(String(300), nullable=False)
    name: Mapped[str] = mapped_column(String(200), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    authorization_proof: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"),
                                                   nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                          default=_utcnow)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)


class EngineDef(Base):
    __tablename__ = "engine_defs"
    id: Mapped[int] = mapped_column(primary_key=True)
    engine_id: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    icon: Mapped[str] = mapped_column(String(40), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    target_kinds: Mapped[list] = mapped_column(JSON, default=list)
    profiles: Mapped[list] = mapped_column(JSON, default=list)
    params_schema: Mapped[dict] = mapped_column(JSON, default=dict)
    cfg: Mapped[dict] = mapped_column(JSON, default=dict)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"),
                                           index=True)
    engine_id: Mapped[str] = mapped_column(String(40), index=True)
    profile: Mapped[str] = mapped_column(String(20), default="deep")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    creds_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"),
                                                   nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending",
                                        index=True)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    exit_code: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    workdir: Mapped[str] = mapped_column(Text, default="")
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                          default=_utcnow)
    started_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)
    finished_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)

    target = relationship("Target")


class JobItem(Base):
    __tablename__ = "job_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), unique=True,
                                         index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued",
                                        index=True)
    worker: Mapped[str] = mapped_column(String(80), default="")
    claimed_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)
    heartbeat_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(Text, default="")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"),
                                           index=True)
    engine_id: Mapped[str] = mapped_column(String(40), index=True)
    ref: Mapped[str] = mapped_column(String(20), default="")
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[str] = mapped_column(String(20))
    category: Mapped[str] = mapped_column(String(60), default="")
    asset: Mapped[str] = mapped_column(String(300), default="")
    cwe: Mapped[str] = mapped_column(String(30), default="")
    cvss: Mapped[str] = mapped_column(String(30), default="")
    source_module: Mapped[str] = mapped_column(String(80), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="open",
                                        index=True)
    state_note: Mapped[str] = mapped_column(Text, default="")
    state_changed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    state_changed_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)
    resolved_by_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id"), nullable=True)
    dedup_key: Mapped[str] = mapped_column(String(300), default="", index=True)
    first_seen: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                          default=_utcnow)
    last_seen: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                         default=_utcnow)


class ScanEvent(Base):
    __tablename__ = "scan_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    ts: Mapped[datetime.datetime] = mapped_column(DateTime, default=_utcnow)
    level: Mapped[str] = mapped_column(String(12), default="info")
    message: Mapped[str] = mapped_column(Text, default="")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime.datetime] = mapped_column(DateTime, default=_utcnow)
    actor: Mapped[str] = mapped_column(String(80), default="")
    action: Mapped[str] = mapped_column(String(60), index=True)
    target_type: Mapped[str] = mapped_column(String(40), default="")
    target_id: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)