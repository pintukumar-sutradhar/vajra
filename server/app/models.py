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
    # Pause is stop/continue of the engine process (SIGSTOP/SIGCONT), driven
    # by this flag; the worker records when it happened so progress and ETA
    # can discount the paused interval instead of reporting it as scan time.
    pause_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    paused_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)
    resumed_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)
    paused_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    # 0 normal, 1 -v (baseline/suppression decisions), 2 -vv (every probe).
    verbose: Mapped[int] = mapped_column(Integer, default=0)
    # Candidates the proof gate refused. Surfaced in the audit ledger so a
    # suppression is visible rather than silently dropped.
    suppressed_count: Mapped[int] = mapped_column(Integer, default=0)
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
    # What proved it, and the ceiling that evidence is allowed to reach.
    # `proof` reads like "extraction [php://filter base64 decoded to a passwd
    # marker]" and is what turns a finding from a claim into a demonstration —
    # it is the field an operator checks before believing anything else on the
    # page, so it survives the trip out of the bundle rather than staying
    # behind in the run's sqlite.
    proof: Mapped[str] = mapped_column(Text, default="")
    cap: Mapped[str] = mapped_column(String(20), default="")
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
    # Vuln-management workflow: who owns this finding and when it must be
    # remediated. SLA-able in the UI and, together with `risk`, lets the
    # dashboard rank work instead of just inventories.
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"),
                                                    nullable=True)
    due_date: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True, index=True)
    # Evidence-backed risk weight for this finding (see findings.set_risk).
    # Distinct from severity: two "high" findings with different reachability
    # should not read as equal in the executive view.
    risk: Mapped[float] = mapped_column(Float, default=0.0)
    # Re-verification bookkeeping: the last re-probe and what it concluded, so
    # the operator sees at a glance whether a finding was still reproducible
    # the last time it was checked rather than assuming it is.
    rechecked_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)
    recheck_outcome: Mapped[str] = mapped_column(String(20), default="")
    rechecked_by_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id"), nullable=True)


# Evidence-backed risk weighting: two "high" findings are not equal when one
# is reachable, certain and yields RCE and the other is theoretical. The
# severity ceiling is scaled by the proof's confidence and lifted by what the
# proof actually allows, so risk is computed from what was demonstrated.
_SEV_W = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5,
          "info": 0.5}
_CAP_BONUS = {"rce": 1.5, "unauth": 1.0, "auth": 0.4,
              "denial-of-service": 0.5, "info": 0.0}
_CONF_MULT = {"certain": 1.0, "firm": 0.9, "high": 0.9, "medium": 0.8,
              "tentative": 0.7, "low": 0.6}


def compute_risk(severity, confidence, cap):
    base = _SEV_W.get((severity or "info").lower(), 1.0)
    base *= _CONF_MULT.get((confidence or "").lower(), 0.8)
    bonus = _CAP_BONUS.get((cap or "").lower(), 0.3)
    return round(min(10.0, base + bonus), 1)


class Schedule(Base):
    """Recurring scan plan: when due, the worker enqueues a Scan just like a
    manual one (same engine contract, same queue, same lifecycle)."""

    __tablename__ = "schedules"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"),
                                           index=True)
    engine_id: Mapped[str] = mapped_column(String(40), index=True)
    profile: Mapped[str] = mapped_column(String(20), default="full")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    label: Mapped[str] = mapped_column(String(200), default="")
    # Hours between runs (0.5 = every 30 minutes). next_run is computed on
    # create/update and advanced by interval when a run is fired.
    interval_hours: Mapped[float] = mapped_column(Float, default=24.0)
    next_run: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_run_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True)
    last_scan_id: Mapped[int | None] = mapped_column(Integer, default=0)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"),
                                                   nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                          default=_utcnow)

    target = relationship("Target")


class ScanEvent(Base):
    __tablename__ = "scan_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    ts: Mapped[datetime.datetime] = mapped_column(DateTime, default=_utcnow)
    level: Mapped[str] = mapped_column(String(12), default="info")
    message: Mapped[str] = mapped_column(Text, default="")


class SuppressedCheck(Base):
    """Candidates the proof gate refused.

    These are deliberately NOT findings: nothing here reached the evidentiary
    bar for its class. They are kept so a suppression is visible and
    reviewable — an empty ledger and a broken scanner look identical from the
    findings list alone, and a genuine issue that was suppressed for a bad
    reason should be findable rather than invisible.
    """

    __tablename__ = "suppressed_checks"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"),
                                           index=True)
    module: Mapped[str] = mapped_column(String(80), default="")
    cls: Mapped[str] = mapped_column(String(60), default="")
    severity: Mapped[str] = mapped_column(String(20), default="")
    title: Mapped[str] = mapped_column(String(500), default="")
    # Why the gate refused it: no proof, dirty control, no rule for the class,
    # or a marker that was not present.
    reason: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    dedup_key: Mapped[str] = mapped_column(String(300), default="", index=True)
    ts: Mapped[datetime.datetime] = mapped_column(DateTime, default=_utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime.datetime] = mapped_column(DateTime, default=_utcnow)
    actor: Mapped[str] = mapped_column(String(80), default="")
    action: Mapped[str] = mapped_column(String(60), index=True)
    target_type: Mapped[str] = mapped_column(String(40), default="")
    target_id: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)