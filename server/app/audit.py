"""Audit logging helper."""

from . import models


def log(db, actor, action, target_type="", target_id=0, detail=None):
    db.add(models.AuditLog(actor=actor, action=action,
                           target_type=target_type,
                           target_id=int(target_id or 0),
                           detail=detail or {}))
    db.commit()