"""Seed EngineDef rows into the platform DB from the engine templates."""

from ..worker.engine_defs import ENGINES

from . import models


def upsert_engines(db):
    for engine_id, defn in ENGINES.items():
        row = db.query(models.EngineDef).filter(
            models.EngineDef.engine_id == engine_id).first()
        fields = {"label": defn["label"], "description": defn["description"],
                  "icon": defn.get("icon", ""),
                  "enabled": True,
                  "target_kinds": defn["target_kinds"],
                  "profiles": defn["profiles"],
                  "params_schema": defn.get("params_schema", {}),
                  "cfg": defn.get("cfg", {})}
        if row:
            for k, v in fields.items():
                setattr(row, k, v)
        else:
            db.add(models.EngineDef(
                engine_id=engine_id,
                label=defn["label"],
                description=defn["description"],
                icon=defn.get("icon", ""),
                target_kinds=defn["target_kinds"],
                profiles=defn["profiles"],
                params_schema=defn.get("params_schema", {}),
                cfg=defn.get("cfg", {})))
    db.commit()