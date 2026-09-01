"""VAJRA workspace — persistent engagement state spanning runs.

A workspace is a directory under Outputs/workspaces/<name>/ holding:
  - runs/<timestamp>.json   per-run snapshot (targets, findings, services)
  - latest.json             most recent snapshot (convenience pointer)
  - workspace_report.md   cumulative run narrative (retest delta + synthesis)
  - state/<target>.json     lightweight engine.state reuse (ports/services)

Consecutive scans of the same target are diffed against the last snapshot to
produce a retest delta: new / fixed / still-open finding sets."""
import hashlib
import datetime
import json
import os
import re

from core.database import SEV_RANK
from core.utils import PROJECT_ROOT

DEFAULT_ROOT = str(PROJECT_ROOT / "Outputs" / "workspaces")


def _slug(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(name)).strip("_") or "default"


def finding_key(f):
    return "%s::%s" % (f.get("module", ""), f.get("title", ""))


class Workspace:
    def __init__(self, name, root=None):
        slug = _slug(name)
        root = root or DEFAULT_ROOT
        self.dir = os.path.join(root, slug)
        self.runs_dir = os.path.join(self.dir, "runs")
        self.state_dir = os.path.join(self.dir, "state")
        for d in (self.dir, self.runs_dir, self.state_dir):
            os.makedirs(d, exist_ok=True)
        self.report_path = os.path.join(self.dir, "workspace_report.md")
        self.latest_path = os.path.join(self.dir, "latest.json")
        self.name = name

    # ---- snapshots -----------------------------------------------------

    def snapshot(self, per_target, profile="", meta=None):
        """per_target: dict display -> {'findings': [...], 'services': [...],
        'score': float}. Returns the snapshot dict and persists it."""
        now = datetime.datetime.now().isoformat(timespec="seconds")
        snap = {"generated": now, "profile": profile, "meta": meta or {},
                "targets": per_target}
        path = os.path.join(self.runs_dir,
                            "run_%s.json" % now.replace(":", "").replace("-", ""))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2, default=str)
        with open(self.latest_path, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2, default=str)
        self._trim()
        return snap

    def _trim(self, keep=30):
        try:
            runs = sorted(os.listdir(self.runs_dir))
            for r in runs[:-keep]:
                os.remove(os.path.join(self.runs_dir, r))
        except Exception:
            pass

    def latest(self):
        try:
            with open(self.latest_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def previous_target(self, display):
        """Most recent prior snapshot for a target (latest run containing it),
        or None."""
        snap = self.latest()
        if not snap:
            return None
        t = snap.get("targets") or {}
        if display in t:
            return t[display]
        return None

    # ---- delta ---------------------------------------------------------

    def delta_for(self, display, current_findings):
        """Compare current findings vs the last known snapshot of the target.
        Returns {'new': [...], 'fixed': [...], 'still_open': [...]} plus a
        status stamp. Matching key: (module, title)."""
        prev = self.previous_target(display) or {}
        prev_f = {(f.get("module"), f.get("title")): f
                  for f in prev.get("findings", [])}
        cur_f = {(f.get("module"), f.get("title")): f
                 for f in current_findings}
        new = [cur_f[k] for k in sorted(cur_f) if k not in prev_f]
        fixed = [prev_f[k] for k in sorted(prev_f) if k not in cur_f]
        still = [cur_f[k] for k in sorted(cur_f)
                 if k in prev_f and prev_f[k].get("severity") != "info"]
        still.sort(key=lambda f: -SEV_RANK.get(f.get("severity", "info"), 0))
        return {"new": new, "fixed": fixed, "still_open": still,
                "previous": prev.get("generated", "")}

    # ---- AI + state -------------------------------------------------

    def append_narrative(self, text):
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
        with open(self.report_path, "a", encoding="utf-8") as f:
            f.write("\n<!-- %s -->\n%s\n" % (stamp, text))

    def narrative_text(self, limit=8000):
        try:
            with open(self.report_path, encoding="utf-8") as f:
                return f.read()[-limit:]
        except Exception:
            return ""

    def save_state(self, display, state_dict):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(display))
        keep = {}
        for k in ("open_ports", "udp_open", "services", "web_targets",
                  "subdomains", "tech", "os_guess", "smb_shares",
                  "snmp", "ad", "cloud_indicators", "cloud_tech",
                  "cloud_buckets", "forms", "emails", "js", "channels",
                  "creds", "pages", "etc_hosts", "has_cloud_intel"):
            v = state_dict.get(k)
            if isinstance(v, (list, dict, str, int, float, bool)) or v is None:
                keep[k] = v
        # Persist which modules actually reached completion this run so a
        # --resume run can skip re-executing already-finished heavy modules.
        done = state_dict.get("_done_modules")
        if isinstance(done, (list, set)):
            keep["_done_modules"] = sorted(done)
        if "loot" in state_dict:
            keep["loot"] = state_dict["loot"]
        path = os.path.join(self.state_dir, "%s.json" % safe)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(keep, f, indent=2, default=str)

    def load_state(self, display):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(display))
        path = os.path.join(self.state_dir, "%s.json" % safe)
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    # ---- export/merge (collaboration) ---------------------------------

    def export(self, out_path):
        snap = self.latest() or {"targets": {}}
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({"tool": "VAJRA", "kind": "workspace-export",
                       "generated": datetime.datetime.now().isoformat(
                           timespec="seconds"),
                       "snapshots": [snap]}, f, indent=2, default=str)
        return out_path

    def import_export(self, in_path):
        """Merge an exported payload into this workspace as a snapshot."""
        with open(in_path, encoding="utf-8") as f:
            data = json.load(f)
        per_target = {}
        for snap in data.get("snapshots", [data]):
            for disp, tgt in (snap.get("targets") or {}).items():
                per_target.setdefault(disp, tgt)
        if per_target:
            return self.snapshot(per_target, profile=data.get("profile", ""),
                                 meta={"imported_from": in_path})
        return None

    def merged_findings(self):
        """Flatten all findings from all stored snapshots (latest first)."""
        out = {}
        try:
            path = self.latest_path
            with open(path, encoding="utf-8") as f:
                snap = json.load(f)
            for disp, tgt in (snap.get("targets") or {}).items():
                for f in tgt.get("findings", []):
                    f = dict(f)
                    f.setdefault("target", disp)
                    out[finding_key(f)] = f
        except Exception:
            pass
        return list(out.values())

    def export_findings(self, filepath):
        """Export merged findings to a JSON file."""
        merged = self.merged_findings()
        with open(filepath, 'w') as f:
            json.dump(merged, f, indent=2)