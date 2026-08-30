"""Vajra - findings storage (SQLite) and Finding model."""
import os
import sqlite3
import threading
import datetime
from collections import Counter

from core import mitre as _mitre

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 1.5, "info": 0.2}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLORS = {"critical": "#ff1744", "high": "#ff5252", "medium": "#ffb300",
              "low": "#4fc3f7", "info": "#9e9e9e"}
SEV_BY_RANK = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}

# Evidence confidence uses the Burp Suite-style scale: Certain / Firm /
# Tentative. Internal aliases are canonicalized: verified/conclusive/
# confirmed/reproduced -> certain; possible/suspected/likely -> tentative;
# low/speculative/unverified/unknown -> tentative.
CONFIDENCE_NORM = {
    "certain": "certain", "verified": "certain", "conclusive": "certain",
    "confirmed": "certain", "reproduced": "certain",
    "firm": "firm", "high": "firm",
    "tentative": "tentative", "possible": "tentative", "suspected": "tentative",
    "likely": "tentative", "low": "tentative", "speculative": "tentative",
    "unverified": "tentative", "unknown": "tentative",
}
CONFIDENCE_LABEL = {"certain": "Certain", "firm": "Firm",
                    "tentative": "Tentative"}

# Anti-false-positive policy: a finding may only claim a severity that its
# evidence confidence supports. Only proof-tested ("certain") evidence can be
# critical; "firm" evidence can reach high but must stay below critical;
# heuristic/differential signals ("tentative") are bounded to medium;
# speculative signals are bounded to low. This guarantees no unverified
# finding can ever be reported as critical/high.
CONFIDENCE_CAP = {
    "certain": 4, "verified": 4, "conclusive": 4, "confirmed": 4,
    "reproduced": 4,
    "firm": 3, "high": 3,
    "tentative": 2, "possible": 2, "suspected": 2, "likely": 2,
    "low": 1, "speculative": 1, "unverified": 1, "unknown": 1,
}

CONFIDENCE_ORDER = ["certain", "firm", "tentative"]


class Finding:
    def __init__(self, target, module, category, severity, title, detail="",
                 evidence="", remediation="", confidence="firm", mitre=None):
        if mitre is None:
            tid, tname = _mitre.lookup(module, category, title)
            mitre = "%s %s" % (tid, tname)
        self.target = target
        self.module = module
        self.category = category
        self.severity = severity.lower() if severity.lower() in SEV_RANK else "info"
        raw_conf = (confidence or "firm").lower()
        self.confidence = CONFIDENCE_NORM.get(raw_conf, "tentative")
        cap_rank = CONFIDENCE_CAP.get(raw_conf, CONFIDENCE_CAP["possible"])
        if SEV_RANK[self.severity] > cap_rank:
            bound_to = SEV_BY_RANK[cap_rank]
            if detail:
                detail += "\n"
            detail += ("[Bounded] claimed severity %s lowered to %s: evidence "
                       "confidence is '%s' and the check was not fully "
                       "proof-tested (anti-false-positive policy)."
                       % (self.severity, bound_to,
                          CONFIDENCE_LABEL.get(self.confidence,
                                               self.confidence)))
            self.severity = bound_to
        self.title = title
        self.detail = detail
        self.evidence = evidence[:20000]
        self.remediation = remediation
        self.mitre = mitre
        self.created_at = datetime.datetime.now().isoformat(timespec="seconds")

    def to_dict(self):
        d = self.__dict__.copy()
        d.setdefault("mitre", "")
        return d


SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT, module TEXT, category TEXT, severity TEXT,
    title TEXT, detail TEXT, evidence TEXT, remediation TEXT,
    confidence TEXT, created_at TEXT, mitre TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT, port INTEGER, service TEXT, banner TEXT, product TEXT,
    version TEXT, tls INTEGER DEFAULT 0, created_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT, event TEXT, detail TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
"""


class Database:
    def __init__(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def add_finding(self, f):
        if isinstance(f, dict):
            f = Finding(**f)
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM findings WHERE target=? AND module=? AND title=? LIMIT 1",
                (f.target, f.module, f.title))
            if cur.fetchone():
                return False
            self.conn.execute(
                "INSERT INTO findings (target,module,category,severity,title,detail,"
                "evidence,remediation,confidence,created_at,mitre)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (f.target, f.module, f.category, f.severity, f.title, f.detail,
                 f.evidence, f.remediation, f.confidence, f.created_at,
                 getattr(f, "mitre", "")))
            self.conn.commit()
        return True

    def add_service(self, target, port, service, banner="", product="",
                    version="", tls=False):
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM services WHERE target=? AND port=? LIMIT 1",
                (target, port))
            if cur.fetchone():
                return False
            self.conn.execute(
                "INSERT INTO services (target,port,service,banner,product,version,tls,created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (target, port, service, banner[:2000], product, version,
                 1 if tls else 0,
                 datetime.datetime.now().isoformat(timespec="seconds")))
            self.conn.commit()
        return True

    def add_event(self, target, event, detail=""):
        with self.lock:
            self.conn.execute(
                "INSERT INTO events (target,event,detail,created_at) VALUES (?,?,?,?)",
                (target, event, detail[:1000],
                 datetime.datetime.now().isoformat(timespec="seconds")))
            self.conn.commit()

    def findings(self, target=None):
        q = "SELECT target,module,category,severity,title,detail,evidence," \
            "remediation,confidence,created_at,IFNULL(mitre,'') FROM findings"
        args = ()
        if target:
            q += " WHERE target=?"
            args = (target,)
        q += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1" \
             " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at"
        rows = []
        with self.lock:
            for r in self.conn.execute(q, args):
                rows.append({
                    "target": r[0], "module": r[1], "category": r[2],
                    "severity": r[3], "title": r[4], "detail": r[5],
                    "evidence": r[6], "remediation": r[7], "confidence": r[8],
                    "created_at": r[9], "mitre": r[10] if len(r) > 10 else ""})
        return rows

    def services(self, target=None):
        q = "SELECT target,port,service,banner,product,version,tls FROM services"
        args = ()
        if target:
            q += " WHERE target=?"
            args = (target,)
        out = []
        with self.lock:
            for r in self.conn.execute(q, args):
                out.append({"target": r[0], "port": r[1], "service": r[2],
                            "banner": r[3], "product": r[4], "version": r[5],
                            "tls": bool(r[6])})
        return out

    def events_for(self, target):
        with self.lock:
            rows = [(r[0], r[1], r[2], r[3]) for r in
                    self.conn.execute(
                        "SELECT target,event,detail,created_at FROM events "
                        "WHERE target=? ORDER BY id", (target,))]
        return rows

    def events(self):
        with self.lock:
            rows = [(r[0], r[1], r[2], r[3]) for r in
                    self.conn.execute("SELECT target,event,detail,created_at FROM events ORDER BY id")]
        return rows

    def stats(self, target=None):
        c = Counter()
        q = "SELECT severity FROM findings"
        args = ()
        if target:
            q += " WHERE target=?"
            args = (target,)
        with self.lock:
            for (sev,) in self.conn.execute(q, args):
                c[sev] += 1
        return dict(c)

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
