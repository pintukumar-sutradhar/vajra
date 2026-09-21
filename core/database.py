"""Vajra - findings storage (SQLite) and Finding model."""
import os
import re
import sqlite3
import threading
import datetime
import json as _json
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


# ---- Evidence-confidence ladder -------------------------------------------
# The declared confidence is the module's claim, but it is merged with an
# *evidence-derived* grade so the report reflects what the evidence actually
# proves. Strong proof artifacts (krb5tgs hash, NTLM hash, minted cert, OOB
# callback, confirmed command output, or a reproduced scripted exploit) let a
# finding climb the ladder; heuristic-only signals can never.
_EVID_FIRM = [
    re.compile(r"\$krb5tgs\$", re.I),
    re.compile(r"\bNTDS|\ba[0-9a-f]{31}=\b|\b[a-f0-9]{32}(:[^#]{0,40}){3}\b", re.I),
    re.compile(r"has password\b", re.I),
    re.compile(r"\brc4-hmac\b|\brc4[_@]?hmac\b", re.I),
    re.compile(r"\[VERIFIED\]", re.I),
    re.compile(r"\.pfx\b|\.pem\b|\.crt\b|BEGIN CERTIFICATE", re.I),
    re.compile(r"command output\b|exit code 0\b|# .*[Ss]uccess", re.I),
    re.compile(r"session|smtp relay|relay", re.I),
]
_EVID_CERTAIN = [
    re.compile(r"\$krb5tgs\$", re.I),
    re.compile(r"\ba[0-9a-f]{31}=\b", re.I),
    re.compile(r"\bNT hash\b|\bNTDS\b", re.I),
    re.compile(r"\[VERIFIED\]", re.I),
]


def ladder_evidence(confidence, evidence="", category=""):
    """Return the ladder-merged confidence ('certain'|'firm'|'tentative').

    Takes the STRONGER of the declared confidence and the evidence-derived
    grade. A module that forgets to claim proof still gets credit for proof
    artifacts in its evidence; a module that over-claims with no proof stays
    capped at whatever the evidence supports. Never returns something lower
    than what the declared confidence already proves.
    """
    ev = (evidence or "") or ""
    derived = "tentative"
    if any(p.search(ev) for p in _EVID_CERTAIN) and \
            str(category or "").startswith("exploit"):
        derived = "certain"
    elif any(p.search(ev) for p in _EVID_FIRM):
        derived = "firm"
    declared = CONFIDENCE_NORM.get((confidence or "tentative").lower(),
                                   "tentative")
    order = {"tentative": 0, "firm": 1, "certain": 2}
    if order[derived] > order[declared]:
        return derived
    return declared


def evidence_cap(evidence="", category=""):
    """Sev-left cap awarded purely by evidence strength: 4 for a confirmed
    exploit artifact, 3 for solid reproducible proof, else 0 (no elevation).
    Confirm/graded from _EVID_* markers only; empty/heuristic evidence grants
    nothing, so the declared claim's strictness (e.g. 'low') is preserved."""
    ev = (evidence or "") or ""
    if any(p.search(ev) for p in _EVID_CERTAIN) and \
            str(category or "").startswith("exploit"):
        return 4
    if any(p.search(ev) for p in _EVID_FIRM):
        return 3
    return 0


class Finding:
    def __init__(self, target, module, category, severity, title, detail="",
                 evidence="", remediation="", confidence="firm", mitre=None,
                 cap=None, proof="", request="", response="", meta=None):
        if mitre is None:
            tid, tname = _mitre.lookup(module, category, title)
            mitre = "%s %s" % (tid, tname)
        self.target = target
        self.module = module
        self.category = category
        self.severity = severity.lower() if severity.lower() in SEV_RANK else "info"
        raw_conf = (confidence or "firm").lower()
        # Evidence-confidence ladder: merge declared confidence with what the
        # evidence string actually proves, then enforce the anti-FP severity cap
        # from the strongest of the declared claim and the proof in the evidence.
        #
        # `cap` is set by core.proof's gate (engine.record) from the *kind* of
        # proof a module actually supplied, and is authoritative when present:
        # a module cannot claim more severity than its proof kind supports.
        self.confidence = ladder_evidence(raw_conf, evidence, category)
        declared_cap = CONFIDENCE_CAP.get(raw_conf, CONFIDENCE_CAP["possible"])
        if cap is not None:
            cap_rank = min(cap, max(declared_cap, evidence_cap(evidence,
                                                               category)))
        else:
            cap_rank = max(declared_cap, evidence_cap(evidence, category))
        self.proof = proof
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
        self.request = request or ""
        self.response = response or ""
        self.meta = meta if isinstance(meta, dict) else {}
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
    confidence TEXT, created_at TEXT, mitre TEXT DEFAULT '',
    -- What proved this finding, and the severity ceiling that evidence
    -- supports. Both are computed by the proof gate; storing them is what
    -- lets a reviewer see the demonstration instead of only the claim.
    proof TEXT DEFAULT '', cap TEXT DEFAULT '',
    -- The raw HTTP request and response that proved this finding (web
    -- findings only), plus a small metadata blob (found-at, host:port,
    -- method+path, module). Empty for findings that never touched HTTP.
    request TEXT DEFAULT '', response TEXT DEFAULT '',
    meta TEXT DEFAULT ''
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
-- Candidates the proof gate refused to promote to findings. Kept so an
-- operator can see *what was suppressed and why* rather than having to trust
-- that nothing real was dropped (see core/proof.py).
CREATE TABLE IF NOT EXISTS suppressed (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT, module TEXT, cls TEXT, severity TEXT, title TEXT,
    reason TEXT, detail TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_suppressed_target ON suppressed(target);
"""


class Database:
    def __init__(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.executescript(SCHEMA)
        self._ensure_columns()
        self.conn.commit()

    def _ensure_columns(self):
        """Add columns introduced after a bundle was created.

        CREATE TABLE IF NOT EXISTS is a no-op on an existing table, so a run
        dir written by an earlier version keeps the old column set. Adding the
        column is enough here: these are per-run bundles, and the reader
        defaults a missing value.
        """
        wanted = (("findings", "proof", "TEXT DEFAULT ''"),
                  ("findings", "cap", "TEXT DEFAULT ''"),
                  ("findings", "request", "TEXT DEFAULT ''"),
                  ("findings", "response", "TEXT DEFAULT ''"),
                  ("findings", "meta", "TEXT DEFAULT ''"))
        for table, col, decl in wanted:
            try:
                cols = {r[1] for r in
                        self.conn.execute("PRAGMA table_info(%s)" % table)}
            except sqlite3.Error:
                continue
            if cols and col not in cols:
                try:
                    self.conn.execute("ALTER TABLE %s ADD COLUMN %s %s"
                                      % (table, col, decl))
                except sqlite3.Error:
                    pass

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
                "evidence,remediation,confidence,created_at,mitre,proof,cap,"
                "request,response,meta)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f.target, f.module, f.category, f.severity, f.title, f.detail,
                 f.evidence, f.remediation, f.confidence, f.created_at,
                 getattr(f, "mitre", ""), getattr(f, "proof", "") or "",
                 str(getattr(f, "cap", "") or ""),
                 getattr(f, "request", "") or "",
                 getattr(f, "response", "") or "",
                 _json.dumps(getattr(f, "meta", {}) or {})))
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

    def add_suppressed(self, target, module, cls, severity, title, reason,
                       detail=""):
        """Record a candidate the proof gate refused to promote."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM suppressed WHERE target=? AND module=? AND "
                "title=? AND reason=? LIMIT 1",
                (target, module, title, reason))
            if cur.fetchone():
                return False
            self.conn.execute(
                "INSERT INTO suppressed (target,module,cls,severity,title,"
                "reason,detail,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (target, module, cls, severity, title, reason,
                 (detail or "")[:4000],
                 datetime.datetime.now().isoformat(timespec="seconds")))
            self.conn.commit()
        return True

    def suppressed(self, target=None):
        q = ("SELECT target,module,cls,severity,title,reason,detail,created_at"
             " FROM suppressed")
        args = ()
        if target:
            q += " WHERE target=?"
            args = (target,)
        q += " ORDER BY id"
        rows = []
        with self.lock:
            for r in self.conn.execute(q, args):
                rows.append({"target": r[0], "module": r[1], "cls": r[2],
                             "severity": r[3], "title": r[4], "reason": r[5],
                             "detail": r[6], "created_at": r[7]})
        return rows

    def findings(self, target=None):
        q = "SELECT target,module,category,severity,title,detail,evidence," \
            "remediation,confidence,created_at,IFNULL(mitre,'')," \
            "IFNULL(proof,''),IFNULL(cap,''),IFNULL(request,'')," \
            "IFNULL(response,''),IFNULL(meta,'') FROM findings"
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
                    "created_at": r[9], "mitre": r[10] if len(r) > 10 else "",
                    "proof": r[11] if len(r) > 11 else "",
                    "cap": r[12] if len(r) > 12 else "",
                    "request": r[13] if len(r) > 13 else "",
                    "response": r[14] if len(r) > 14 else "",
                    "meta": _json.loads(r[15]) if len(r) > 15 and r[15] else {}})
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
