"""VAJRA — response baseline & differencing engine.

Every check that asks "does this resource exist?" or "did this payload
actually change anything?" runs through here.

The problem this solves: a scan engine that trusts a status code will report
a finding on every path of any server that answers 200 (or 403, or a 302 to
/login) for literally any URL. Trusting a substring will report XSS wherever
the input is echoed back — including escaped, in plain text. Both were real
false-positive sources in this codebase.

The approach: before asking "does /admin exist?", first ask the server about
paths that certainly do *not* exist, and record exactly how it answers.
Anything the server answers the same way is unproven, whatever the status
code says. Anything it answers differently genuinely differs, and is worth a
finding.

Kept stdlib-only to match the engine's existing posture.
"""
from __future__ import annotations

import hashlib
import re
import urllib.parse

# ---------------------------------------------------------------------------
# Response fingerprinting
# ---------------------------------------------------------------------------

_WS_RE = re.compile(r"\s+")
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# Statuses that mean "not here" on their own, provided the server also uses
# them for paths we know are absent.
NOT_FOUND_STATUSES = frozenset((404, 410))

# Bodies above this size are truncated before tokenising: a 5 MB page costs
# real time to shingle and adds nothing to the comparison.
_MAX_TOKEN_BODY = 200_000

# Two responses whose lengths differ by more than this factor are treated as
# different content regardless of how similar their text looks.
_LENGTH_FLOOR = 0.90

# Shingle similarity at or above this counts as "the same page".
_SIMILAR = 0.85

# Very short bodies (a bare "Not Found") have too few shingles to compare
# meaningfully; fall back to near-exact length matching for those.
_SHORT_BODY = 512
_SHORT_SLACK = 32


def _norm_path_variants(path):
    """Every spelling of `path` a server might echo back into an error page."""
    if not path:
        return ()
    out = {path, path.strip("/")}
    try:
        out.add(urllib.parse.unquote(path))
        out.add(urllib.parse.unquote(path).strip("/"))
    except Exception:
        pass
    return tuple(sorted((p for p in out if len(p) > 3), key=len, reverse=True))


def shingles(text, n=5):
    """Word n-grams of `text` as a set, for Dice similarity."""
    tokens = _TOKEN_RE.findall(text.lower())
    if len(tokens) < n:
        return {tuple(tokens)} if tokens else set()
    return {tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


def dice(a, b):
    """Dice coefficient over two shingle sets (0.0 .. 1.0)."""
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if not inter:
        return 0.0
    return 2.0 * inter / float(len(a) + len(b))


def _length_ratio(a, b):
    hi = max(a, b)
    if hi == 0:
        return 1.0
    return min(a, b) / float(hi)


class Fingerprint:
    """What a response looks like, reduced to what distinguishes one page
    from another: status, size, content type, redirect target, title, and a
    token-shingle digest of the body."""

    __slots__ = ("status", "length", "ctype", "location", "title", "body",
                 "_shingles", "_hash", "url")

    def __init__(self, resp, path=""):
        self.status = int(getattr(resp, "status", 0) or 0)
        body = getattr(resp, "body", "") or ""
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        headers = getattr(resp, "headers", None) or {}
        self.ctype = (headers.get("content-type", "") or "").split(";")[0].strip().lower()
        self.url = getattr(resp, "url", "") or ""
        # Strip every spelling of the requested path before comparing: a
        # soft-404 that echoes the path into its <title> must still match the
        # baseline taken with a random path, or it looks like a real page.
        # The redirect target needs the same treatment — a wildcard 302 to
        # `/login?next=<path>` carries a different Location on every request,
        # and comparing those verbatim makes the whole class look like real
        # findings.
        variants = _norm_path_variants(path)
        text = body[:_MAX_TOKEN_BODY]
        loc = headers.get("location", "") or ""
        for variant in variants:
            text = text.replace(variant, " ")
            loc = loc.replace(variant, " ")
        self.location = loc
        self.body = body
        # Length describes the *normalised* text, not the raw body. Measuring
        # the raw body reintroduces the echo: a 12-char probe path and a
        # 6-char real path produce soft-404s of different sizes, the ratio
        # guard rejects the match, and the soft-404 is promoted to REAL.
        self.length = len(text)
        tm = _TITLE_RE.search(text[:20000])
        self.title = _WS_RE.sub(" ", tm.group(1)).strip().lower() if tm else ""
        self._shingles = shingles(text)
        self._hash = hashlib.sha1(
            ("%d|%s|%s" % (self.status, self.title, text[:2048]))
            .encode("utf-8", "replace")).hexdigest()

    def similar_to(self, other):
        """True when these two responses are the same page for our purposes."""
        if self.status != other.status:
            return False
        # A differing redirect target means a genuinely different outcome:
        # a wildcard redirect all points at one place, a real one goes
        # somewhere specific.
        if self.location and other.location and self.location != other.location:
            return False
        if self.ctype and other.ctype and self.ctype != other.ctype:
            return False
        if _length_ratio(self.length, other.length) < _LENGTH_FLOOR:
            return False
        if self.length < _SHORT_BODY and other.length < _SHORT_BODY:
            return abs(self.length - other.length) <= _SHORT_SLACK
        return dice(self._shingles, other._shingles) >= _SIMILAR

    def __repr__(self):
        return "<Fingerprint %d %db %s>" % (self.status, self.length, self.ctype)


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

class Baseline:
    """How a host answers requests for things that do not exist.

    Built from several *shapes* of nonexistent path, because servers commonly
    behave differently across them: a PHP app 404s `/x.php` while answering a
    bare `/x` with the SPA shell, and a directory-style `/x/` can differ
    again. One probe (what this codebase used to do) misses two of the three.
    """

    def __init__(self, base, probes=None, error=""):
        self.base = base
        self.probes = list(probes or ())
        self.error = error

    @property
    def usable(self):
        return bool(self.probes)

    @property
    def statuses(self):
        return {p.status for p in self.probes}

    def match(self, fp):
        """Return the baseline probe this fingerprint matches, or None."""
        for probe in self.probes:
            if fp.similar_to(probe):
                return probe
        return None

    def describe(self):
        if not self.usable:
            return "no baseline (%s)" % (self.error or "no probes")
        parts = []
        for p in self.probes:
            parts.append("%d/%db" % (p.status, p.length))
        return "baseline " + ", ".join(parts)


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

REAL = "real"                # differs from a known-absent path: exists
ABSENT = "absent"            # answered exactly like a known-absent path
WILDCARD = "wildcard"        # catch-all: same answer for everything
UNREACHABLE = "unreachable"  # no response at all


def verdict(resp, baseline, path=""):
    """Classify a response against the host's not-found behaviour.

    Returns (verdict, reason). `REAL` is the only verdict that justifies
    reporting an existence finding; the others mean the response carries no
    evidence that this specific path exists.
    """
    fp = Fingerprint(resp, path)
    if fp.status == 0:
        return UNREACHABLE, "no response"
    if not (baseline and baseline.usable):
        # Without a baseline we cannot prove absence, but we must not silently
        # upgrade to "real" either — an unbaselined 200 is exactly the old
        # false-positive. Only a hard 404/410 is trustworthy unbaselined.
        if fp.status in NOT_FOUND_STATUSES:
            return ABSENT, "status %d" % fp.status
        return WILDCARD, "unbaselined %d (no reference)" % fp.status

    hit = baseline.match(fp)
    if hit is not None:
        if fp.status in NOT_FOUND_STATUSES:
            return ABSENT, "matches not-found baseline (%d)" % fp.status
        return WILDCARD, ("catch-all: same %d/%db response as a known-absent "
                          "path" % (fp.status, fp.length))
    if fp.status in NOT_FOUND_STATUSES:
        # A server-certified 404/410 is the strongest absence signal a host
        # can send. It must never be promoted to a "found" positive merely
        # because the not-found baseline happened to use a different status
        # (soft-404 catch-alls answer 200 for absent paths, so a later 404
        # would otherwise "differ from baseline" and get reported as real).
        return ABSENT, "status %d" % fp.status
    return REAL, "differs from baseline (%d/%db vs %s)" % (
        fp.status, fp.length, "/".join(str(s) for s in sorted(baseline.statuses)))


def is_real(resp, baseline, path=""):
    """Convenience predicate: does this response prove the path exists?"""
    return verdict(resp, baseline, path)[0] == REAL


# ---------------------------------------------------------------------------
# Baseline construction & caching
# ---------------------------------------------------------------------------

def _rand_token(n=12):
    import random
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alpha) for _ in range(n))


# The three path shapes a not-found probe should cover.
PROBE_SHAPES = ("file", "bare", "dir")


def _probe_paths():
    tok = _rand_token(12)
    return [("file", "/%s.php" % tok),
            ("bare", "/%s" % tok),
            ("dir", "/%s/" % tok)]


def build_baseline(engine, base, shapes=PROBE_SHAPES):
    """Probe `base` with paths that cannot exist and record how it answers."""
    probes, err = [], ""
    for shape, path in _probe_paths():
        if shape not in shapes:
            continue
        try:
            r = engine.http.get(base.rstrip("/") + path,
                                allow_redirects=False, timeout=8)
        except Exception as exc:
            err = repr(exc)[:200]
            continue
        probes.append(Fingerprint(r, path))
    bl = Baseline(base, probes, err)
    engine.log.debug("[baseline] %s -> %s" % (base, bl.describe()))
    return bl


def baseline_for(engine, base, shapes=PROBE_SHAPES):
    """Cached baseline for a host, so a 600-path directory bust costs three
    baseline requests rather than 600."""
    cache = engine.state.setdefault("_baselines", {})
    key = (base.rstrip("/"), tuple(shapes))
    if key not in cache:
        cache[key] = build_baseline(engine, base, shapes)
    return cache[key]


# ---------------------------------------------------------------------------
# Differential — negative controls for injection checks
# ---------------------------------------------------------------------------

class Differential:
    """Compares a payload response against a benign control response for the
    same parameter.

    A motive that fires on "the string `root:x:` appears" will fire on a page
    that mentions /etc/passwd in its help text. A motive that fires on "the
    string appears here and does *not* appear in the control response" will
    not. That is the whole point of a negative control, and it is what turns
    a guess into evidence.
    """

    def __init__(self, control, test, path=""):
        self.control = Fingerprint(control, path) if control is not None else None
        self.test = Fingerprint(test, path)
        self._control_text = self.control.body if self.control else ""

    @property
    def status_changed(self):
        return self.control is not None and self.test.status != self.control.status

    @property
    def length_delta(self):
        if self.control is None:
            return self.test.length
        return self.test.length - self.control.length

    @property
    def similarity(self):
        if self.control is None:
            return 0.0
        return dice(self.test._shingles, self.control._shingles)

    def changed(self, min_delta=24):
        """True when the payload measurably altered the response."""
        if self.control is None:
            return False
        if self.status_changed:
            return True
        return abs(self.length_delta) >= min_delta

    def new_text(self):
        """Body text present in the test response but absent from the
        control — the part of the response the payload is responsible for."""
        if not self._control_text:
            return self.test.body
        ctrl = self._control_text
        body = self.test.body
        # Cheap containment filter: drop lines that appear verbatim in the
        # control. Line granularity keeps this linear and good enough to
        # isolate injected content (a passwd line, a command's output).
        ctrl_lines = set(ctrl.splitlines())
        return "\n".join(ln for ln in body.splitlines()
                         if ln.strip() and ln not in ctrl_lines)

    def contains_new(self, needle):
        """True when `needle` appears in the test response but not in the
        control: the marker is attributable to the payload, not the page."""
        if needle not in self.test.body:
            return False
        return needle not in self._control_text
