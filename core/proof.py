"""VAJRA — the proof gate.

One place decides whether a candidate becomes a finding.

The problem this solves: confidence used to be a string each module typed by
hand. 146 of ~250 finding sites in this codebase declared "firm" — a label the
severity cap lets rise to *high* — without anything structural requiring
evidence behind it. A module could write `confidence="firm"` on a bare status
code and the report would present it as an authoritative high-severity issue.

Here, a module cannot declare confidence at all. It supplies a `Proof`: what
it actually observed, and — for the injection classes — whether a negative
control came back clean. The gate validates that proof against a per-class
rule, and the *kind* of proof determines the confidence. No proof, no finding:
the candidate goes to the suppressed ledger instead, with the reason, so it is
visible rather than silently swallowed.

Stdlib-only.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Proof kinds
# ---------------------------------------------------------------------------

MARKER = "marker"            # a format marker only the real thing produces
EXTRACTION = "extraction"    # a value computed by the target (7*7 -> 49)
DIFFERENTIAL = "differential"  # payload changed behaviour vs a clean control
CALLBACK = "callback"        # the target connected back to us
AUTH = "auth"                # we obtained a session/privilege we did not have
OBSERVATION = "observation"  # a deterministic fact: header absent, port open

KINDS = (MARKER, EXTRACTION, DIFFERENTIAL, CALLBACK, AUTH, OBSERVATION)

# Kind -> the strongest severity its confidence can support. Matches the
# SEV_RANK scale in core.database (critical 4, high 3, medium 2, low 1).
#
# These express *trust*: how much the evidence kind can be relied on. A
# differential is inherently inferential, so it stops at high. A direct
# observation is deterministic and carries no such doubt — what limits an
# observation's severity is the class it belongs to (see Rule.cap), not the
# kind: "TLS 1.0 accepted" and "port 22 is open" are equally certain and
# wildly different in severity.
KIND_CAP = {
    MARKER: 4,
    EXTRACTION: 4,
    CALLBACK: 4,
    AUTH: 4,
    OBSERVATION: 4,
    DIFFERENTIAL: 3,
}

# Kind -> derived confidence. Only these two values exist now: anything that
# would have been "tentative" is suppressed instead of recorded.
KIND_CONFIDENCE = {
    MARKER: "certain",
    EXTRACTION: "certain",
    CALLBACK: "certain",
    AUTH: "certain",
    DIFFERENTIAL: "firm",
    OBSERVATION: "firm",
}

# Gate outcomes
PROVEN = "proven"
UNPROVEN = "unproven"
UNCLASSIFIED = "unclassified"


class Proof:
    """What a module actually observed.

    artifact      the raw string backing the claim (the passwd line, the
                  decoded base64, the reflected payload, the callback log)
    control_clean for injection classes: True when the same request with a
                  benign value did NOT produce the artifact
    reproduced    True when the observation was confirmed a second time
    baseline_delta measured change against the control, when numeric
    """

    __slots__ = ("kind", "artifact", "control_clean", "reproduced",
                 "baseline_delta", "note")

    def __init__(self, kind, artifact="", control_clean=None, reproduced=None,
                 baseline_delta=None, note=""):
        self.kind = kind
        self.artifact = artifact or ""
        self.control_clean = control_clean
        self.reproduced = reproduced
        self.baseline_delta = baseline_delta
        self.note = note

    def summary(self):
        bits = ["kind=%s" % self.kind]
        if self.control_clean is not None:
            bits.append("control=%s" % ("clean" if self.control_clean
                                        else "dirty"))
        if self.reproduced is not None:
            bits.append("reproduced=%s" % self.reproduced)
        if self.note:
            bits.append(self.note)
        return " ".join(bits)

    def __repr__(self):
        return "<Proof %s %db>" % (self.kind, len(self.artifact))


# ---------------------------------------------------------------------------
# Per-class rules
# ---------------------------------------------------------------------------

class Rule:
    """What counts as proof for one vulnerability class.

    kinds            acceptable Proof kinds
    markers          if set, the artifact must match at least one
    requires_control a clean negative control is mandatory
    requires_repro   the observation must have been confirmed twice
    cap              ceiling for this *class*, independent of evidence kind:
                     a missing security header is a real observation and still
                     never a high-severity finding
    why              shown to the analyst as "why this is proof"
    """

    __slots__ = ("kinds", "markers", "requires_control", "requires_repro",
                 "why", "cap")

    def __init__(self, kinds, markers=None, requires_control=False,
                 requires_repro=False, why="", cap=4):
        self.kinds = tuple(kinds)
        self.markers = tuple(markers or ())
        self.requires_control = requires_control
        self.requires_repro = requires_repro
        self.why = why
        self.cap = cap


# --- markers reused across classes -----------------------------------------

PASSWD_MARKERS = (
    "root:x:", "root:*:0:0:", "root:!:0:0:", "daemon:x:", "bin:x:",
    "root:$1$", "root:$6$", "root:$y$", "root:$2y$",
)
WININI_MARKERS = ("[extensions]", "; for 16-bit app support", "[fonts]",
                  "[mci extensions]")
SHADOW_MARKERS = ("root:$", "root:!", "root:*:")
HOSTS_MARKERS = ("localhost", "127.0.0.1", "::1")
UID_RE = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)")
WIN_WHOAMI_RE = re.compile(r"(?im)^(nt authority|.*\\[a-z0-9_$.\-]{2,32})\s*$")
UNAME_RE = re.compile(r"(?i)Linux\s+\S+\s+\d+\.\d+\.\d+")
HOSTNAME_RE = re.compile(r"(?im)^[a-z0-9][a-z0-9\-]{2,62}$")

SQL_ERR_RE = re.compile(
    r"(sql syntax|warning:\s*mysql_|unclosed quotation|"
    r"quoted string not properly terminated|pg::|fatal:\s*syntax|"
    r"sqlite3::|unrecognized token|ora-\d{5}|odbc.*driver|invalid query|"
    r"mysql_fetch|mysqli_|postgresql.*error|microsoft ole db|"
    r"system\.data\.sqlite|you have an error in your sql)", re.I)

# Base64 of a passwd file starts with "cm9vd" ("roo"). Requiring a decoded
# marker rather than the encoded text is what lets the engine recognise its
# own php://filter payloads — which it previously sent but could not read.
_B64_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")
_B64_SCAN = 120_000  # bound the decode attempt on large artifacts

# An unescaped payload in an executable position. Checking the payload's own
# position — rather than pattern-matching "something that looks like a script"
# anywhere on the page — is what stops two opposite errors: treating an
# escaped echo as XSS, and suppressing a real XSS on a page that legitimately
# calls alert() in its own code.
_ATTR_CONTEXT_RE = re.compile(r"\son[a-z]+\s*=\s*[\"']?[^\"']*$", re.I)
_URL_CONTEXT_RE = re.compile(
    r"\s(?:src|href|action|formaction|data|srcdoc|poster|background)\s*=\s*"
    r"[\"']?\s*(?:javascript:|data:text/html)", re.I)


def _in_executable_context(body, idx):
    """Is the payload starting at `idx` somewhere a browser would run it?

    Returns (ok, where).

    Only the markup *between* the enclosing `<` and the payload itself is
    considered. Looking past the payload would drag in the closing `>` and
    make the anchored attribute test fail — which would reject a genuine
    `<img src=x onerror="...">` — while looking at the whole page instead
    would accept a payload that merely sits next to someone else's inline
    script.
    """
    head = body[:idx]
    # Inside a <script> body: an opening tag with no later closing tag.
    if head.rfind("<script") > head.rfind("</script"):
        return True, "inside a <script> body"
    tag_start = head.rfind("<")
    if tag_start >= 0:
        tag = head[tag_start:]
        # A `>` before the payload means the tag closed: the payload is in
        # text content or a comment, not an attribute of this element.
        if ">" in tag:
            return False, ""
        if _ATTR_CONTEXT_RE.search(tag):
            return True, "inside an event-handler attribute"
        if _URL_CONTEXT_RE.search(tag):
            return True, "inside a javascript:/data: URL"
    return False, ""


# Public alias: core.payload_engine's motives need the same test.
in_executable_context = _in_executable_context


SECRET_MARKERS = (
    re.compile(r"BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"(?i)(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|redis|"
               r"amqp|mssql)://[^\s:@/]+:[^\s:@/]+@"),
)

# Archive magic: an exposed backup is a real file, not an HTML error page.
ARCHIVE_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"SQLite format 3\x00",
                 b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c", b"BZh",
                 b"ustar", b"-- MySQL dump", b"PGDMP")

ENV_LINE_RE = re.compile(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S+")


def _any(patterns, text):
    return any(p.search(text) for p in patterns)


def _has_any(needles, text):
    return any(n in text for n in needles)


def _b64_decoded_markers(artifact):
    """Decode base64 blobs inside an artifact and look for file markers.

    This is what makes `php://filter/convert.base64-encode/resource=/etc/passwd`
    — a payload this engine already sends — actually provable."""
    import base64 as _b64
    for blob in _B64_RE.findall((artifact or "")[:_B64_SCAN]):
        pad = "=" * (-len(blob) % 4)
        try:
            raw = _b64.b64decode(blob + pad, validate=False)
        except Exception:
            continue
        text = raw.decode("utf-8", "replace")
        if _has_any(PASSWD_MARKERS, text) or _has_any(WININI_MARKERS, text) \
                or _has_any(SHADOW_MARKERS, text) or UID_RE.search(text):
            return text
    return ""


# --- the registry -----------------------------------------------------------

def _injection(kinds=(MARKER, EXTRACTION, DIFFERENTIAL), markers=(),
               why=""):
    """Shared shape for the classes where a reflection or a pre-existing
    string could mimic a hit: a clean control is mandatory."""
    return Rule(kinds, markers=markers, requires_control=True, why=why)


PROOF_RULES = {
    # ---- injection: a clean negative control is required -------------------
    "lfi": _injection(
        markers=PASSWD_MARKERS + WININI_MARKERS + SHADOW_MARKERS + HOSTS_MARKERS,
        why="A file's own content appeared in the response and did not appear "
            "in the control response for the same parameter."),
    "rce": _injection(
        # CALLBACK included because the out-of-band case is the strongest
        # evidence there is: the target made a request to a listener whose URL
        # carried a token minted for this scan. Nothing on the page could have
        # produced that, so it is strictly better than a marker, not looser.
        kinds=(MARKER, EXTRACTION, DIFFERENTIAL, CALLBACK),
        why="Output matching the command that was actually sent appeared in "
            "the response, and not in the control."),
    "xss": _injection(
        kinds=(MARKER, EXTRACTION),
        why="The payload appeared unescaped in an executable position "
            "(inside a script body, an event handler, or a javascript: URL) "
            "and not in the control."),
    "sqli": _injection(
        markers=(SQL_ERR_RE,),
        why="A database error signature attributable to the payload appeared "
            "in the response and not in the control."),
    "sqli_blind": Rule(
        (DIFFERENTIAL,), requires_control=True, requires_repro=True,
        why="A time or boolean difference reproduced across repeated "
            "requests and was absent in the control."),
    "ssti": _injection(
        kinds=(EXTRACTION, MARKER),
        why="A value the template engine computed (7*7 -> 49) appeared, and a "
            "control expression did not produce it."),
    "xxe": _injection(
        markers=PASSWD_MARKERS + WININI_MARKERS + HOSTS_MARKERS,
        why="File content referenced by the XML entity was returned, and not "
            "returned for a control entity."),
    "ssrf": Rule(
        (CALLBACK, MARKER, DIFFERENTIAL), requires_control=True,
        why="The target connected back to our listener, or fetched a "
            "resource it could only reach with attacker-supplied input."),
    "open_redirect": Rule(
        (MARKER,), requires_control=True,
        why="The redirect Location points at the attacker-controlled host, "
            "and a benign value does not redirect there."),
    "crlf": Rule(
        (MARKER, EXTRACTION), requires_control=True,
        why="The injected header or body appeared only for the CRLF payload, "
            "not for the control."),
    "header_injection": Rule(
        (MARKER,), requires_control=True,
        why="An injected response header appeared only for the payload."),
    "nosql": _injection(kinds=(DIFFERENTIAL, MARKER),
                        why="The operator payload changed the response in a "
                            "way the control did not."),
    "ldap": _injection(kinds=(DIFFERENTIAL, MARKER),
                       why="The LDAP filter payload changed the response in a "
                           "way the control did not."),
    "xpath": _injection(kinds=(DIFFERENTIAL, MARKER),
                        why="The XPath payload changed the response in a way "
                            "the control did not."),
    "hpp": _injection(kinds=(DIFFERENTIAL,),
                      why="Parameter pollution changed behaviour relative to "
                          "the control."),
    "deserialization": Rule(
        (MARKER, CALLBACK, DIFFERENTIAL), requires_control=True,
        why="A deserialisation marker or callback was observed."),
    "race": Rule(
        (DIFFERENTIAL,), requires_repro=True,
        why="The race outcome reproduced across repeated concurrent "
            "attempts."),
    "prototype_pollution": _injection(
        kinds=(DIFFERENTIAL, EXTRACTION),
        why="A polluted property became observable in the response."),
    "cache_poison": Rule(
        (MARKER,), requires_repro=True,
        why="The poisoned response was served to a subsequent clean request."),

    # ---- credential & access ----------------------------------------------
    "default_creds": Rule(
        (AUTH,), why="Authentication succeeded with a default credential "
                     "pair, proven by a post-login artifact or session."),
    "weak_creds": Rule(
        (AUTH,), why="Authentication succeeded with a guessed credential."),
    "brute_force": Rule(
        (AUTH,), why="A valid credential was recovered and verified by "
                     "logging in."),
    "auth_bypass": Rule(
        (AUTH, MARKER, DIFFERENTIAL),
        why="A protected resource was retrieved without authorisation, or "
            "with an artifact only an authenticated principal receives."),
    "auth_logic": Rule(
        (DIFFERENTIAL, MARKER), requires_control=True,
        why="A logical control was bypassed in a way the control request "
            "did not achieve."),
    "privilege_escalation": Rule(
        (AUTH, MARKER), why="A privilege level was reached that the starting "
                            "principal did not hold, evidenced by the "
                            "resulting identity or token."),
    "jwt": Rule(
        (AUTH, MARKER, EXTRACTION),
        why="A forged or unsigned token was accepted, evidenced by access to "
            "a protected resource."),

    # ---- exposure: the marker is self-authenticating -----------------------
    "exposure": Rule(
        (MARKER, EXTRACTION, OBSERVATION, DIFFERENTIAL),
        why="Content matching a known-sensitive format was returned, or the "
            "resource answered measurably differently from the host's own "
            "response for a path that certainly does not exist."),
    "info_leak": Rule(
        (MARKER, EXTRACTION, OBSERVATION),
        why="Specific sensitive data was extracted from the response."),
    "secrets": Rule(
        (MARKER,), markers=SECRET_MARKERS,
        why="A credential or key matching a known format was found."),
    "sca": Rule(
        (EXTRACTION, MARKER),
        why="A component version was identified and mapped to a known "
            "vulnerability."),
    "cve": Rule(
        (MARKER, EXTRACTION),
        why="A version banner or exploit artifact matched a known CVE."),
    "webshell": Rule(
        (MARKER, EXTRACTION),
        why="A file with shell behaviour and a matching signature was "
            "retrieved."),
    "takeover": Rule(
        (MARKER,), why="A dangling CNAME/NS record matched a known takeover "
                       "fingerprint in the provider's own response."),
    "cloud": Rule(
        (MARKER, EXTRACTION),
        why="The cloud resource returned content proving it is public or "
            "misconfigured."),

    # ---- deterministic observations ----------------------------------------
    # The class ceiling is what keeps a genuine, certain observation from
    # presenting as a critical finding.
    "misconfiguration": Rule(
        (OBSERVATION, MARKER), cap=3,
        why="A configuration state was observed directly, not inferred."),
    "tls": Rule(
        (OBSERVATION, MARKER), cap=3,
        why="A TLS property was observed from the handshake or certificate."),
    "header": Rule(
        (OBSERVATION,), cap=2,
        why="A response header was observed to be absent or present as "
            "stated."),
    "cors": Rule(
        (OBSERVATION, MARKER), cap=3,
        why="The server reflected an attacker-controlled Origin and permitted "
            "credentials."),
    "cookie": Rule(
        (OBSERVATION,), cap=2,
        why="A cookie attribute was observed directly."),
    "network_service": Rule(
        (OBSERVATION, MARKER), cap=2,
        why="A service banner was read from the socket."),
    "network_tls": Rule(
        (OBSERVATION, MARKER), cap=3,
        why="A TLS property was read from the handshake."),
    "os_fingerprint": Rule(
        (OBSERVATION, MARKER), cap=1,
        why="An OS signature was observed in a response or stack behaviour."),
    "ad": Rule(
        (MARKER, EXTRACTION, AUTH),
        why="A directory object, hash, or ticket was retrieved."),
    "ad_misconfig": Rule(
        (OBSERVATION, MARKER), cap=3,
        why="A directory configuration state was read directly."),
    "policy": Rule(
        (OBSERVATION, MARKER), cap=2,
        why="A policy or header state was observed directly."),
    "compliance": Rule(
        (OBSERVATION, MARKER), cap=2,
        why="A benchmark control state was observed directly."),
    "business_logic": Rule(
        (DIFFERENTIAL, MARKER), requires_control=True,
        why="A workflow constraint was violated reproducibly."),
    "upload": Rule(
        (MARKER, EXTRACTION), requires_control=True,
        why="An uploaded file was retrieved back with its content intact."),
    "phishing": Rule(
        (OBSERVATION, MARKER), cap=1, why="A directly observed state."),
    "other": Rule(
        (MARKER, EXTRACTION, DIFFERENTIAL, CALLBACK, AUTH, OBSERVATION),
        why="A proof artifact was captured."),
}

# Aliases so a module can use the naming it already had.
_CLASS_ALIASES = {
    "web.dirbuster": "exposure",
    "dirbuster": "exposure",
    "loot": "exposure",
    "info-leak": "info_leak",
    "info_leak": "info_leak",
    "misconfig": "misconfiguration",
    "sqli_error": "sqli",
    "blind_sqli": "sqli_blind",
    "time_sqli": "sqli_blind",
    # vuln_scanner's own spelling of the timing class. Same mechanism as
    # time_sqli, so it has to land on the same rule.
    "sqli_time": "sqli_blind",
    "command_injection": "rce",
    "remote_code_execution": "rce",
    # Blind/out-of-band variants prove the same mechanism as their in-band
    # counterparts; the difference is in what was observed, which the proof
    # kind already carries.
    "rce_blind": "rce",
    "ssrf_blind": "ssrf",
    "hostinject": "header_injection",
    "host_header_injection": "header_injection",
    "path_traversal": "lfi",
    "directory_traversal": "lfi",
    "local_file_inclusion": "lfi",
    "reflected_xss": "xss",
    "stored_xss": "xss",
    "dom_xss": "xss",
    "template_injection": "ssti",
    "open_redirect": "open_redirect",
    "redirect": "open_redirect",
    "xxe_injection": "xxe",
    "server_side_request_forgery": "ssrf",
    "insecure_deserialization": "deserialization",
    "default_credentials": "default_creds",
    "weak_credentials": "weak_creds",
    "credential_stuffing": "brute_force",
    "privesc": "privilege_escalation",
    "kerberos": "ad",
    "smb": "ad",
    "ldap_enum": "ad",
    "network": "network_service",
    "service": "network_service",
    "tls_audit": "tls",
    "security_headers": "header",
    "cors_misconfig": "cors",
    "cloud_storage": "cloud",
    "subdomain_takeover": "takeover",
    "api": "misconfiguration",
    "graphql": "misconfiguration",
    "saml": "auth_bypass",
}


def resolve_class(cls):
    """Canonicalise a class name; returns None when unknown."""
    if not cls:
        return None
    key = str(cls).strip().lower().replace(" ", "_").replace("-", "_")
    key = _CLASS_ALIASES.get(key, key)
    if key in PROOF_RULES:
        return key
    # Allow dotted / prefixed spellings: "web.lfi" -> "lfi".
    tail = key.rsplit(".", 1)[-1]
    tail = _CLASS_ALIASES.get(tail, tail)
    return tail if tail in PROOF_RULES else None


def rule_for(cls):
    canon = resolve_class(cls)
    return PROOF_RULES.get(canon) if canon else None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate(cls, proof):
    """Return (ok, canonical_class, reason).

    `ok` is True only when the proof satisfies the class rule. Every failure
    carries a reason suitable for the suppressed ledger and the verbose log.
    """
    canon = resolve_class(cls)
    if canon is None:
        return False, None, "no proof rule registered for class %r" % (cls,)
    rule = PROOF_RULES[canon]
    if proof is None:
        return False, canon, "no proof supplied for class %s" % canon
    if proof.kind not in KINDS:
        return False, canon, "unknown proof kind %r" % (proof.kind,)
    if proof.kind not in rule.kinds:
        return False, canon, (
            "proof kind %s is not acceptable for %s (expected %s)"
            % (proof.kind, canon, "/".join(rule.kinds)))
    if not proof.artifact and proof.kind != OBSERVATION:
        return False, canon, "proof artifact is empty"
    if rule.requires_control:
        if proof.control_clean is None:
            # Fail closed. A class that demands a negative control cannot be
            # proven without one, and silently treating "no control run" as
            # "control came back clean" is how an unproven claim becomes a
            # finding.
            return False, canon, (
                "no negative control was run — %s cannot be proven without "
                "one" % canon)
        if proof.control_clean is not True:
            return False, canon, (
                "negative control did not come back clean — the observation "
                "may be pre-existing page content, not evidence of %s" % canon)
    if rule.requires_repro and proof.reproduced is not True:
        return False, canon, (
            "the observation did not reproduce on a second attempt")
    if rule.markers and not _artifact_matches(rule.markers, proof):
        return False, canon, (
            "artifact does not contain a marker proving %s" % canon)
    return True, canon, "ok"


def _artifact_matches(markers, proof):
    text = proof.artifact or ""
    if text in ("", None) and proof.kind == OBSERVATION:
        # Observation artifacts are structured facts; the note carries them.
        text = proof.note or ""
    for m in markers:
        if hasattr(m, "search"):
            if m.search(text):
                return True
        elif isinstance(m, str) and m in text:
            return True
    # Base64-encoded file content (php://filter and friends).
    if _b64_decoded_markers(text):
        return True
    return False


def confidence_for(proof):
    """Confidence is derived from the proof kind — never declared."""
    return KIND_CONFIDENCE.get(proof.kind, "tentative")


def cap_for(cls, proof):
    """Severity ceiling: the stricter of what the evidence kind supports and
    what the class can ever be."""
    rule = rule_for(cls)
    kind_cap = KIND_CAP.get(proof.kind, 0) if proof else 0
    if rule is None:
        return kind_cap
    return min(kind_cap, rule.cap)


def why_for(cls):
    rule = rule_for(cls)
    return rule.why if rule else ""


# ---------------------------------------------------------------------------
# Convenience constructors, so call sites stay short
# ---------------------------------------------------------------------------

def marker(artifact, control_clean=None, note=""):
    return Proof(MARKER, artifact, control_clean=control_clean, note=note)


def extraction(artifact, control_clean=None, note=""):
    return Proof(EXTRACTION, artifact, control_clean=control_clean, note=note)


def differential(artifact, control_clean=True, reproduced=False, delta=None,
                 note=""):
    return Proof(DIFFERENTIAL, artifact, control_clean=control_clean,
                 reproduced=reproduced, baseline_delta=delta, note=note)


def callback(artifact, note=""):
    return Proof(CALLBACK, artifact, note=note)


def auth(artifact, note=""):
    return Proof(AUTH, artifact, note=note)


def observation(artifact, note=""):
    return Proof(OBSERVATION, artifact, note=note)


def _control_state(marker_present, control_body):
    """Tri-state: None when no control was run, else whether it came back
    clean. `None` is not a pass — see validate()."""
    if control_body is None:
        return None
    return not marker_present(control_body)


def xss_proof(body, payload, control_body=None, note=""):
    """Build an XSS proof only when the payload survived unescaped into a
    position a browser would execute.

    A parameter echoed back as text — or as `&lt;svg onload=...&gt;` — is not
    XSS, and treating it as such was a primary false-positive source. Use a
    payload carrying a random nonce (`engine.nonce()`), which also makes the
    negative control meaningful: if the control response contains the nonce,
    something is wrong with the test, not the target.
    """
    body = body or ""
    if not payload:
        return Proof(MARKER, "", control_clean=False, note="no payload")
    idx = body.find(payload)
    if idx < 0:
        return Proof(MARKER, "", control_clean=False,
                     note="payload not reflected verbatim (escaped or "
                          "filtered)")
    ok, where = _in_executable_context(body, idx)
    if not ok:
        return Proof(MARKER, "", control_clean=False,
                     note="payload reflected but not in an executable "
                          "context")
    clean = _control_state(lambda t: payload in t, control_body)
    frag = body[max(0, idx - 120):idx + len(payload) + 120].strip()
    return Proof(MARKER, frag, control_clean=clean,
                 note="reflected %s" % where)


def lfi_proof(body, control_body=None, note=""):
    """Build an LFI proof from a response, decoding base64 file content.

    Recognises the plain-text markers and the base64 output of the
    php://filter payloads this engine sends."""
    body = body or ""
    found = ""
    for m in PASSWD_MARKERS + WININI_MARKERS + SHADOW_MARKERS + HOSTS_MARKERS:
        if m in body:
            found = m
            break
    if not found:
        decoded = _b64_decoded_markers(body)
        if decoded:
            for m in PASSWD_MARKERS + WININI_MARKERS + SHADOW_MARKERS:
                if m in decoded:
                    found = m
                    break
            if not found and UID_RE.search(decoded):
                found = UID_RE.search(decoded).group(0)
            if found:
                body = decoded
    if not found:
        return Proof(MARKER, "", control_clean=False,
                     note="no file-content marker in the response")
    clean = _control_state(lambda t: found in t, control_body)
    return Proof(MARKER, _snippet(body, found), control_clean=clean, note=note)


def rce_proof(body, control_body=None, note=""):
    """Build an RCE proof from actual command output."""
    body = body or ""
    found = ""
    m = UID_RE.search(body)
    if m:
        found = m.group(0)
    else:
        m = UNAME_RE.search(body)
        if m:
            found = m.group(0)
    if not found:
        return Proof(MARKER, "", control_clean=False,
                     note="no command-output signature in the response")
    clean = _control_state(lambda t: found in t, control_body)
    return Proof(MARKER, _snippet(body, found), control_clean=clean, note=note)


def sqli_proof(body, control_body=None, note=""):
    body = body or ""
    m = SQL_ERR_RE.search(body or "")
    if not m:
        return Proof(MARKER, "", control_clean=False,
                     note="no database error signature in the response")
    clean = _control_state(lambda t: bool(SQL_ERR_RE.search(t)), control_body)
    return Proof(MARKER, _snippet(body, m.group(0)), control_clean=clean,
                 note=note)


def ssti_proof(body, expected, control_body=None, note=""):
    """Build an SSTI proof: the engine must have computed `expected`, and a
    control expression must not have produced it."""
    body = body or ""
    if expected not in body:
        return Proof(EXTRACTION, "", control_clean=False,
                     note="computed value %r not present" % expected)
    clean = _control_state(lambda t: expected in t, control_body)
    return Proof(EXTRACTION, _snippet(body, expected), control_clean=clean,
                 note=note)


def _snippet(text, needle, pad=160):
    i = text.find(needle)
    if i < 0:
        return text[:pad * 2]
    return text[max(0, i - pad):i + len(needle) + pad].strip()
