"""VAJRA post.loot — high-value file survey on hosts we can log into.

When a credential set (from network.brute or the operator) opens an SSH
session, this module lists read-only breadcrumb paths that commonly hold
secrets: user/home keys, cloud creds, kube/netrc/history files. It never
downloads or modifies anything — it reports what is present and readable.

Without a usable SSH transport (paramiko) or credentials it stops with an
info finding instead of pretending."""
import os

from core.database import Finding

try:
    import paramiko
    HAVE_PARAMIKO = True
except Exception:
    paramiko = None
    HAVE_PARAMIKO = False

PATHS = [
    ("ssh-keys", ["~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_dsa",
                  "~/.ssh/authorized_keys"]),
    ("cloud-creds", ["~/.aws/credentials", "~/.aws/config",
                     "~/.azure/azureProfile.json", "~/.gcloud/access_tokens.db",
                     "~/.config/gcloud/credentials.db",
                     "~/.config/gcloud/legacy_credentials"]),
    ("k8s", ["~/.kube/config", "~/.kube/admin.conf"]),
    ("netrc-hist", ["~/.netrc", "~/.bash_history", "~/.zsh_history",
                    "~/.profile", "~/.bash_profile", "~/.docker/config.json"]),
    ("notes", ["~/notes*", "~/passwords*", "~/secrets*", "~/creds*"]),
]

NAMES = {"ssh": "SSH private keys", "cloud-creds": "cloud provider creds",
         "k8s": "Kubernetes config", "netrc-hist":
         "netrc / shell history / docker config", "notes":
         "password-adjacent notes"}


def _creds(engine):
    out = []
    for entry in engine.state.get("creds", []):
        if not isinstance(entry, (list, tuple)) or len(entry) < 4:
            continue
        kind, user, pw, host = entry[:4]
        if "ssh" in str(kind).lower():
            out.append((user, pw, host))
    return out


def _exec(cli, command):
    try:
        _in, out, err = cli.exec_command(command, timeout=20)
        return (out.read().decode("utf-8", "replace") +
                err.read().decode("utf-8", "replace")).strip()
    except Exception:
        return ""


def _survey(cli):
    found = []
    for cat, paths in PATHS:
        hits = []
        for p in paths:
            out = _exec(cli, "test -e %s && echo YES" % p)
            if "YES" in out:
                reads = _exec(cli,
                              "test -r %s && echo R || echo NR" % p)
                hits.append("%s (%s)" % (p, "readable" if "R" in reads
                                         else "exists/not-readable"))
        if hits:
            found.append((cat, hits))
    return found


def run(engine):
    t = engine.target
    host = t.scan_host()
    if not HAVE_PARAMIKO:
        engine.db.add_finding(Finding(
            t.display, "post.loot", "coverage", "info",
            "Post-compromise loot survey skipped",
            detail="paramiko not installed — install it to let post.loot "
                   "inspect SSH-enabled hosts read-only.",
            confidence="firm"))
        return
    box = _creds(engine)
    if not box:
        engine.db.add_event(t.display, "post.loot",
                            "no SSH credentials in state to survey with")
        return
    user, pw, _h = box[0]
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(host, port=22, username=user, password=pw, timeout=10,
                    allow_agent=False, look_for_keys=False)
    except Exception as e:
        engine.db.add_finding(Finding(
            t.display, "post.loot", "coverage", "low",
            "post.loot credentials did not open an SSH session",
            detail="user=%s err=%r" % (user, e),
            confidence="possible"))
        return
    try:
        whoami = _exec(cli, "id -un").strip() or user
        found = _survey(cli)
        if not found:
            engine.db.add_event(t.display, "post.loot",
                                "no high-value files under %s's homes" % user)
            return
        for cat, hits in found:
            sev = "high" if cat in ("ssh", "cloud-creds") else "medium"
            engine.db.add_finding(Finding(
                t.display, "post.loot", "secret-at-rest", sev,
                "%s present under %s's account (%d file(s))" %
                (NAMES.get(cat, cat), whoami, len(hits)),
                detail="Read-only survey found secret-bearing files on the "
                       "logged-in host; a compromised account would read "
                       "these directly.",
                evidence="\n".join(hits[:25]),
                remediation="Rotate keys/cloud tokens, purge plaintext "
                            "secrets, enable disk encryption + credential "
                            "guard.",
                confidence="firm"))
            engine.log.finding("[post.loot] %s: %s" %
                               (whoami, NAMES.get(cat)))

            engine.state.setdefault("loot", []).append(
                {"category": cat, "files": hits})
    finally:
        try:
            cli.close()
        except Exception:
            pass