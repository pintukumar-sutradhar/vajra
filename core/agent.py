"""VAJRA mission agent — the 'AI select' operator-agent loop.

Each iteration the local Qwen3 brain inspects the live scan state (open
ports, services, web targets, findings), chooses the single highest-value
next action from a CLOSED tool set, and the framework executes it through a
small safe adapter layer. The loop continues until the model says done, the
step budget is spent, or the wall-clock budget expires.

Safety posture:
  - Exploit / brute / intrusive module actions only fire when --aggressive
    is set, matching the rest of the framework.
  - Model text is never exec()'d / eval'd / piped to a shell. PoCs are saved
    as reviewable evidence and, when run, delivered only through the
    framework's own validated clients or the approved exploit modules.
  - Every step (rationale + action + outcome) is written to
    evidence/ai_mission_log.md."""
import json
import os
import re
import socket
import threading
import time

INTRUSIVE_MODULES = {
    "network.brute", "exploit.exploit",
    "exploit.default_creds", "exploit.spray", "ad.spray",
    "exploit.form_brute", "ad.privesc_ops", "ad.movement",
}
# exploit.verify (known_exploits) is read-only probing — deliberately NOT
# gated so the brain can triage CVEs even in a read-only engagement.
# Post-exploit / channel-creation modules are only meaningful once real
# credentials or an execution channel exist — never fire without evidence.
CHAIN_MODULES = {"ad.movement"}

try:
    from modules import get_modules as _gm
    _MODULE_INDEX = "\n".join(
        "  %s — %s%s" % (
            m["name"], (m.get("desc") or m.get("short") or "")[:100],
            " [intrusive]" if (m["name"] in INTRUSIVE_MODULES or
                               m.get("phase") == "exploit") else "")
        for m in _gm())
except Exception:
    _MODULE_INDEX = ""

TOOL_SCHEMA = (
    "Tools (pick EXACTLY ONE; respond with a single compact JSON object):\n"
    '  {"tool":"scan_more","args":{"ports":"8000-9000"}}    probe extra TCP ports\n'
    '  {"tool":"run_module","args":{"name":"web.crawl"}}     run any module id\n'
    '  {"tool":"web_fuzz","args":{"url":"...","wordlist":"dirs_common.txt"}}\n'
    '  {"tool":"craft_exploit","args":{"service":"http","note":"..."}}  build PoC\n'
    '  {"tool":"exploit","args":{"service":"smb|http|ftp|ad"}}   run exploit path\n'
    '  {"tool":"brute","args":{"service":"ftp"}}            credential brute force\n'
    '  {"tool":"ad_chain","args":{}}              run AD movement+privesc verbs\n'
    '  {"tool":"assess","args":{}}                          summarize current state\n'
    '  {"tool":"done","args":{}}                            stop the mission\n'
    'Reply format: {"thought":"<1 sentence>",'
    '"tool":"<name>","args":{...},"why":"<reason>"}'
)

if _MODULE_INDEX:
    TOOL_SCHEMA += ("\nModules callable via run_module (id — purpose):\n"
                    + _MODULE_INDEX)


def parse_action(text):
    """Robustly turn model text into {"tool":..,"args":{..},"why":..}."""
    if not text or not str(text).strip():
        return {"tool": "done", "args": {}, "thought": "", "why": ""}
    raw = str(text)
    start, end = raw.find("{"), raw.rfind("}")
    if start != -1 and end > start:
        try:
            data = json.loads(raw[start:end + 1])
        except Exception:
            data = None
        if isinstance(data, dict) and data.get("tool"):
            args = data.get("args")
            if isinstance(args, str):
                args = {"ports": args}
            if not isinstance(args, dict):
                args = {}
            return {"tool": str(data["tool"]).strip().lower(),
                    "args": args,
                    "thought": str(data.get("thought", ""))[:200],
                    "why": str(data.get("why", ""))[:200]}
    low = raw.lower()
    for kw, tool, mod in (
            ("run_module", "run_module", None), ("module", "run_module", None),
            # specific web vuln keywords first so "xxe on the xml api" ->
            # web.vulnscan, not "api"
            ("xxe", "run_module", "web.vulnscan"),
            ("sql injection", "run_module", "web.vulnscan"),
            ("sqli", "run_module", "web.vulnscan"),
            ("ssti", "run_module", "web.vulnscan"),
            ("xss", "run_module", "web.vulnscan"),
            ("inject", "run_module", "web.vulnscan"),
            ("redirect", "run_module", "web.vulnscan"),
            ("graphql", "run_module", "web.graphql_probe"),
            ("openapi", "run_module", "web.api"),
            ("swagger", "run_module", "web.api"),
            ("bucket", "run_module", "web.cloud"),
            ("ssrf", "run_module", "web.ssrf_scan"),
            ("jwt", "run_module", "web.jwt_audit"),
            ("idor", "run_module", "web.api"), ("iqor", "run_module", "web.api"),
            ("csrf", "run_module", "web.api"),
            ("takeover", "run_module", "web.takeover"),
            ("ratelimit", "run_module", "web.policy"),
            ("rate limit", "run_module", "web.policy"),
            ("lockout", "run_module", "web.policy"),
            ("websocket", "run_module", "web.wiretests"),
            ("smuggl", "run_module", "web.wiretests"),
            ("deserial", "run_module", "web.wiretests"),
            ("kerberoast", "run_module", "ad.kerberos"),
            ("asrep", "run_module", "ad.kerberos"),
            ("upload", "run_module", "web.upload"),
            ("file upload", "run_module", "web.upload"),
            ("cve", "run_module", "web.tech"),
            ("cms", "run_module", "web.tech"),
            ("secret", "run_module", "web.js"),
            ("scan port", "scan_more", None),
            ("scan_more", "scan_more", None),
            ("port scan", "scan_more", None),
            ("extra port", "scan_more", None),
            ("dirbuster", "web_fuzz", None), ("fuzz", "web_fuzz", None),
            ("directory", "web_fuzz", None),
            ("craft", "craft_exploit", None), ("poc", "craft_exploit", None),
            ("make exploit", "craft_exploit", None),
            ("brute", "brute", None), ("password", "brute", None),
            ("ad_chain", "ad_chain", None), ("movement", "ad_chain", None),
            ("lateral", "ad_chain", None), ("dcsync", "ad_chain", None),
            ("gpp", "ad_chain", None), ("privesc", "ad_chain", None),
            ("exploit", "exploit", None), ("attack", "exploit", None),
            # generic labels last so they don't shadow specific ones
            ("dir", "web_fuzz", None), ("path", "web_fuzz", None),
            ("api", "run_module", "web.api"),
            ("cloud", "run_module", "web.cloud"),
            ("token", "run_module", "web.jwt_audit"),
            ("header", "run_module", "web.headers"),
            ("tls", "run_module", "web.tls"), ("https", "run_module", "web.tls"),
            ("tech", "run_module", "web.tech"),
            ("javascript", "run_module", "web.js"),
            ("waf", "run_module", "web.waf"),
            ("sitemap", "run_module", "web.crawl"),
            ("robot", "run_module", "web.crawl"),
            ("crawl", "run_module", "web.crawl"),
            ("recon web", "run_module", "web.api"),
            ("assess", "assess", None), ("summar", "assess", None),
            ("report", "assess", None),
            ("nmap", "scan_more", None),
            ("open ports", "scan_more", None),
            # bare "port" last: only reached when nothing more specific matched
            # ("report"/"support"/"important" all resolve before it)
            ("port", "scan_more", None)):
        if kw in low:
            if tool == "run_module" and mod:
                return {"tool": "run_module", "args": {"name": mod},
                        "thought": "", "why": ""}
            return {"tool": tool, "args": {}, "thought": "", "why": ""}
    return {"tool": "done", "args": {}, "thought": "", "why": ""}


def expand_ports(spec):
    ports = []
    for part in str(spec or "").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = int(part.split("-")[0]), int(part.split("-")[1])
                ports.extend(range(a, min(b, 65535) + 1))
            except Exception:
                pass
        else:
            try:
                ports.append(int(part))
            except Exception:
                pass
    uniq = []
    for p in ports:
        if 0 < p <= 65535 and p not in uniq:
            uniq.append(p)
    return uniq[:2000]


class MissionAgent:
    def __init__(self, engine):
        self.engine = engine
        self.log = engine.log
        self.ai = engine.ai
        self.steps = []
        self.budget = float(engine.cfg("ai_mission_budget", 240))
        self.max_steps = int(engine.cfg("ai_mission_steps", 8))

    # ---------- state ----------

    def snapshot(self):
        st = self.engine.state
        t = self.engine.target
        lines = ["target=%s | profile=%s" % (t.display, self.engine.profile)]
        ports = st.get("open_ports", {})
        keys = sorted(ports.keys()) if isinstance(ports, dict) else ports
        lines.append("open_ports=%s" % ("none" if not keys else
                                        ",".join(map(str, keys[:60]))))
        svcs = st.get("services", []) or []
        if svcs:
            sline = "; ".join(
                "%s:%d %s%s" % (s.get("host", t.display), s["port"],
                                s.get("service", "?"),
                                (" " + (s.get("banner") or "")[:50])
                                if s.get("banner") else "")
                for s in svcs[:25])
            lines.append("services: " + sline)
        webs = st.get("web_targets", []) or []
        if webs:
            lines.append("web: %s" % "; ".join(w["url"] for w in webs[:10]))
        api = st.get("api") or {}
        if api.get("endpoints"):
            lines.append("api_endpoints=%d (JSON fuzz via web.vulnscan; "
                         "auth sweep via web.api)" % len(api["endpoints"]))
        if st.get("authenticated"):
            lines.append("web_auth=established (session cookies active)")
        if st.get("waf"):
            lines.append("waf=%s" % st["waf"])
        findings = []
        try:
            findings = self.engine.db.findings(t.display) \
                if self.engine.db else []
        except Exception:
            pass
        if findings:
            hot = []
            for f in findings[-18:]:
                if f.get("severity") in ("critical", "high"):
                    hot.append("[%s] %s" % (f["severity"], f["title"][:110]))
            if hot:
                lines.append("hot findings:\n" + "\n".join(hot))
            else:
                lines.append("findings so far: %d (none critical/high)"
                             % len(findings))
        exploit_ok = bool(getattr(self.engine.args, "aggressive", False))
        lines.append("exploitation=%s"
                     % ("ARMED (--aggressive)" if exploit_ok else
                        "read-only (--aggressive enables it)"))
        ad = st.get("ad") or {}
        if ad:
            lines.append("ad: realm=%s dcs=%s ports=%s" % (
                ad.get("realm", "?"),
                ",".join(d.get("host", "?") for d in ad.get("dcs", [])[:3])
                or "srvdns", ",".join(map(str, ad.get("ad_ports", []))) or "-"))
        creds = getattr(self.engine, "ad_creds", {}) or {}
        if creds.get("user"):
            lines.append("ad_creds: %s%s%s" % (
                creds["user"],
                " (PTH)" if creds.get("nthash") else "",
                " VALID" if getattr(self.engine, "ad_valid", False) else
                " NOT-YET-VERIFIED"))
        box = st.get("creds") or []
        chans = st.get("channels") or []
        lines.append("creds=%d channels=%d%s"
                     % (len(box), len(chans),
                        " BEACON" if st.get("sessions") else ""))
        lines.append("step=%d/%d"
                     % (len(self.steps) + 1, self.max_steps))
        return "\n".join(lines)

    # ---------- main loop ----------

    def run(self):
        self._deadline = time.time() + self.budget
        self.log.info("[ai-mission] operator-agent engaged (model %s)"
                      % self.ai.model)
        for step in range(1, self.max_steps + 1):
            if time.time() > self._deadline:
                self.log.warn("[ai-mission] time budget exhausted")
                self.report("time budget exhausted")
                return
            self.log.info("[ai-mission] step %d/%d — inspecting state"
                          % (step, self.max_steps))
            snap = self.snapshot()
            prompt = (TOOL_SCHEMA + "\n\nCurrent state:\n" + snap +
                      "\n\nNext action JSON:")
            text = self.ai.ask(prompt, system=(
                "You are VAJRA's red-team mission planner. Inspect the state, "
                "pick the single most impactful next action, be concrete."))
            act = parse_action(text)
            tool = act.get("tool", "done")
            self.log.finding("[ai-mission] step %d -> %s %s"
                             % (step, tool, act.get("args") or ""))
            if tool == "done" or not tool:
                self.report("planner said done: %s"
                            % (act.get("why") or act.get("thought") or
                               "no action"))
                return
            try:
                outcome = self.execute(tool, act.get("args", {}))
            except Exception as e:
                outcome = "error: %r" % e
                self.log.error("[ai-mission] %s failed: %r" % (tool, e))
            self.steps.append({"step": step, "tool": tool,
                               "args": act.get("args", {}),
                               "why": act.get("why", ""),
                               "outcome": str(outcome)[:500]})
            self.log.info("[ai-mission] -> %s" % str(outcome)[:220])
        self.report("step budget reached")

    def report(self, reason):
        lines = ["# VAJRA AI mission log",
                 "", "target: %s" % self.engine.target.display,
                 "profile: %s" % self.engine.profile,
                 "model: %s" % self.ai.model,
                 "termination: %s" % reason, ""]
        if not self.steps:
            lines.append("(no agent actions executed)")
        for s in self.steps:
            lines.append("## step %d: %s" % (s["step"], s["tool"]))
            if s.get("why"):
                lines.append("- rationale: " + s["why"])
            if s.get("args"):
                lines.append("- args: %s" % json.dumps(s["args"]))
            lines.append("- outcome: " + s["outcome"])
        try:
            rel = self.engine.save_evidence("ai_mission_log.md",
                                            "\n".join(lines))
            self.log.success("[ai-mission] log -> %s" % rel)
        except Exception as e:
            self.log.error("[ai-mission] could not write log: %r" % e)

    # ---------- tools ----------

    def execute(self, tool, args):
        e = self.engine
        t = e.target
        host = t.scan_host()
        if tool == "scan_more":
            return self._scan_ports(host, args.get("ports", "8000-9000"))
        if tool == "run_module":
            return self._run_module(args.get("name", ""))
        if tool == "web_fuzz":
            return self._web_fuzz(args)
        if tool == "craft_exploit":
            return self._craft_exploit(host, args)
        if tool == "exploit":
            return self._exploit(host, args.get("service", ""))
        if tool == "brute":
            return self._brute(args.get("service", "ftp"))
        if tool == "ad_chain":
            return self._ad_chain()
        if tool == "assess":
            return self._assess()
        return "unknown tool %r" % tool

    def _find(self, name):
        from modules import get_modules, find
        if not name:
            return None
        m = find(name) if "." in name else None
        if m:
            return m
        short = name.lower()
        for mod in get_modules():
            if mod["name"] == name or mod["name"].endswith("." + name) \
                    or short in mod["name"]:
                return mod
        return None

    def _run_module(self, name):
        m = self._find(name)
        if m is None:
            return "unknown module %r" % name
        intrusive = (m["name"] in INTRUSIVE_MODULES or
                     m["phase"] == "exploit")
        if intrusive and not getattr(self.engine.args, "aggressive", False):
            return ("refused: %s is intrusive — requires --aggressive"
                    % m["name"])
        self.engine._exec(m)
        return "ran %s" % m["name"]

    def _scan_ports(self, host, spec):
        ports = expand_ports(spec)
        if not ports:
            return "empty port spec %r" % spec
        found = []
        lock = threading.Lock()
        threads = []

        def probe(p):
            s = socket.socket()
            s.settimeout(0.7)
            try:
                if s.connect_ex((host, p)) == 0:
                    with lock:
                        found.append(p)
            finally:
                s.close()

        for p in ports:
            th = threading.Thread(target=probe, args=(p,), daemon=True)
            th.start()
            threads.append(th)
            if len(threads) >= 400:
                for th in threads:
                    th.join()
                threads = []
        for th in threads:
            th.join()
        found.sort()
        if not found:
            return "no new open ports in %s" % spec
        op = self.engine.state.setdefault("open_ports", {})
        for p in found:
            if p not in op:
                op[p] = 0.0
        self._run_module("service_detect")
        return "found %d new open port(s): %s" % (len(found),
                                                  ",".join(map(str, found)))

    def _web_fuzz(self, args):
        m = self._find("web.dirbuster")
        if m is None:
            return "dirbuster module missing"
        webs = self.engine.state.get("web_targets", []) or []
        url = args.get("url") or (webs[0]["url"] if webs else "")
        if not url:
            return "no web target to fuzz"
        pri = webs
        self.engine.state["web_targets"] = [{"url": url, "primary": True}]
        try:
            res = self.engine._exec(m)
            return "fuzzed %s%s" % (
                url, "" if m.get("name") != "web.dirbuster" else
                "; sensitive paths (.git/.env/backups) probed")
        finally:
            self.engine.state["web_targets"] = pri

    def _craft_exploit(self, host, args):
        svc = (args.get("service") or "http").lower()
        note = (args.get("note") or "").strip()
        prompt = (
            "Target address: %s\nService: %s\nOperator note: %s\n"
            "Write a short non-destructive proof-of-concept (max 50 lines) in "
            "Python using ONLY socket/struct/urllib.request that confirms the "
            "suspected weakness. Use a unique marker string 'VJRPROBE'. "
            "Reply with the code only, no fences." % (host, svc, note))
        code = self.ai.ask(prompt, system=(
            "You are a PoC author for an authorized penetration test. Output "
            "code only. No metasploit, no persistence, proof-of-concept "
            "quality."), max_tokens=900)
        if not code.strip():
            return "model returned no PoC"
        bad = ("os.system", "subprocess.", "eval(", "exec(", "pty.",
               "bash -i", "nc -e", "sh -i")
        flagged = [b for b in bad if b in code]
        rel = self.engine.save_evidence(
            "ai_poc_%s.py" % svc,
            "# AI-crafted PoC — review before use\n# target %s\n%s\n"
            % (host, code))
        if flagged:
            return ("PoC saved read-only %s (flagged keywords %s — review "
                    "before executing)" % (rel, flagged))
        self.engine.log.info("[ai-mission] PoC for %s saved (%s)" % (svc, rel))
        if svc in ("http", "https", "web") and \
                getattr(self.engine.args, "aggressive", False):
            return self._run_module("exploit.exploit") + "; PoC: " + rel
        return "PoC evidence saved: " + rel

    def _exploit(self, host, service):
        e = self.engine
        svc = (service or "").lower()
        findings = []
        try:
            findings = e.db.findings(e.target.display) if e.db else []
        except Exception:
            pass
        ms17 = any("MS17" in (f.get("title") or "") or
                   "ETERNALBLUE" in (f.get("title") or "").upper()
                   for f in findings)
        if not getattr(e.args, "aggressive", False):
            plan = self._exploit_plan(svc, ms17, findings)
            rel = self.engine.save_evidence("ai_exploit_plan.txt", plan)
            return ("read-only plan saved: %s (run --aggressive to execute)"
                    % rel)
        if svc in ("smb", "smbv1", "445", "ms17-010", "eternalblue") or \
                (svc == "" and ms17):
            return self._ms17_run() if ms17 else \
                "MS17-010 not verified on this host"
        if svc in ("http", "https", "web", "sqli", "rce"):
            return self._run_module("exploit.exploit")
        if svc in ("ftp", "ssh", "http-admin", "form", "telnet"):
            return self._run_module("network.brute")
        if svc in ("ad", "ldap", "kerberos", "domain", "smb", "samba",
                   "winrm"):
            out = []
            for n in ("ad.smb_recon", "ad.kerberos", "ad.ldap_enum"):
                out.append(self._run_module(n))
            chain = self._ad_chain(require_creds=False)
            out.append(chain)
            return "; ".join(out)
        return "no exploit path for %r" % svc

    def _exploit_plan(self, svc, ms17, findings):
        lines = ["# VAJRA exploit plan (read-only)",
                 "target: %s" % self.engine.target.display,
                 "service: %s" % svc,
                 "ms17-010 verified: %s" % ms17, ""]
        hot = [f for f in findings
               if f.get("severity") in ("critical", "high")][:10]
        for f in hot:
            lines.append("- [%s] %s" % (f["severity"], f["title"]))
        lines.append("")
        if ms17:
            lines.append("next: run evidence/ms17_010_resource.rc (already "
                         "written by ad.smb_recon) with msfconsole --aggressive")
        elif svc in ("http", "https", "web"):
            lines.append("next: --aggressive exploit.exploit (SQLi/RCE/"
                         "auth-bypass proving)")
        elif svc in ("ftp", "ssh"):
            lines.append("next: --aggressive network.brute on %s" % svc)
        else:
            lines.append("next: deepen recon, then re-plan.")
        return "\n".join(lines)

    def _ms17_run(self):
        import shutil
        import subprocess
        if not shutil.which("msfconsole"):
            return "metasploit not installed on operator host"
        from modules.ad.smb_recon import _msf_resource
        rc = _msf_resource(self.engine.target.scan_host())
        rel = self.engine.save_evidence("ms17_010_resource.rc", rc)
        path = os.path.join(self.engine.outroot, rel)
        self.log.warn("[ai-mission] firing MS17-010 via msfconsole "
                      "(AGGRESSIVE, explicit operator intent)")
        try:
            r = subprocess.run(["msfconsole", "-q", "-r", path],
                               capture_output=True, text=True, timeout=180)
            out = r.stdout[-1600:]
            self.engine.save_evidence("ai_msf_run.txt",
                                      "rc exit=%s\n%s\n"
                                      % (r.returncode, out))
            got = bool(self.engine.state.get("sessions"))
            return "msf finished rc=%s%s" % (r.returncode,
                                             " — session captured" if got
                                             else "")
        except Exception as e:
            return "msf run error: %r" % e

    def _brute(self, service):
        if not getattr(self.engine.args, "aggressive", False):
            return "brute requires --aggressive"
        return self._run_module("network.brute")

    def _ad_chain(self, require_creds=True):
        """Active AD chain: movement (psexec/wmiexec lateral channel) then
        privesc/dump ops (GPP, ZeroLogon probe, DC-Sync, bounded hashcat
        crack of roasted/dumped hashes). Both are intrusive — gated."""
        if not getattr(self.engine.args, "aggressive", False):
            return ("ad_chain requires --aggressive (movement + DC-Sync are "
                    "intrusive)")
        creds = getattr(self.engine, "ad_creds", {}) or {}
        if creds.get("user") and not getattr(self.engine, "ad_valid", True):
            return "supplied AD credentials are not valid on the domain"
        if require_creds and not creds.get("user"):
            return "ad_chain needs --ad-user/--ad-pass (or --nthash)"
        if not self.engine.state.get("ad"):
            return "no Active Directory indicators on this target"
        outs = []
        for name in ("ad.movement", "ad.privesc_ops"):
            m = self._find(name)
            if m is None:
                outs.append("%s missing" % name)
                continue
            self.engine._exec(m)
            outs.append("ran " + m["name"])
        return "; ".join(outs)

    def _assess(self):
        from core.intelligence import Intelligence
        e = self.engine
        t = e.target
        try:
            stats = e.db.stats(t.display) if e.db else {}
            findings = e.db.findings(t.display) if e.db else []
            services = e.db.services(t.display) if e.db else []
        except Exception:
            stats, findings, services = {}, [], []
        note = Intelligence().summarize(
            stats, findings, services, [{"display": t.display}])
        rel = self.engine.save_evidence(
            "ai_assessment.md",
            "# VAJRA AI assessment — %s\n\n%s\n" % (t.display, note))
        return "assessment saved: %s" % rel