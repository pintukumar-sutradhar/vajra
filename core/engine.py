"""VAJRA orchestration engine — phases, conditions, dispatch, per-target
Outputs bundles and AI-assisted planning."""
import os
import shutil
import time
import traceback
import importlib
import datetime
import sys

from core.database import Database, Finding, SEV_ORDER
from core.intelligence import Intelligence
from core.ai import AIEngine
from core.report import (build_data, render_html, render_json,
                         render_markdown, render_pdf)
from core.utils import PROJECT_ROOT
from modules import get_modules


def sanitize_target_name(display):
    import re as _re
    name = display.replace("://", "_").replace("/", "_")
    name = _re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:80].strip("_") or "target"


PROFILES = {
    "quick": {"ports": "top100", "crawl_max_pages": 25, "crawl_max_depth": 3,
              "dir_threads": 20, "max_injection_points": 40,
              "max_payloads_direct": 60, "max_mutants": 10},
    "full": {"ports": "all", "crawl_max_pages": 150, "crawl_max_depth": 5,
             "dir_threads": 40, "max_injection_points": 120,
             "time_based_sqli": True,
             "max_payloads_direct": 160, "max_mutants": 28},
    "vast": {"ports": "all", "crawl_max_pages": 400, "crawl_max_depth": 6,
             "dir_threads": 64, "max_injection_points": 300,
             "time_based_sqli": True, "max_payloads_direct": 320,
             "max_mutants": 48, "scan_concurrency": 900},
    "stealth": {"ports": "top100", "scan_concurrency": 50, "dir_threads": 6,
                "crawl_max_pages": 30, "max_injection_points": 30,
                "delay": 0.4, "brute_delay": 0.6, "rotate_ua": True},
    "webonly": {"ports": None, "crawl_max_pages": 200, "crawl_max_depth": 5,
                "dir_threads": 25, "max_injection_points": 80},
    "recon": {"ports": "top100"},
}

try:
    import json as _json
    _prof_file = PROJECT_ROOT / "config" / "profiles.json"
    if _prof_file.exists():
        _prof_raw = _json.loads(_prof_file.read_text(encoding="utf-8"))
        for _pname, _pvals in (_prof_raw.get("profiles") or {}).items():
            PROFILES.setdefault(_pname, {}).update(_pvals)
except Exception:
    pass


class Engine:
    def __init__(self, args, config):
        self.args = args
        self.profile = args.profile
        self.config = config or {}
        self.pconf = dict(PROFILES.get(self.profile, {}))
        self.outroot = self._make_outroot(args.output)
        self.log = LoggerProxy(args.verbose, color=not args.no_color)
        self.db = None
        self.dbs = []
        self.target_dirs = {}
        self.reported = set()
        ai_on = bool(getattr(args, "ai", False)) or \
            bool(self.config.get("ai_enabled", False))
        self.ai = AIEngine(self.config, enabled=ai_on, log=self.log)
        self.ai_select = bool(getattr(args, "ai_select", False)) or \
            bool(self.config.get("ai_select", False))
        self.intel = Intelligence()
        base_timeout = float(self.cfg("http_timeout", 7))
        from core.http_client import HttpClient
        self.socks = getattr(args, "socks5", None) or None
        self.http = HttpClient(timeout=base_timeout,
                               user_agent=args.user_agent or None,
                               proxy=args.proxy or None,
                               socks=self.socks,
                               follow=True)
        self.threads = args.threads or int(self.cfg("threads", 40))
        self.tooling = {}
        try:
            raw = _json.loads((PROJECT_ROOT / "config" / "tooling.json")
                              .read_text(encoding="utf-8"))
            for cat, spec in (raw.get("categories") or {}).items():
                for t in spec.get("tools", []):
                    self.tooling[t] = cat
        except Exception:
            pass

        self.online = bool(self.cfg("external_intel", True)) and \
            not getattr(args, "no_external_intel", False)
        if not self.online:
            self.log.info("third-party intel lookups disabled")
        self.cve_update = bool(getattr(args, "cve_update", False))
        self.targets = []
        self.state = {}
        self.target = None
        self.evasion_all = []
        self.sessions_all = []
        self._lhost = getattr(args, "lhost", None)
        if self._lhost in ("auto", "", None):
            self._lhost = None
        self._lport = getattr(args, "lport", None)
        self._wl_cache = {}
        self.ad_creds = {
            "user": getattr(args, "ad_user", None) or "",
            "password": getattr(args, "ad_pass", None) or "",
            "nthash": getattr(args, "nthash", None) or "",
        }
        if self.ad_creds["user"]:
            self.log.info("[ad] credentials supplied for %s%s" %
                          (self.ad_creds["user"],
                           " (PTH)" if self.ad_creds["nthash"] else ""))
        self.web_creds = {
            "user": getattr(args, "web_user", None) or "",
            "password": getattr(args, "web_pass", None) or "",
            "otp": getattr(args, "web_otp", None) or "",
            "totp": getattr(args, "web_totp_secret", None) or "",
            "login": getattr(args, "web_login", None) or "",
        }
        if self.web_creds["user"]:
            self.log.info("[web] authenticated-scan credentials for %s%s"
                          % (self.web_creds["user"],
                             " (+OTP)" if (self.web_creds["otp"] or
                                           self.web_creds["totp"]) else ""))
        self.start_time = time.time()
        self._warned_conds = set()
        self.oob = None
        if getattr(args, "oob", False) or self.profile in ("full", "vast") \
                or bool(self.cfg("oob_enabled", False)):
            try:
                from core.oob import OobListener
                self.oob = OobListener(port=int(self.cfg("oob_port", 0)))
                self.oob.start()
                self.log.info("[oob] blind-callback listener up on %s:%d%s"
                              % (self.oob.host(), self.oob.port,
                                 "" if getattr(args, "aggressive", False)
                                 else " (read-only detections)"))
            except Exception as e:
                self.log.warn("[oob] listener failed: %r" % e)
        if self.ai.enabled:
            self.log.info("[ai] brain enabled — Ollama + %s provisioning "
                          "in background" % self.ai.model)
            self.ai.warm_start()
        else:
            self.log.debug("[ai] disabled (--ai to enable)")

    def _make_outroot(self, base):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        root = os.path.join(base or "Outputs", "vajra_%s" % ts)
        os.makedirs(root, exist_ok=True)
        return os.path.abspath(root)

    def cfg(self, key, default=None):
        if hasattr(self.args, key) and getattr(self.args, key) is not None \
                and key in ("threads", "timeout", "delay"):
            return getattr(self.args, key)
        if key in self.pconf:
            return self.pconf[key]
        return self.config.get(key, default)

    def profile_cfg(self, key, default=None):
        return self.pconf.get(key, default)

    def wordlist_path(self, name):
        d = getattr(self.args, "wordlists_dir", None) or \
            str(PROJECT_ROOT / "wordlists")
        return os.path.join(d, name)

    @property
    def deep(self):
        return self.profile in ("full", "vast") or \
            getattr(self.args, "aggressive", False)

    def _wl(self, name):
        if name not in self._wl_cache:
            try:
                with open(self.wordlist_path(name), encoding="utf-8") as f:
                    self._wl_cache[name] = [ln.strip() for ln in f
                                            if ln.strip()]
            except Exception:
                self._wl_cache[name] = []
        return self._wl_cache[name]

    def users(self):
        return self._wl("users_full.txt") if self.deep else self._wl("users.txt")

    def passwords(self):
        return self._wl("passwords_full.txt") if self.deep \
            else self._wl("passwords.txt")

    def dirs_words(self):
        return self._wl("dirs_full.txt") if self.deep \
            else self._wl("dirs_common.txt")

    def subs_words(self):
        return self._wl("subs_full.txt") if self.deep \
            else self._wl("subs_common.txt")

    def save_evidence(self, filename, content):
        """Persist raw proof material under the current target's bundle."""
        ev_dir = self.state.get("evidence_dir")
        if not ev_dir:
            return ""
        os.makedirs(ev_dir, exist_ok=True)
        path = os.path.join(ev_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content[:2000000])
        rel = os.path.relpath(path, self.outroot)
        self.log.success("[evidence] saved -> %s" % rel)
        return rel

    def _collect_evasion(self, attacker):
        try:
            entries = attacker.evasion_log
        except AttributeError:
            return
        for e in entries[-40:]:
            if len(self.evasion_all) < 400:
                self.evasion_all.append(e)
                self.state.setdefault("evasion_log", []).append(e)

    def nonce(self, n=8):
        import random, string
        return "".join(random.choices(string.ascii_lowercase + string.digits,
                                      k=n))

    def rand_path(self, n=8):
        import random, string
        return "".join(random.choices(string.ascii_lowercase, k=n))

    # ---------- callback parameter resolution ----------

    def resolve_callback(self, interactive=False):
        """Return (lhost, lport); prompts the operator when interactive and
        values were not supplied on the command line."""
        if self._lhost and self._lport:
            return self._lhost, self._lport
        from core.listener import detect_lhost, pick_lport
        sug_h = self.args.lhost if getattr(self.args, "lhost", None) not in \
            (None, "auto", "") else detect_lhost()
        sug_p = self.args.lport or pick_lport()
        if interactive and sys.stdin.isatty():
            print("\n╔══════════════════════════════════════════════╗")
            print("║  CALLBACK ENDPOINT REQUIRED FOR NEXT STAGE   ║")
            print("╚══════════════════════════════════════════════╝")
            try:
                h = input("  LHOST [%s]: " % sug_h).strip()
                p = input("  LPORT [%d]: " % sug_p).strip()
            except (EOFError, KeyboardInterrupt):
                h, p = "", ""
            self._lhost = h or sug_h
            try:
                self._lport = int(p) if p else sug_p
            except ValueError:
                self._lport = sug_p
        else:
            self._lhost = sug_h
            self._lport = sug_p
        self.log.info("callback endpoint: %s:%s" % (self._lhost, self._lport))
        return self._lhost, self._lport

    @property
    def lhost(self):
        if self._lhost is None:
            from core.listener import detect_lhost
            self._lhost = detect_lhost()
        return self._lhost

    @property
    def lport(self):
        if self._lport is None:
            from core.listener import pick_lport
            self._lport = pick_lport()
        return self._lport

    def _on_session(self, sess):
        self.state.setdefault("sessions", []).append(sess)
        self.sessions_all.append(sess)
        self.db.add_finding({
            "target": self.target.display, "module": "exploit.exploit",
            "category": "exploit-proof", "severity": "critical",
            "title": "REVERSE SESSION ESTABLISHED from %s:%s" %
                     (sess.addr[0], sess.addr[1]),
            "detail": "Target connected back to our handler at %s:%s. "
                      "Interactive command execution is now available."
                      % (self.lhost, self.lport),
            "evidence": "callback received at %s" % time.strftime("%H:%M:%S"),
            "remediation": "Host compromise assumed — forensics + rebuild.",
            "confidence": "firm"})
        self.log.finding("[session] callback from %s:%d" %
                         (sess.addr[0], sess.addr[1]))

    # ---------- main flow ----------

    def run(self):
        raw_target = self.args.target
        if not raw_target:
            raise SystemExit("[!] --target/-t is required (see --help)")
        from core.target import expand_targets
        self.targets = expand_targets(raw_target)
        self.log.phase("=" * 62)
        self.log.phase(" VAJRA — profile=%s — %d target(s)%s" %
                       (self.profile, len(self.targets),
                        " [AGGRESSIVE]" if getattr(
                            self.args, "aggressive", False) else ""))
        self.log.phase("=" * 62)
        self.workspace = None
        ws_name = getattr(self.args, "workspace", None) or \
            (sanitize_target_name(self.targets[0].display)
             if len(self.targets) == 1 else self.profile)
        if ws_name:
            from core.workspace import Workspace
            self.workspace = Workspace(ws_name)
            self.log.info("[workspace] '%s' open at %s" %
                          (ws_name,
                           os.path.relpath(self.workspace.dir,
                                           PROJECT_ROOT)))
        try:
            for t in self.targets:
                self.run_target(t)
                try:
                    self.generate_target_reports(t)
                except Exception as e:
                    self.log.error("reporting failed for %s: %r" %
                                   (t.display, e))
        finally:
            for t in self.targets:
                if t not in self.reported:
                    try:
                        self.generate_target_reports(t)
                    except Exception:
                        pass
            self.write_run_summary()
            self._workspace_finish()

    def run_target(self, t):
        self.target = t
        tname = sanitize_target_name(t.display)
        tdir = os.path.join(self.outroot, tname)
        os.makedirs(tdir, exist_ok=True)
        evdir = os.path.join(tdir, "evidence")
        os.makedirs(evdir, exist_ok=True)
        self.target_dirs[t.display] = tdir
        if self.db is not None:
            self.dbs.append(self.db)
        self.db = Database(os.path.join(tdir, "data.sqlite"))
        self.log.set_file(os.path.join(tdir, "vajra.log"))
        self.state = {"services": [], "open_ports": {}, "pages": [],
                      "forms": [], "emails": [], "js": [], "web_targets": [],
                      "tech": [], "outdir": tdir, "evidence_dir": evdir}
        banner_name = "URL %s" % t.display if t.kind == "url" else \
            "HOST %s" % t.display
        self.db.add_event(t.display, "scan-start", "profile=%s" % self.profile)
        self.log.phase("-" * 62)
        self.log.phase("[%s]" % banner_name)
        if t.kind == "host":
            ips = t.resolve()
            if not ips:
                self.log.warn("could not resolve %s - continuing with literal"
                              % t.hostname)
            else:
                self.log.info("resolved: %s" % ", ".join(ips[:5]))
        enabled_names = None
        if self.args.modules:
            enabled_names = [x.strip() for x in self.args.modules.split(",")]
        disabled = {x.strip() for x in
                    (self.args.exclude_modules or "").split(",") if x.strip()}
        if self.args.no_brute:
            disabled.add("network.brute")
        recon_only = self.profile == "recon"
        for phase in ("recon", "net", "web", "exploit", "ad", "post"):
            if recon_only and phase not in ("recon",):
                continue
            if phase == "web":
                self._plan_web()
            if phase == "exploit":
                self._plan_exploit()
            self.log.phase(">>> PHASE: %s" % phase.upper())
            for m in get_modules():
                if m["phase"] != phase:
                    continue
                name = m["name"]
                if enabled_names and not any(
                        name == n or n.split(".")[-1] == name.split(".")[-1]
                        for n in enabled_names):
                    continue
                if name in disabled:
                    continue
                if self.profile in m["profile_skip"]:
                    continue
                if not self._cond_ok(m["cond"]):
                    continue
                self._exec(m)
        if self.ai_select:
            self.run_mission()
        self._workspace_target(t)
        self.db.add_event(t.display, "scan-end", "")
        self.dbs.append(self.db)

    def _workspace_target(self, t):
        ws = getattr(self, "workspace", None)
        if not ws:
            return
        findings = self.db.findings(t.display)
        delta = ws.delta_for(t.display, findings)
        ws.save_state(t.display, self.state)
        try:
            from core.synthesis import build_brain_blocks
            block = build_brain_blocks(
                {t.display: {"findings": findings}},
                delta_summary={"new": len(delta["new"]),
                               "fixed": len(delta["fixed"]),
                               "still": len(delta["still_open"])},
                spread=None)
            ws.append_narrative(block)
        except Exception as e:
            self.log.debug("brain block failed: %r" % e)
        self.state["delta"] = {
            "new": [f["title"] for f in delta["new"]],
            "fixed": [f["title"] for f in delta["fixed"]],
            "still_open": [f["title"] for f in delta["still_open"]],
            "previous": delta["previous"]}
        if delta["new"] or delta["fixed"]:
            self.log.info("[workspace] retest delta vs %s: +%d new, ~%d "
                          "fixed, %d still open (target %s)"
                          % (delta["previous"], len(delta["new"]),
                             len(delta["fixed"]),
                             len(delta["still_open"]), t.display))

    def _workspace_finish(self):
        ws = getattr(self, "workspace", None)
        if not ws:
            return
        per_target = {}
        for disp, _tdir in self.target_dirs.items():
            db = self._db_for(disp)
            if db is None:
                continue
            findings = db.findings(disp)
            per_target[disp] = {"findings": findings,
                                "services": db.services(disp),
                                "score": Intelligence().score(findings)}
        if not per_target:
            return
        ws.snapshot(per_target, profile=self.profile,
                    meta={"targets": list(per_target)})
        try:
            from core.synthesis import correlate_across, build_brain_blocks
            all_f = [dict(f, target=disp)
                     for disp, pt in per_target.items()
                     for f in pt.get("findings", [])]
            block = build_brain_blocks(
                per_target, delta_summary=None, spread=correlate_across(all_f))
            ws.append_narrative(block)
            self.log.info("[workspace] snapshot persisted (%d target(s)) -> "
                          "workspace_report.md" % len(per_target))
        except Exception as e:
            self.log.debug("workspace brain update failed: %r" % e)

    def run_mission(self):
        if not self.ai.enabled:
            self.log.info("[ai-mission] skipped — AI disabled (use --ai)")
            return
        if not self.ai.available():
            self.log.warn("[ai-mission] Qwen3 not reachable — mission "
                          "deferred (start ollama / pull qwen3:8b)")
            return
        from core.agent import MissionAgent
        self.log.phase(">>> AI-MISSION (operator-agent, Qwen3)")
        agent = MissionAgent(self)
        try:
            agent.run()
        except Exception as e:
            self.log.error("[ai-mission] aborted: %r" % e)
            self.log.debug(traceback.format_exc())

    def _exec(self, m):
        t0 = time.time()
        self.log.info("» module %-22s %s" % (m["name"], "(" + m["desc"] + ")"))
        self.db.add_event(self.target.display, "module-start", m["name"])
        try:
            mod = importlib.import_module(m["func"])
            mod.run(self)
            dur = time.time() - t0
            self.log.success("» module %-22s done (%.1fs)" % (m["name"], dur))
            self.db.add_event(self.target.display, "module-end",
                              "%s %.1fs" % (m["name"], dur))
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.log.error("module %s crashed: %r" % (m["name"], e))
            self.log.debug(traceback.format_exc())
            self.db.add_event(self.target.display, "module-error",
                              "%s: %r" % (m["name"], e))

    def _cond_ok(self, conds):
        st = self.state
        t = self.target
        for c in conds:
            if c == "always":
                ok = True
            elif c == "domain":
                ok = t.is_domain
            elif c == "ports_open":
                ok = bool(st.get("open_ports"))
            elif c.startswith("ports:"):
                want = {int(x) for x in c.split(":", 1)[1].split(",")}
                ok = bool(want & set(st.get("open_ports", {})))
            elif c.startswith("udp:"):
                want = {int(x) for x in c.split(":", 1)[1].split(",")}
                ok = bool(want & set(st.get("udp_open", [])))
            elif c == "has_web":
                ok = bool(st.get("web_targets"))
            elif c == "has_web_tls":
                ok = any(w["url"].lower().startswith("https")
                         for w in st.get("web_targets", [])) or \
                    any(s.get("tls") for s in st.get("services", []))
            elif c == "has_ad":
                ok = bool(st.get("ad") and (
                    st["ad"].get("dcs") or st["ad"].get("ad_ports")))
                continue
            elif c == "has_channels":
                ok = bool(st.get("channels"))
                continue
            elif c == "has_web_or_services":
                ok = bool(st.get("web_targets")) or bool(st.get("open_ports"))
            elif c == "has_forms":
                ok = any(p.get("forms") for p in st.get("pages", []))
            elif c == "has_subdomains":
                ok = bool(st.get("subdomains"))
            else:
                if c not in self._warned_conds:
                    self._warned_conds.add(c)
                ok = True
            if not ok:
                return False
        return True

    def _plan_web(self):
        web = self.intel_plan_targets()
        seen = set()
        uniq = []
        for w in web:
            if w["url"] not in seen:
                seen.add(w["url"])
                uniq.append(w)
        self.state["web_targets"] = uniq
        if uniq:
            self.log.info("web scope: %s" % ", ".join(w["url"] for w in uniq))

    def intel_plan_targets(self):
        return self.intel.plan_web_targets(self.target,
                                           self.state["services"])

    def _plan_exploit(self):
        try:
            findings = [f for f in self.db.findings(self.target.display)]
            actions = self.intel.next_actions(self.state, findings)
            if self.ai.available():
                summary = "\n".join(
                    "- %s [%s]" % (f["title"], f["severity"])
                    for f in findings[:12])
                services = "; ".join("%s:%s %s" % (s.get("host"), s["port"],
                                                   s["service"])
                                     for s in self.state.get("services", [])[:8])
                ai_acts = self.ai.plan_actions(
                    "services: %s\nfindings:\n%s" % (services, summary))
                actions.extend(a for a in ai_acts if a)
            if actions:
                self.log.info("intel campaign plan: %s" % "; ".join(actions))
        except Exception as e:
            self.log.debug("planner skipped: %r" % e)

    # ---------- reporting ----------

    def generate_target_reports(self, t):
        if t.display in self.reported:
            return
        tdir = self.target_dirs.get(t.display)
        db = self._db_for(t.display)
        if not tdir or db is None:
            return
        data = build_data_for(db, t, self)
        formats = (self.args.format or "all").lower()
        paths = []
        try:
            if formats in ("html", "all"):
                p = os.path.join(tdir, "report.html")
                open(p, "w", encoding="utf-8").write(render_html(data))
                paths.append(p)
            if formats in ("json", "all"):
                p = os.path.join(tdir, "report.json")
                open(p, "w", encoding="utf-8").write(render_json(data))
                paths.append(p)
            if formats in ("md", "markdown", "all"):
                p = os.path.join(tdir, "report.md")
                open(p, "w", encoding="utf-8").write(render_markdown(data))
                paths.append(p)
            if formats in ("pdf", "all"):
                p = os.path.join(tdir, "report.pdf")
                render_pdf(data, path=p)
                paths.append(p)
        except Exception as e:
            self.log.error("report generation failed: %r" % e)
        stats = data["stats"]
        total = sum(stats.values())
        grade = data["grade"]
        self.log.phase("-" * 62)
        self.log.phase(" TARGET REPORT — %s | %d finding(s) | score %.1f | "
                       "grade %s" % (t.display, total, data["score"], grade))
        for sev in SEV_ORDER:
            if stats.get(sev):
                bar = "█" * min(24, stats[sev])
                self.log.always("   %-8s %3d  %s" % (sev.upper(), stats[sev],
                                                     bar))
        for p in paths:
            self.log.success("report -> %s" % p)
        self.reported.add(t.display)

    def _db_for(self, display):
        if self.target and self.target.display == display and self.db:
            return self.db
        for db in self.dbs:
            rows = db.findings(display)
            if rows or db.services(display):
                return db
            if db.events_for(display):
                return db
        return None

    def write_run_summary(self):
        entries = []
        agg = {}
        for disp, tdir in self.target_dirs.items():
            db = self._db_for(disp)
            if db is None:
                continue
            st = db.stats()
            for k, v in st.items():
                agg[k] = agg.get(k, 0) + v
            findings = db.findings(disp)
            score = Intelligence().score(findings)
            entries.append({"target": disp, "folder": os.path.relpath(tdir,
                            self.outroot), "stats": st,
                            "grade": Intelligence().grade(findings),
                            "risk_score": score})
        import json as _json
        summary = {"tool": "VAJRA",
                   "generated": datetime.datetime.now().isoformat(
                       timespec="seconds"),
                   "profile": self.profile,
                   "output_root": self.outroot,
                   "targets": entries, "aggregate_stats": agg}
        path = os.path.join(self.outroot, "summary.json")
        open(path, "w", encoding="utf-8").write(_json.dumps(summary, indent=2))
        elapsed = time.time() - self.start_time
        total = sum(agg.values())
        self.log.phase("=" * 62)
        self.log.phase(" RUN COMPLETE — %d target(s) | %d finding(s) total | "
                        "%.0fs" % (len(entries), total, elapsed))
        for e in entries:
            self.log.always("   %-34s grade %-2s  %d finding(s)"
                            % (e["target"][:34], e["grade"],
                               sum(e["stats"].values())))
        self.log.success("output root -> %s" % self.outroot)
        self.log.phase("=" * 62)


class LoggerProxy:
    def __init__(self, verbose=0, color=True, logfile=None):
        from core.logger import Logger
        self._l = Logger(verbose=verbose, color=color, logfile=logfile)

    def set_file(self, path):
        self._l.set_file(path)

    def debug(self, m):
        self._l.debug(m)

    def info(self, m):
        self._l.info(m)

    def warn(self, m):
        self._l.warn(m)

    def error(self, m):
        self._l.error(m)

    def success(self, m):
        self._l.success(m)

    def finding(self, m):
        self._l.finding(m)

    def phase(self, m):
        self._l.phase(m)

    def always(self, m):
        self._l.always(m)


def build_data_for(db, target, engine):
    """Assemble report payload scoped to one target's database."""
    stats = db.stats(target.display)
    findings = db.findings(target.display)
    services = db.services(target.display)
    events = db.events_for(target.display)
    narrative = Intelligence().summarize(stats, findings, services,
                                         [{"display": target.display}])
    score = Intelligence().score(findings)
    try:
        from core.compliance import remediate as compliance_remediate
        from core.synthesis import (auto_narrative as synth_narrative,
                                    correlate_across, build_brain_blocks)
        spread = correlate_across(
            [f for db in engine.dbs for f in db.findings()])
    except Exception:
        compliance_remediate = lambda f: []
        spread = []
    data = {
        "meta": {"tool": "VAJRA",
                 "generated": datetime.datetime.now().isoformat(
                     timespec="seconds"),
                 "profile": engine.profile,
                 "targets": [target.display],
                 "output_dir": engine.target_dirs.get(target.display,
                                                      engine.outroot)},
        "stats": stats,
        "score": score,
        "grade": Intelligence().grade(findings),
        "narrative": narrative,
        "synthesis": synth_narrative(stats, findings, services,
                                     [{"display": target.display}], score,
                                     Intelligence().grade(findings)),
        "remediation": compliance_remediate(findings),
        "delta": engine.state.get("delta") or {},
        "spread": spread,
        "services": services,
        "findings": findings,
        "events": events,
        "tech": sorted(set(engine.state.get("tech", []) or [])),
        "subdomains": engine.state.get("subdomains", []),
        "os_guess": engine.state.get("os_guess", ""),
        "evasion": list(getattr(engine, "evasion_all", []))[:150],
    }
    return data
