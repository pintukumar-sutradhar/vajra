"""VAJRA AI brain — talks internally to a local Ollama server running the
Qwen3 8B model. Fully offline once provisioned; auto-installs server + model
when missing; every call is time-boxed so scanning never slows down. Also
exposes the mission loop primitives used by the 'AI select' operator-
agent (core/agent.py)."""
import json
import shutil
import socket
import subprocess
import threading
import time
import urllib.request

DEFAULT_MODEL = "qwen3:8b"
BASE = "http://127.0.0.1:11434"


class AIEngine:
    def __init__(self, config=None, enabled=True, log=None):
        self.cfg = config or {}
        self.log = log
        self.enabled = enabled
        self.model = self.cfg.get("ai_model", DEFAULT_MODEL)
        self.timeout = float(self.cfg.get("ai_timeout", 12))
        self.max_tokens = int(self.cfg.get("ai_max_tokens", 512))
        self.autosetup = bool(self.cfg.get("ai_autosetup", True))
        self._ok = None
        self._checked_at = 0.0
        self._cache = {}
        self._lock = threading.Lock()

    def _log_dbg(self, msg):
        if self.log:
            try:
                self.log.debug("[ai] " + msg)
            except Exception:
                pass

    def _http(self, method, path, body=None, timeout=None):
        url = BASE + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    def _server_up(self):
        try:
            s = socket.create_connection(("127.0.0.1", 11434), timeout=0.8)
            s.close()
            return True
        except Exception:
            return False

    def available(self, refresh=False):
        if not self.enabled:
            return False
        now = time.time()
        if not refresh and self._ok is not None and now - self._checked_at < 60:
            return self._ok
        self._ok = self._server_up()
        self._checked_at = now
        return self._ok

    def warm_start(self):
        """Background provisioning so first real call is already hot."""
        if not self.enabled:
            return

        def work():
            try:
                if not self._server_up():
                    if not self.autosetup:
                        return
                    self._install_server()
                if not self._server_up():
                    return
                tags = self._http("GET", "/api/tags", timeout=3).get("models", [])
                names = {m.get("name", "") for m in tags}
                if not any(n.startswith(self.model.split(":")[0]) for n in names):
                    if self.autosetup and self._online():
                        self._log_dbg("pulling model %s (one-time)" % self.model)
                        self._pull_model()
                self.available(refresh=True)
                if self._ok:
                    if self.log:
                        self.log.success("[ai] Qwen3 online via Ollama (%s)"
                                         % self.model)
            except Exception as e:
                self._log_dbg("warm-start skipped: %r" % e)

        threading.Thread(target=work, daemon=True).start()

    def _online(self):
        try:
            s = socket.create_connection(("ollama.com", 443), timeout=2)
            s.close()
            return True
        except Exception:
            return False

    def _install_server(self):
        if shutil.which("ollama"):
            if self.log:
                self.log.info("[ai] starting local ollama service")
            subprocess.Popen(["ollama", "serve"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            for _ in range(20):
                if self._server_up():
                    return
                time.sleep(0.5)
            return
        if not self.autosetup or not self._online():
            return
        if self.log:
            self.log.info("[ai] installing Ollama runtime (one-time setup)")
        try:
            subprocess.run("curl -fsSL https://ollama.com/install.sh | sh",
                           shell=True, timeout=600,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            for _ in range(30):
                if self._server_up():
                    return
                time.sleep(0.5)
        except Exception as e:
            self._log_dbg("installer failed: %r" % e)

    def _pull_model(self):
        try:
            req = urllib.request.Request(
                BASE + "/api/pull",
                data=json.dumps({"name": self.model}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=1800) as r:
                while r.read(4096):
                    pass
        except Exception as e:
            self._log_dbg("model pull failed: %r" % e)

    def ask(self, prompt, system=None, max_tokens=None):
        if not self.available():
            return ""
        key = (system or "") + "|" + prompt
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        ntok = int(max_tokens or self.max_tokens)
        self._log_dbg("ask max_tokens=%d" % ntok)
        body = {"model": self.model, "prompt": prompt, "stream": False,
                "keep_alive": "15m",
                "options": {"num_predict": ntok, "temperature": 0.2}}
        if system:
            body["system"] = system
        try:
            resp = self._http("POST", "/api/generate", body)
            out = (resp.get("response") or "").strip()
        except Exception as e:
            self._log_dbg("ask failed: %r" % e)
            out = ""
        with self._lock:
            if len(self._cache) > 200:
                self._cache.clear()
            self._cache[key] = out
        return out

    def suggest_payloads(self, cls, waf, blocked_sample, context=""):
        """Situation-wise payload ideas when filters defeat the standard bank."""
        if not self.available():
            return []
        ckey = "%s|%s|%s" % (cls, waf, (blocked_sample or "")[:60])
        with self._lock:
            if ckey in self._cache:
                cached = self._cache[ckey]
                return list(cached) if isinstance(cached, list) else []
        prompt = (
            "You are a red-team payload engineer. WAF product blocking us: %s. "
            "Injection class: %s. Blocked sample payload: %r. Target context: %s. "
            "Return EXACTLY 5 alternate payloads, one per line, no numbering, "
            "no explanations, no markdown. Each must achieve the same objective "
            "while evading that WAF." % (waf or "unknown", cls,
                                         (blocked_sample or "")[:120],
                                         context[:160]))
        out = self.ask(prompt, system="Answer with payloads only.")
        items = []
        for ln in out.splitlines():
            ln = ln.strip().strip("`").strip()
            if ln and len(ln) < 500 and not ln.startswith("#"):
                items.append(ln)
        items = items[:6]
        with self._lock:
            self._cache[ckey] = items
        if items:
            self._log_dbg("%d evasion ideas accepted for %s/%s"
                          % (len(items), cls, waf))
        return items

    def plan_actions(self, surface_summary):
        if not self.available():
            return []
        prompt = ("Penetration-test state:\n%s\n"
                  "List up to 5 concrete next attack actions, one per line, "
                  "no explanations." % surface_summary[:1500])
        out = self.ask(prompt, system="You are a senior penetration tester.")
        acts = [ln.strip("-• ").strip() for ln in out.splitlines()
                if ln.strip() and len(ln.strip()) < 160]
        return acts[:5]

    def alternate_sql(self, dialect, cols, goal):
        if not self.available():
            return ""
        prompt = ("Craft ONE %s SQL injection expression for a UNION SELECT "
                  "with %d columns that would: %s. Reply with the raw SQL "
                  "fragment only." % (dialect, cols, goal))
        out = self.ask(prompt)
        return out.splitlines()[0][:300] if out else ""
