"""Vajra - unified logging with color support."""
import sys
import os
import threading
import datetime

LEVELS = {"DEBUG": 10, "PHASE": 15, "INFO": 20, "SUCCESS": 22, "FINDING": 22,
          "WARN": 30, "ERROR": 40}
COLORS = {"DEBUG": "\033[90m", "PHASE": "\033[95m\033[1m", "INFO": "\033[96m",
          "SUCCESS": "\033[92m", "FINDING": "\033[94m\033[1m",
          "WARN": "\033[93m", "ERROR": "\033[91m"}
RESET = "\033[0m"


class Logger:
    def __init__(self, verbose=0, color=True, logfile=None):
        self.verbose = verbose
        self.color = color and sys.stdout.isatty()
        self._fh = None
        self._lock = threading.Lock()
        if logfile:
            os.makedirs(os.path.dirname(os.path.abspath(logfile)), exist_ok=True)
            self._fh = open(logfile, "a", encoding="utf-8", errors="replace")

    def _threshold(self):
        return 10 if self.verbose >= 1 else 20

    def _emit(self, lvl, msg, forced=False):
        if not forced and LEVELS.get(lvl, 20) < self._threshold():
            return
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        line = "[%s] [%-7s] %s" % (ts, lvl, msg)
        with self._lock:
            if self.color:
                print("%s%s%s" % (COLORS.get(lvl, ""), line, RESET), flush=True)
            else:
                print(line, flush=True)
            if self._fh:
                try:
                    self._fh.write(line + "\n")
                    self._fh.flush()
                except Exception:
                    pass

    def set_file(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self._lock:
            if self._fh:
                try:
                    self._fh.close()
                except Exception:
                    pass
            self._fh = open(path, "a", encoding="utf-8", errors="replace")

    def debug(self, m):
        self._emit("DEBUG", m)

    def info(self, m):
        self._emit("INFO", m)

    def warn(self, m):
        self._emit("WARN", m)

    def error(self, m):
        self._emit("ERROR", m)

    def success(self, m):
        self._emit("SUCCESS", m)

    def finding(self, m):
        self._emit("FINDING", m)

    def phase(self, m):
        self._emit("PHASE", m, forced=True)

    def always(self, m):
        self._emit("INFO", m, forced=True)
