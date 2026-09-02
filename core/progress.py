"""VAJRA live scan progress — a vulnerability-scanner-style meter showing a
percentage and a stable remaining-time (ETA) that updates smoothly as the scan
runs.

Design notes
------------
* The overall run is shown as ONE live bar. Its percentage moves as real work
  (modules / ports / folders / credentials) completes, and the ETA is computed
  from a smoothed work-rate so it does not jump wildly between steps.
* On a TTY the bar is redrawn live (periodically, even inside a long-running
  module) and is carefully cleaned up before every log line is printed — the
  progress and the log stream never mangle each other.
* When the output is not a TTY it degrades to a plain one-line log message, so
  no information is lost in redirected/CI runs.

A module-level registry lets the Logger tell any active meter to relinquish the
console line before it writes, then redraw it afterwards.
"""
import sys
import time
import threading


# ETA is only presented once the meter has enough signal to measure a
# rate: a minimum wall-clock elapsed time AND a minimum amount of travelled
# work (in percentage points). Up to then we print the honest "--:--".
MIN_ESTIMATE_ELAPSED = 10.0
MIN_ESTIMATE_DONE = 3
ESTIMATE_ALPHA = 0.08


class _State:
    _active = set()

    @classmethod
    def register(cls, meter):
        cls._active.add(meter)

    @classmethod
    def unregister(cls, meter):
        cls._active.discard(meter)

    @classmethod
    def clear_lines(cls):
        for m in list(cls._active):
            m.clear()

    @classmethod
    def refresh(cls):
        for m in list(cls._active):
            m.redraw()


class ProgressMeter:
    def __init__(self, label="progress", total=100, log=None, bar_width=20,
                 refresh=0.35):
        self.label = label
        self.total = max(1, int(total))
        self.log = log
        self.bar_width = bar_width
        self.refresh = refresh
        self.done = 0
        self.start = time.time()
        self._smooth_rate = None        # exponential moving average work/s
        self._last_eta = None           # monotonic countdown (never grows)
        self._detail = ""
        self._last_draw = -1.0
        self._tty = bool(sys.stdout.isatty())
        self._closed = False
        self._lock = threading.Lock()
        self._we_own_line = False
        if self._tty:
            _State.register(self)
            self._tick()
        else:
            self._emit_now(force=True)

    # -- public API --------------------------------------------------------

    def set_detail(self, text):
        self._detail = text or ""
        self._redraw_if_needed()

    def update(self, n, force=False):
        with self._lock:
            self.done = max(0, min(int(n), self.total))
        if force:
            self._redraw_if_needed(force=True)
        else:
            self._redraw_if_needed()

    def advance(self, step=1):
        self.update(self.done + step)

    def finish(self):
        if self._closed:
            return
        self._closed = True
        with self._lock:
            self.done = self.total
        if self._tty:
            _State.unregister(self)
            self._draw(force=True)      # final 100% line
            print("\n", end="", flush=True)
        else:
            self._emit_now(force=True)

    # -- live rendering ----------------------------------------------------

    def clear(self):
        """Relinquish the console line before the logger writes."""
        if self._tty and self._we_own_line:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
            self._we_own_line = False

    def redraw(self):
        """Re-acquire and redraw the console line after the logger writes."""
        if self._tty and not self._closed:
            self._draw()

    def _redraw_if_needed(self, force=False):
        if not self._tty:
            self._emit_now(force=force)
            return
        now = time.time()
        if force or now - self._last_draw >= self.refresh:
            self._draw()

    def _tick(self):
        """Periodic redraw so the bar stays alive inside long modules."""

        def loop():
            while not self._closed and self._tty:
                time.sleep(self.refresh)
                self._redraw_if_needed()

        threading.Thread(target=loop, daemon=True).start()

    def _pct(self):
        return min(100.0, 100.0 * self.done / self.total)

    def _eta(self):
        """Stable remaining time from a smoothed (EMA) work-rate.

        The ETA is explicitly NON-EXACT and monotonic: it is a best-effort
        estimate that only ever trends down towards completion. This matters
        because early, slow steps (e.g. the first port of a sweep) can make a
        naive rate-based estimate balloon — shown live, a climbing remaining
        time reads as a bug. So:

          * no numeric ETA is shown until there is real signal (some elapsed
            time AND measurable progress) — a still-at-0% meter prints the
            honest '--:--' rather than a fabricated countdown,
          * the raw estimate is capped to a sane upper bound, and
          * the displayed value is never allowed to grow once shown.

        The result is a stable countdown that reassures the operator work is
        progressing without pretending to predict the future precisely."""
        el = time.time() - self.start
        if self.done <= 0 or el <= 0.001:
            return "--:--"
        # Wait for meaningful momentum before trusting a rate: in the first
        # seconds (or while progress is still ~0) any number we print would
        # be a guess, so we keep it honest and blank.
        if el < MIN_ESTIMATE_ELAPSED or self.done < MIN_ESTIMATE_DONE:
            return "--:--"
        rate = self.done / el
        if self._smooth_rate is None:
            self._smooth_rate = rate
        else:
            # Slower EMA: discrete module completions register as spikes, so
            # a fast alpha makes the estimate wobble. Decay gently instead.
            self._smooth_rate = (ESTIMATE_ALPHA * rate +
                                 (1 - ESTIMATE_ALPHA) * self._smooth_rate)
        sps = max(1e-6, self._smooth_rate)
        remain = (self.total - self.done) / sps
        # Round to 5s granularity, clamp to a non-alarming ceiling.
        remain = min(600.0, max(0.0, round(remain / 5.0) * 5.0))
        # Monotonic non-increasing: never let the shown ETA climb.
        if self._last_eta is not None:
            remain = min(remain, self._last_eta)
        if remain <= 0:
            remain = 0.0
        self._last_eta = remain
        m, s = divmod(int(remain), 60)
        h, m = divmod(m, 60)
        if h:
            return "%d:%02d:%02d" % (h, m, s)
        return "%02d:%02d" % (m, s)

    def _draw(self, force=False):
        if self._closed and not force:
            return
        with self._lock:
            done = self.done
        pct = self._pct()
        filled = int(round(self.bar_width * done / self.total))
        bar = "█" * filled + "░" * (self.bar_width - filled)
        eta = self._eta()
        elapsed = int(time.time() - self.start)
        detail = ("  " + self._detail) if self._detail else ""
        line = ("\r\033[K%s [%s] %5.1f%%  ETA %s  %s (%ds)%s"
                % (self.label, bar, pct, eta, self._elapsed_hms(elapsed),
                   elapsed, detail))
        sys.stdout.write(line)
        sys.stdout.flush()
        self._we_own_line = True
        self._last_draw = time.time()

    @staticmethod
    def _elapsed_hms(sec):
        m, s = divmod(int(sec), 60)
        h, m = divmod(m, 60)
        if h:
            return "%d:%02d:%02d" % (h, m, s)
        return "%02d:%02d" % (m, s)

    def _emit_now(self, force=False):
        if self.log is None:
            return
        pct = self._pct()
        msg = "%s %d/%d (%.1f%%) ETA %s%s" % (
            self.label, self.done, self.total, pct, self._eta(),
            ("  " + self._detail) if self._detail else "")
        if force:
            self.log.info(msg)
