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
# ETA rate is measured over the recent window of progress samples (seconds);
# within that window the rate is EMA-smoothed with RATE_ALPHA. This keeps the
# estimate reflecting the CURRENT throughput instead of an early fast burst.
RATE_WINDOW = 30.0
RATE_ALPHA = 0.35


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
        self._last_eta = None           # recent display value (for damping)
        self._samples = []              # (wallclock, done) for windowed rate
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

        The ETA is a best-effort estimate and, importantly, TRACKS reality
        rather than being frozen to an early value. A hard monotonic clamp
        made a long running module never raise its ETA once a low value was
        shown (it would stick at e.g. 00:10 for the whole run). Here we:

          * show no numeric ETA until there is real signal (some elapsed time
            AND measurable progress),
          * cap the raw estimate to a sane upper bound,
          * damp the *rate* with an EMA so it does not jump wildly, and
          * only gently limit how far the ETA may move per update (so it reads
            steadily) rather than locking it forever at the first guess.

        The result is a countdown that reflects the currently measured pace and
        drifts toward completion instead of a permanently pinned number."""
        el = time.time() - self.start
        if self.done <= 0 or el <= 0.001:
            return "--:--"
        if el < MIN_ESTIMATE_ELAPSED or self.done < MIN_ESTIMATE_DONE:
            return "--:--"
        # Windowed work-rate: the pace over the RECENT samples, so a slow
        # mid-scan module drags the estimate toward its real (longer) completion
        # rather than staying anchored to an early fast burst.
        self._samples.append((time.time(), self.done))
        cutoff = time.time() - RATE_WINDOW
        while len(self._samples) >= 2 and self._samples[0][0] < cutoff:
            self._samples.pop(0)
        if len(self._samples) >= 2 and self._samples[-1][1] > self._samples[0][1]:
            span = max(1e-6, self._samples[-1][0] - self._samples[0][0])
            rate = (self._samples[-1][1] - self._samples[0][1]) / span
        else:
            rate = self.done / el
        if self._smooth_rate is None:
            self._smooth_rate = rate
        else:
            self._smooth_rate = (RATE_ALPHA * rate +
                                 (1 - RATE_ALPHA) * self._smooth_rate)
        sps = max(1e-6, self._smooth_rate)
        remain = (self.total - self.done) / sps
        # Cap to a non-alarming ceiling; also never display below 5s.
        remain = min(600.0, max(0.0, remain))
        # Steady the display: limit per-update movement so a bursty module does
        # not swing the remaining time wildly, but do NOT freeze an old low ETA.
        if self._last_eta is not None:
            low = 0.5 * self._last_eta
            high = 1.5 * self._last_eta
            if low <= remain <= high:
                # inside the smooth band -> keep it smooth (no change ok)
                pass
            elif remain < low:
                remain = max(remain, low)      # don't crash downward
            else:
                remain = min(remain, high)     # don't explode upward
        remain = round(remain / 5.0) * 5.0
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
