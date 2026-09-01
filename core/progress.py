"""VAJRA console progress meter — a live, self-refreshing percentage + ETA
bar that a human can read while a scan runs.

It renders inline with ANSI escapes (backspaces) so it does not flood the
log, prints a final line on completion, and degrades gracefully to a plain
one-line log message when the output is not a TTY."""
import sys
import time


class ProgressMeter:
    def __init__(self, label="progress", total=100, log=None, bar_width=24):
        self.label = label
        self.total = max(1, int(total))
        self.log = log              # optional engine.log proxy
        self.bar_width = bar_width
        self.done = 0
        self.start = time.time()
        self._last = 0.0
        self._tty = bool(sys.stdout.isatty())
        self._closed = False

    def update(self, n, force=False):
        self.done = max(0, min(int(n), self.total))
        now = time.time()
        if not force and now - self._last < 0.15:
            return          # throttle redraws
        self._last = now
        if self._tty:
            self._draw()
        else:
            self._emit_log(force)

    def advance(self, step=1):
        self.update(self.done + step)

    def finish(self):
        if self._closed:
            return
        self._closed = True
        self.update(self.total, force=True)
        if self._tty:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def _pct(self):
        return 100.0 * self.done / self.total

    def _eta(self):
        el = time.time() - self.start
        if self.done <= 0 or el <= 0:
            return "--:--"
        rate = self.done / el
        remain = (self.total - self.done) / rate
        if remain < 0:
            remain = 0
        m, s = divmod(int(remain), 60)
        h, m = divmod(m, 60)
        if h:
            return "%d:%02d:%02d" % (h, m, s)
        return "%02d:%02d" % (m, s)

    def _bar(self):
        filled = int(round(self.bar_width * self.done / self.total))
        blocks = "█" * filled
        dashes = "░" * (self.bar_width - filled)
        return blocks + dashes

    def _draw(self):
        pct = self._pct()
        elapsed = time.time() - self.start
        line = ("\r\033[K%s [%s] %5.1f%%  %d/%d  ETA %s  (%ds)"
                % (self.label, self._bar(), pct, self.done, self.total,
                   self._eta(), int(elapsed)))
        sys.stdout.write(line)
        sys.stdout.flush()

    def _emit_log(self, force=False):
        if self.log is None:
            return
        pct = self._pct()
        msg = "%s %d/%d (%.1f%%) ETA %s" % (
            self.label, self.done, self.total, pct, self._eta())
        if force:
            self.log.info(msg)
