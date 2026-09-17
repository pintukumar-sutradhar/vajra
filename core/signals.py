"""VAJRA — graceful-termination plumbing.

Cancelling a scan from the platform sends SIGTERM. The engine only ever
handled KeyboardInterrupt — which is what SIGINT (Ctrl-C) raises — so SIGTERM
killed the process outright: `_finalize_partial_scan()` never ran, the findings
bundle was never written, and the driver's harvest step was skipped. That is
why stopping a scan appeared to lose everything found so far.

Raising KeyboardInterrupt from a SIGTERM handler routes cancellation down the
same graceful path Ctrl-C already took, so the existing `finally:` blocks do
their job. Nothing else about the engine has to change.

Stdlib-only.
"""
from __future__ import annotations

import signal
import threading

# Signals that mean "stop what you are doing". SIGINT is deliberately absent:
# Python already raises KeyboardInterrupt for it, which is the behaviour we are
# reproducing.
TERMINATORS = tuple(
    s for s in (getattr(signal, "SIGTERM", None),
                getattr(signal, "SIGHUP", None),
                getattr(signal, "SIGBREAK", None))
    if s is not None)

_previous = {}
_installed = []


def _on_terminate(signum, frame):
    """Turn a termination signal into the interruption Ctrl-C already causes.

    The handler uninstalls itself first. A second SIGTERM therefore falls
    through to the default disposition and kills the process outright, which
    is the escape hatch if the graceful path is itself wedged — the operator
    asks twice, they mean it.
    """
    try:
        signal.signal(signum, signal.SIG_DFL)
    except (OSError, ValueError, RuntimeError):
        pass
    raise KeyboardInterrupt("terminated by signal %d" % signum)


def install(signals=None):
    """Route termination signals through the graceful path.

    Returns True when at least one handler was installed. A no-op off the main
    thread, where Python does not permit signal handlers to be set.
    """
    if threading.current_thread() is not threading.main_thread():
        return False
    wanted = TERMINATORS if signals is None else tuple(signals)
    changed = False
    for sig in wanted:
        if sig is None or sig in _installed:
            continue
        try:
            _previous[sig] = signal.getsignal(sig)
            signal.signal(sig, _on_terminate)
        except (OSError, ValueError, RuntimeError):
            continue
        _installed.append(sig)
        changed = True
    return changed


def restore():
    """Put back whatever handlers were in place before install()."""
    while _installed:
        sig = _installed.pop()
        prev = _previous.pop(sig, signal.SIG_DFL)
        try:
            signal.signal(sig, prev)
        except (OSError, ValueError, RuntimeError):
            pass


def installed():
    return tuple(_installed)
