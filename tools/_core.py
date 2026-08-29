"""vajra-toolkit shared helpers: colors, row printing, project-root + data
paths, and small arg conveniences. Pure stdlib."""
import json
import os
import shlex
import sys

try:
    from pathlib import Path
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
except Exception:
    PROJECT_ROOT = Path(os.path.dirname(os.path.abspath(__file__))).parent

BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

try:
    import locale
    locale.setlocale(locale.LC_ALL, "")
    ENC_IN = locale.getpreferredencoding(False) or "utf-8"
except Exception:
    ENC_IN = "utf-8"
ENC_OUT = sys.stdout.encoding or "utf-8"


def c(s, color=None, bold=False, dim=False, err=False):
    if not sys.__stdout__.isatty() or os.getenv("NO_COLOR"):
        return str(s)
    pre = (color or "") + (BOLD if bold else "") + (DIM if dim else "")
    return "%s%s%s" % (pre, s, RESET)


def status(tag, msg, color=None):
    print("%s %s %s" % (c("[%s]" % tag, color=color or BLUE, bold=True),
                        c(msg, color=color)))


def ok(msg):
    status("OK", msg, GREEN)


def warn(msg):
    status("!", msg, YELLOW)


def err(msg):
    status("x", msg, RED)


def data(path):
    """Resolve a project data file (config/, intel/, wordlists/)."""
    for sub in ("config", "intel", "wordlists"):
        if len(path.split("/")) > 1 and path.split("/")[0] in sub:
            return Path(os.path.join(str(PROJECT_ROOT), *path.split("/")))
    return Path(os.path.join(str(PROJECT_ROOT), path))


def load_json(path, default=None):
    try:
        with open(data(path), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def hr(width=70):
    print(c("-" * width, color=BLUE, dim=True))